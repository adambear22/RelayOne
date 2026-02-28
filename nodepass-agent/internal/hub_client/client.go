package hub_client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"nodepass-agent/internal/nodepass"
)

type MsgType string

const (
	AgentHello     MsgType = "AgentHello"
	Ping           MsgType = "Ping"
	Pong           MsgType = "Pong"
	ConfigPush     MsgType = "ConfigPush"
	TrafficReport  MsgType = "TrafficReport"
	DeployProgress MsgType = "DeployProgress"
	Ack            MsgType = "Ack"
	Error          MsgType = "Error"
)

type Message struct {
	Type      MsgType         `json:"type"`
	ID        string          `json:"id,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

type AgentHelloPayload struct {
	AgentID string                 `json:"agent_id"`
	Version string                 `json:"version"`
	Arch    string                 `json:"arch"`
	OS      string                 `json:"os"`
	SysInfo map[string]interface{} `json:"sys_info"`
}

type ConfigPushPayload struct {
	RuleID      string `json:"rule_id"`
	Action      string `json:"action"`
	NodepassURL string `json:"nodepass_url"`
	Target      string `json:"target"`
}

type TrafficReportPayload struct {
	AgentID string                 `json:"agent_id"`
	Records []nodepass.TrafficData `json:"records"`
}

type DeployProgressPayload struct {
	AgentID  string `json:"agent_id"`
	Step     string `json:"step"`
	Progress int    `json:"progress"`
	Message  string `json:"message"`
}

type Config struct {
	HubWSURL   string
	AgentID    string
	AgentToken string
	Version    string
}

type Client struct {
	cfg     Config
	manager *nodepass.Manager
	logger  *slog.Logger

	connMu  sync.RWMutex
	conn    *websocket.Conn
	writeMu sync.Mutex

	readyOnce sync.Once
	readyCh   chan struct{}

	counter atomic.Uint64
}

func LoadConfigFromEnv(version string) (Config, error) {
	cfg := Config{
		HubWSURL:   strings.TrimSpace(os.Getenv("HUB_WS_URL")),
		AgentID:    strings.TrimSpace(os.Getenv("AGENT_ID")),
		AgentToken: strings.TrimSpace(os.Getenv("AGENT_TOKEN")),
		Version:    strings.TrimSpace(version),
	}
	if cfg.HubWSURL == "" {
		return Config{}, errors.New("HUB_WS_URL is required")
	}
	if cfg.AgentID == "" {
		return Config{}, errors.New("AGENT_ID is required")
	}
	if cfg.AgentToken == "" {
		return Config{}, errors.New("AGENT_TOKEN is required")
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	return cfg, nil
}

func NewClient(cfg Config, manager *nodepass.Manager, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}

	return &Client{
		cfg:     cfg,
		manager: manager,
		logger:  logger,
		readyCh: make(chan struct{}),
	}
}

func (c *Client) Start(ctx context.Context) error {
	go c.connectLoop(ctx)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.readyCh:
		return nil
	}
}

func (c *Client) Close() {
	conn := c.getConn()
	if conn != nil {
		_ = conn.Close()
	}
	c.setConn(nil)
}

func (c *Client) UpdateNodePassCredentials(masterAddr, apiKey string) {
	c.logger.Info(
		"nodepass credentials updated",
		slog.String("master_addr", strings.TrimSpace(masterAddr)),
		slog.String("api_key_prefix", maskSecretPrefix(apiKey)),
	)
}

func (c *Client) SendTrafficReport(records []nodepass.TrafficData) error {
	if len(records) == 0 {
		return nil
	}

	payload := TrafficReportPayload{
		AgentID: c.cfg.AgentID,
		Records: records,
	}
	return c.sendWithPayload(TrafficReport, "", payload)
}

func (c *Client) SendDeployProgress(step string, progress int, message string) error {
	payload := DeployProgressPayload{
		AgentID:  c.cfg.AgentID,
		Step:     strings.TrimSpace(step),
		Progress: progress,
		Message:  strings.TrimSpace(message),
	}
	return c.sendWithPayload(DeployProgress, "", payload)
}

func (c *Client) connectLoop(ctx context.Context) {
	backoff := time.Second

	for {
		if ctx.Err() != nil {
			return
		}

		err := c.connectAndServe(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			c.logger.Warn("hub connection dropped", slog.Any("err", err), slog.String("retry_in", backoff.String()))
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

func (c *Client) connectAndServe(ctx context.Context) error {
	wsURL, err := c.buildWebSocketURL()
	if err != nil {
		return err
	}

	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, _, err := dialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	c.setConn(conn)
	defer c.setConn(nil)

	if err := c.sendAgentHello(); err != nil {
		return err
	}

	c.readyOnce.Do(func() {
		close(c.readyCh)
	})

	for {
		messageType, payload, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		if messageType != websocket.TextMessage && messageType != websocket.BinaryMessage {
			continue
		}

		if err := c.handleIncoming(payload); err != nil {
			c.logger.Warn("handle incoming hub message failed", slog.Any("err", err))
		}
	}
}

func (c *Client) buildWebSocketURL() (string, error) {
	raw := strings.TrimSpace(c.cfg.HubWSURL)
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}

	if parsed.Scheme == "http" {
		parsed.Scheme = "ws"
	}
	if parsed.Scheme == "https" {
		parsed.Scheme = "wss"
	}
	if parsed.Scheme == "" {
		return "", errors.New("invalid HUB_WS_URL scheme")
	}

	query := parsed.Query()
	query.Set("agent_id", c.cfg.AgentID)
	query.Set("token", c.cfg.AgentToken)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func (c *Client) sendAgentHello() error {
	payload := AgentHelloPayload{
		AgentID: c.cfg.AgentID,
		Version: c.cfg.Version,
		Arch:    runtime.GOARCH,
		OS:      runtime.GOOS,
		SysInfo: map[string]interface{}{
			"go_version": runtime.Version(),
			"num_cpu":    runtime.NumCPU(),
		},
	}
	return c.sendWithPayload(AgentHello, "", payload)
}

func (c *Client) handleIncoming(raw []byte) error {
	var msg Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		return err
	}

	switch msg.Type {
	case Ping:
		return c.sendWithPayload(Pong, msg.ID, map[string]any{"agent_id": c.cfg.AgentID})
	case ConfigPush:
		return c.handleConfigPush(msg)
	default:
		return nil
	}
}

func (c *Client) handleConfigPush(msg Message) error {
	if c.manager == nil {
		return errors.New("manager is nil")
	}

	var payload ConfigPushPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	action := strings.ToLower(strings.TrimSpace(payload.Action))
	var err error
	switch action {
	case "start":
		err = c.manager.Start(payload.RuleID, payload.NodepassURL, payload.Target)
	case "stop":
		err = c.manager.Stop(payload.RuleID)
	case "restart":
		err = c.manager.Restart(payload.RuleID)
	case "sync":
		err = c.manager.Start(payload.RuleID, payload.NodepassURL, payload.Target)
	default:
		err = fmt.Errorf("unsupported action: %s", payload.Action)
	}

	if err != nil {
		errorPayload := map[string]any{
			"id":      msg.ID,
			"rule_id": payload.RuleID,
			"error":   err.Error(),
		}
		_ = c.sendWithPayload(Error, "", errorPayload)
		return err
	}

	return c.sendWithPayload(Ack, msg.ID, map[string]any{"rule_id": payload.RuleID})
}

func (c *Client) sendWithPayload(msgType MsgType, messageID string, payload any) error {
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	msg := Message{
		Type:      msgType,
		ID:        strings.TrimSpace(messageID),
		Timestamp: time.Now().UTC(),
		Payload:   rawPayload,
	}
	if msg.ID == "" {
		msg.ID = c.newMessageID()
	}

	rawMessage, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	conn := c.getConn()
	if conn == nil {
		return errors.New("hub connection not ready")
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	conn = c.getConn()
	if conn == nil {
		return errors.New("hub connection not ready")
	}
	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, rawMessage)
}

func (c *Client) getConn() *websocket.Conn {
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	return c.conn
}

func (c *Client) setConn(conn *websocket.Conn) {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	if c.conn != nil && c.conn != conn {
		_ = c.conn.Close()
	}
	c.conn = conn
}

func (c *Client) newMessageID() string {
	value := c.counter.Add(1)
	return strconv.FormatInt(time.Now().UTC().UnixNano(), 10) + "-" + strconv.FormatUint(value, 10)
}

func maskSecretPrefix(secret string) string {
	trimmed := strings.TrimSpace(secret)
	if trimmed == "" {
		return ""
	}
	if len(trimmed) <= 8 {
		return trimmed
	}
	return trimmed[:8] + "..."
}
