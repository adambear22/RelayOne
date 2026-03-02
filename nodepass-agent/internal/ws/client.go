package ws

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	StateDisconnected int32 = 0
	StateConnecting   int32 = 1
	StateConnected    int32 = 2
)

var (
	ErrSendBufferFull = errors.New("ws: send buffer full")
	ErrNotConnected   = errors.New("ws: not connected")
)

type WSClient struct {
	hubURL      string
	agentID     string
	token       string
	version     string
	conn        *websocket.Conn
	send        chan []byte
	Recv        chan []byte
	connState   atomic.Int32
	reconnectCh chan struct{}
	done        chan struct{}
	mu          sync.Mutex

	pingInterval time.Duration
	pongTimeout  time.Duration
	rnd          *rand.Rand
	closeOnce    sync.Once
	ackMu        sync.Mutex
	ackWaiters   map[string]chan struct{}
	ackSeen      map[string]struct{}
}

func NewClient(hubURL, agentID, token string) *WSClient {
	c := &WSClient{
		hubURL:       hubURL,
		agentID:      agentID,
		token:        token,
		version:      "dev",
		send:         make(chan []byte, 256),
		Recv:         make(chan []byte, 256),
		reconnectCh:  make(chan struct{}, 1),
		done:         make(chan struct{}),
		pingInterval: 30 * time.Second,
		pongTimeout:  10 * time.Second,
		rnd:          rand.New(rand.NewSource(time.Now().UnixNano())),
		ackWaiters:   make(map[string]chan struct{}),
		ackSeen:      make(map[string]struct{}),
	}
	c.connState.Store(StateDisconnected)
	return c
}

func (c *WSClient) Start(ctx context.Context) {
	attempt := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		default:
		}

		c.connState.Store(StateConnecting)
		conn, err := c.connect(ctx)
		if err != nil {
			c.connState.Store(StateDisconnected)
			delay := c.backoffDelay(attempt)
			attempt++
			if !c.sleepOrDone(ctx, delay) {
				return
			}
			continue
		}

		attempt = 0
		c.setConn(conn)
		c.connState.Store(StateConnected)
		_ = c.sendAgentHello(conn)

		err = c.serve(ctx, conn)
		_ = err
		c.connState.Store(StateDisconnected)
		c.setConn(nil)
		_ = conn.Close()

		if !c.sleepOrDone(ctx, c.backoffDelay(attempt)) {
			return
		}
		attempt++
	}
}

func (c *WSClient) connect(ctx context.Context) (*websocket.Conn, error) {
	wsURL, err := c.buildURL()
	if err != nil {
		return nil, err
	}

	headers := http.Header{}
	headers.Set("X-Internal-Token", c.token)

	dialer := websocket.DefaultDialer
	conn, _, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		return nil, err
	}

	_ = conn.SetReadDeadline(time.Now().Add(c.pingInterval + c.pongTimeout))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(c.pingInterval + c.pongTimeout))
	})

	return conn, nil
}

func (c *WSClient) serve(ctx context.Context, conn *websocket.Conn) error {
	errCh := make(chan error, 2)

	go func() {
		errCh <- c.readPump(ctx, conn)
	}()
	go func() {
		errCh <- c.writePump(ctx, conn)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return context.Canceled
	case err := <-errCh:
		return err
	}
}

func (c *WSClient) readPump(ctx context.Context, conn *websocket.Conn) error {
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			return err
		}

		if c.handleControlMessage(message) {
			continue
		}
		select {
		case c.Recv <- message:
		default:
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.done:
			return context.Canceled
		default:
		}
	}
}

func (c *WSClient) writePump(ctx context.Context, conn *websocket.Conn) error {
	ticker := time.NewTicker(c.pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = c.writeClose(conn)
			return ctx.Err()
		case <-c.done:
			_ = c.writeClose(conn)
			return context.Canceled
		case msg := <-c.send:
			if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
				return err
			}
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return err
			}
		case <-ticker.C:
			if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
				return err
			}
			if err := conn.WriteMessage(websocket.PingMessage, []byte("ping")); err != nil {
				return err
			}
		}
	}
}

func (c *WSClient) Send(msg []byte) error {
	if !c.IsConnected() {
		return ErrNotConnected
	}
	select {
	case c.send <- msg:
		return nil
	default:
		return ErrSendBufferFull
	}
}

func (c *WSClient) IsConnected() bool {
	return c.connState.Load() == StateConnected
}

func (c *WSClient) WaitForConnection(timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()

	for {
		if c.IsConnected() {
			return nil
		}
		select {
		case <-c.done:
			return context.Canceled
		case <-timer.C:
			return context.DeadlineExceeded
		case <-tick.C:
		}
	}
}

func (c *WSClient) Close() {
	c.closeOnce.Do(func() {
		close(c.done)
	})
	if conn := c.getConn(); conn != nil {
		_ = conn.Close()
	}
}

func (c *WSClient) SetVersion(version string) {
	clean := strings.TrimSpace(version)
	if clean == "" {
		return
	}
	c.mu.Lock()
	c.version = clean
	c.mu.Unlock()
}

func (c *WSClient) WaitForACK(msgID string, timeout time.Duration) bool {
	id := strings.TrimSpace(msgID)
	if id == "" {
		return false
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	waiter, alreadyAcked := c.registerAckWaiter(id)
	if alreadyAcked {
		return true
	}
	defer c.unregisterAckWaiter(id, waiter)

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-waiter:
		return true
	case <-timer.C:
		return false
	case <-c.done:
		return false
	}
}

func (c *WSClient) backoffDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	base := math.Min(float64(int64(1)<<uint(attempt)), 60)
	jitter := base * 0.2 * (2*c.rnd.Float64() - 1)
	return time.Duration((base + jitter) * float64(time.Second))
}

func (c *WSClient) buildURL() (string, error) {
	parsed, err := url.Parse(c.hubURL)
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "http" {
		parsed.Scheme = "ws"
	} else if parsed.Scheme == "https" {
		parsed.Scheme = "wss"
	}

	q := parsed.Query()
	q.Set("agent_id", c.agentID)
	q.Set("token", c.token)
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

func (c *WSClient) setConn(conn *websocket.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn = conn
}

func (c *WSClient) getConn() *websocket.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn
}

func (c *WSClient) getVersion() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version
}

func (c *WSClient) registerAckWaiter(msgID string) (chan struct{}, bool) {
	c.ackMu.Lock()
	defer c.ackMu.Unlock()
	if _, ok := c.ackSeen[msgID]; ok {
		delete(c.ackSeen, msgID)
		return nil, true
	}
	waiter := make(chan struct{}, 1)
	c.ackWaiters[msgID] = waiter
	return waiter, false
}

func (c *WSClient) unregisterAckWaiter(msgID string, waiter chan struct{}) {
	c.ackMu.Lock()
	defer c.ackMu.Unlock()

	current, ok := c.ackWaiters[msgID]
	if !ok {
		return
	}
	if current != waiter {
		return
	}
	delete(c.ackWaiters, msgID)
}

func (c *WSClient) notifyAck(msgID string) {
	c.ackMu.Lock()
	waiter, ok := c.ackWaiters[msgID]
	if !ok {
		c.ackSeen[msgID] = struct{}{}
	}
	c.ackMu.Unlock()
	if !ok {
		return
	}

	select {
	case waiter <- struct{}{}:
	default:
	}
}

func (c *WSClient) sleepOrDone(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-c.done:
		return false
	case <-timer.C:
		return true
	}
}

func (c *WSClient) writeClose(conn *websocket.Conn) error {
	deadline := time.Now().Add(2 * time.Second)
	_ = conn.SetWriteDeadline(deadline)
	return conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
}

func (c *WSClient) handleControlMessage(raw []byte) bool {
	var msg WireMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return false
	}

	if NormalizeInboundType(msg.Type) != "ack" {
		return false
	}

	c.notifyAck(msg.ID)
	return true
}

func (c *WSClient) sendAgentHello(conn *websocket.Conn) error {
	payload := map[string]any{
		"agent_id": c.agentID,
		"version":  c.getVersion(),
		"arch":     runtime.GOARCH,
		"os":       runtime.GOOS,
		"sys_info": map[string]any{
			"goarch": runtime.GOARCH,
			"goos":   runtime.GOOS,
		},
	}

	raw, err := MarshalWireMessage("AgentHello", "", payload)
	if err != nil {
		return err
	}
	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, raw)
}
