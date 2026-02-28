package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"nodepass-hub/internal/event"
	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
	"nodepass-hub/internal/service"
	"nodepass-hub/internal/sse"
)

const (
	adminRole         = "admin"
	reconnectGrace    = 30 * time.Second
	heartbeatInterval = 30 * time.Second
	heartbeatTimeout  = 90 * time.Second
	messageQueueSize  = 8192
)

type nodeHeartbeatUpdater interface {
	UpdateHeartbeat(ctx context.Context, id uuid.UUID, status string, lastSeenAt time.Time) error
}

type nodeRuntimeUpdater interface {
	UpdateRuntimeInfo(ctx context.Context, id uuid.UUID, version string, arch string, sysInfo map[string]interface{}, lastSeenAt time.Time, status string) error
}

type nodeDeployLogWriter interface {
	InsertDeployLog(ctx context.Context, nodeID uuid.UUID, step string, progress int, message string) error
}

type Hub struct {
	clients sync.Map
	acks    sync.Map

	nodeRepo   repository.NodeRepository
	trafficSvc service.TrafficService
	sseSvc     *sse.SSEHub
	eventBus   *event.Bus

	messageQueue chan incomingMessage
	workerCount  int
	workerWG     sync.WaitGroup
	reconnectTTL time.Duration

	logger *zap.Logger
	stopCh chan struct{}
}

type incomingMessage struct {
	client *AgentClient
	raw    []byte
}

var (
	globalHub     *Hub
	globalHubOnce sync.Once
)

func NewHub(
	nodeRepo repository.NodeRepository,
	trafficSvc service.TrafficService,
	sseSvc *sse.SSEHub,
	eventBus *event.Bus,
	logger *zap.Logger,
) *Hub {
	if logger == nil {
		logger = zap.NewNop()
	}

	h := &Hub{
		nodeRepo:     nodeRepo,
		trafficSvc:   trafficSvc,
		sseSvc:       sseSvc,
		eventBus:     eventBus,
		logger:       logger,
		stopCh:       make(chan struct{}),
		reconnectTTL: reconnectGrace,
	}
	h.workerCount = runtime.NumCPU() * 2
	if h.workerCount < 2 {
		h.workerCount = 2
	}
	h.messageQueue = make(chan incomingMessage, messageQueueSize)

	h.startMessageWorkers()

	go h.startHeartbeat()

	return h
}

func InitGlobal(
	nodeRepo repository.NodeRepository,
	trafficSvc service.TrafficService,
	sseSvc *sse.SSEHub,
	eventBus *event.Bus,
	logger *zap.Logger,
) *Hub {
	globalHubOnce.Do(func() {
		globalHub = NewHub(nodeRepo, trafficSvc, sseSvc, eventBus, logger)
	})
	return globalHub
}

func Global() *Hub {
	return globalHub
}

func (h *Hub) Register(client *AgentClient) {
	if client == nil {
		return
	}

	if current, loaded := h.clients.Load(client.ID); loaded {
		if oldClient, ok := current.(*AgentClient); ok && oldClient != client {
			oldClient.closeConn()
		}
	}

	h.clients.Store(client.ID, client)
	client.markPong(time.Now().UTC())

	h.setNodeOnline(context.Background(), client.ID)
	h.broadcastNodeStatus(client.ID, "online")
}

func (h *Hub) Unregister(client *AgentClient) {
	if client == nil {
		return
	}

	if current, loaded := h.clients.Load(client.ID); loaded {
		if active, ok := current.(*AgentClient); ok && active != client {
			return
		}
		h.clients.Delete(client.ID)
	}

	go func(agentID string) {
		wait := h.reconnectTTL
		if wait <= 0 {
			wait = reconnectGrace
		}

		timer := time.NewTimer(wait)
		defer timer.Stop()

		select {
		case <-h.stopCh:
			return
		case <-timer.C:
		}

		if _, ok := h.clients.Load(agentID); ok {
			return
		}

		h.setNodeOffline(context.Background(), agentID)
		h.publishEvent(event.EventNodeOffline, event.NodeOfflinePayload{
			NodeID:    agentID,
			Timestamp: time.Now().UTC(),
		})
		h.broadcastNodeStatus(agentID, "offline")
	}(client.ID)
}

func (h *Hub) HandleMessage(client *AgentClient, raw []byte) {
	if client == nil || len(raw) == 0 {
		return
	}

	job := incomingMessage{
		client: client,
		raw:    append([]byte(nil), raw...),
	}

	select {
	case <-h.stopCh:
		return
	case h.messageQueue <- job:
		return
	default:
		h.logger.Warn("agent message queue full, dropping message",
			zap.String("agent_id", client.ID),
		)
	}
}

func (h *Hub) processIncomingMessage(client *AgentClient, raw []byte) {
	if client == nil || len(raw) == 0 {
		return
	}

	var msg Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		h.logger.Warn("invalid ws message", zap.String("agent_id", client.ID), zap.Error(err))
		return
	}

	msgType := normalizeMsgType(msg.Type)
	if msgType == "" {
		h.logger.Warn("unknown ws message type", zap.String("agent_id", client.ID), zap.String("type", string(msg.Type)))
		return
	}

	now := time.Now().UTC()
	client.markPong(now)

	switch msgType {
	case AgentHello:
		h.handleAgentHello(client, msg)
	case Ping:
		_ = h.SendToAgent(client.ID, Message{Type: Pong, ID: msg.ID})
	case Pong:
		client.markPong(now)
	case Ack:
		h.handleAck(msg)
	case TrafficReport:
		h.handleTrafficReport(client, msg)
	case DeployProgress:
		h.handleDeployProgress(client, msg)
	case StatusReport:
		h.handleStatusReport(client, msg)
	default:
		h.logger.Debug("message type handled as noop", zap.String("agent_id", client.ID), zap.String("type", string(msgType)))
	}
}

func (h *Hub) SendToAgent(agentID string, msg Message) error {
	value, ok := h.clients.Load(agentID)
	if !ok {
		return fmt.Errorf("agent %s not connected", agentID)
	}

	client, ok := value.(*AgentClient)
	if !ok || client == nil {
		return errors.New("invalid agent client")
	}

	return h.sendToClient(client, msg)
}

func (h *Hub) Close() {
	select {
	case <-h.stopCh:
	default:
		close(h.stopCh)
	}
	h.workerWG.Wait()
}

func (h *Hub) startMessageWorkers() {
	if h.workerCount <= 0 {
		h.workerCount = 1
	}

	for idx := 0; idx < h.workerCount; idx++ {
		h.workerWG.Add(1)
		go h.messageWorker()
	}
}

func (h *Hub) messageWorker() {
	defer h.workerWG.Done()

	for {
		select {
		case <-h.stopCh:
			return
		case job := <-h.messageQueue:
			h.processIncomingMessage(job.client, job.raw)
		}
	}
}

func (h *Hub) startHeartbeat() {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-h.stopCh:
			return
		case now := <-ticker.C:
			h.clients.Range(func(_, value interface{}) bool {
				client, ok := value.(*AgentClient)
				if !ok || client == nil {
					return true
				}

				lastPong := client.LastPong()
				if !lastPong.IsZero() && now.Sub(lastPong) > heartbeatTimeout {
					h.logger.Warn("agent heartbeat timeout",
						zap.String("agent_id", client.ID),
						zap.Duration("idle", now.Sub(lastPong)),
					)
					client.unregister()
					return true
				}

				_ = h.sendToClient(client, Message{Type: Ping})
				return true
			})
		}
	}
}

func (h *Hub) sendToClient(client *AgentClient, msg Message) error {
	if msg.ID == "" {
		msg.ID = uuid.NewString()
	}
	if msg.Timestamp.IsZero() {
		msg.Timestamp = time.Now().UTC()
	}

	raw, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	select {
	case <-client.Done:
		return errors.New("client disconnected")
	case client.Send <- raw:
		return nil
	default:
		h.logger.Warn("agent send channel is full, dropping message",
			zap.String("agent_id", client.ID),
			zap.String("type", string(msg.Type)),
		)
		return nil
	}
}

func (h *Hub) PingAgent(ctx context.Context, agentID string, timeout time.Duration) error {
	value, ok := h.clients.Load(agentID)
	if !ok {
		return fmt.Errorf("agent %s not connected", agentID)
	}

	client, ok := value.(*AgentClient)
	if !ok || client == nil {
		return errors.New("invalid agent client")
	}

	baseline := client.LastPong()
	if err := h.sendToClient(client, Message{Type: Ping, ID: uuid.NewString()}); err != nil {
		return err
	}

	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		lastPong := client.LastPong()
		if !lastPong.IsZero() && (baseline.IsZero() || lastPong.After(baseline)) {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return errors.New("ping timeout")
		case <-ticker.C:
		}
	}
}

func (h *Hub) SendConfigPushAndWaitAck(
	ctx context.Context,
	agentID string,
	ruleID string,
	action string,
	nodepassURL string,
	target string,
	timeout time.Duration,
) (bool, error) {
	payload := ConfigPushPayload{
		RuleID:      strings.TrimSpace(ruleID),
		Action:      strings.TrimSpace(action),
		NodepassURL: strings.TrimSpace(nodepassURL),
		Target:      strings.TrimSpace(target),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}

	msgID := uuid.NewString()
	waiter := make(chan struct{}, 1)
	h.acks.Store(msgID, waiter)
	defer h.acks.Delete(msgID)

	if err := h.SendToAgent(agentID, Message{
		Type:    ConfigPush,
		ID:      msgID,
		Payload: raw,
	}); err != nil {
		return false, err
	}

	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-timer.C:
		return false, nil
	case <-waiter:
		return true, nil
	}
}

func (h *Hub) handleAgentHello(client *AgentClient, msg Message) {
	var payload AgentHelloPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		h.logger.Warn("invalid agent hello payload", zap.String("agent_id", client.ID), zap.Error(err))
		return
	}

	agentID := strings.TrimSpace(payload.AgentID)
	if agentID == "" {
		agentID = client.ID
	}

	sysInfo := make(map[string]interface{})
	for k, v := range payload.SysInfo {
		sysInfo[k] = v
	}
	if payload.OS != "" {
		sysInfo["os"] = payload.OS
	}
	if payload.Arch != "" {
		sysInfo["arch"] = payload.Arch
	}
	if payload.Version != "" {
		sysInfo["version"] = payload.Version
	}

	h.updateRuntimeInfo(context.Background(), agentID, payload.Version, payload.Arch, sysInfo, "online")
	h.publishEvent("rule.resync", map[string]interface{}{"agent_id": agentID})
}

func (h *Hub) handleAck(msg Message) {
	ackID := strings.TrimSpace(msg.ID)
	if ackID == "" {
		var payload struct {
			ID        string `json:"id"`
			MsgID     string `json:"msg_id"`
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal(msg.Payload, &payload); err == nil {
			ackID = strings.TrimSpace(payload.ID)
			if ackID == "" {
				ackID = strings.TrimSpace(payload.MsgID)
			}
			if ackID == "" {
				ackID = strings.TrimSpace(payload.RequestID)
			}
		}
	}

	if ackID == "" {
		return
	}

	waiterAny, ok := h.acks.LoadAndDelete(ackID)
	if !ok {
		return
	}

	waiter, ok := waiterAny.(chan struct{})
	if !ok {
		return
	}

	select {
	case waiter <- struct{}{}:
	default:
	}
}

func (h *Hub) handleTrafficReport(client *AgentClient, msg Message) {
	if h.trafficSvc == nil {
		return
	}

	var payload TrafficReportPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		h.logger.Warn("invalid traffic report payload", zap.String("agent_id", client.ID), zap.Error(err))
		return
	}

	agentID := strings.TrimSpace(payload.AgentID)
	if agentID == "" {
		agentID = client.ID
	}

	records := make([]service.TrafficRecord, 0, len(payload.Records))
	for _, record := range payload.Records {
		timestamp := record.Timestamp
		if timestamp.IsZero() {
			timestamp = time.Now().UTC()
		}
		records = append(records, service.TrafficRecord{
			RuleID:    record.RuleID,
			BytesIn:   record.BytesIn,
			BytesOut:  record.BytesOut,
			Timestamp: timestamp,
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := h.trafficSvc.HandleReport(ctx, agentID, records); err != nil {
		h.logger.Warn("handle traffic report failed", zap.String("agent_id", agentID), zap.Error(err))
	}
}

func (h *Hub) handleDeployProgress(client *AgentClient, msg Message) {
	var payload DeployProgressPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		h.logger.Warn("invalid deploy progress payload", zap.String("agent_id", client.ID), zap.Error(err))
		return
	}

	agentID := strings.TrimSpace(payload.AgentID)
	if agentID == "" {
		agentID = client.ID
	}

	h.insertDeployLog(context.Background(), agentID, payload.Step, payload.Progress, payload.Message)
	h.sendAdminEvent("deploy.progress", payload)
	h.publishEvent("deploy.progress", payload)
}

func (h *Hub) handleStatusReport(client *AgentClient, msg Message) {
	var payload struct {
		AgentID string                 `json:"agent_id"`
		SysInfo map[string]interface{} `json:"sys_info"`
	}
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		h.logger.Warn("invalid status report payload", zap.String("agent_id", client.ID), zap.Error(err))
		return
	}

	agentID := strings.TrimSpace(payload.AgentID)
	if agentID == "" {
		agentID = client.ID
	}

	h.updateRuntimeInfo(context.Background(), agentID, "", "", payload.SysInfo, "online")
}

func (h *Hub) setNodeOnline(ctx context.Context, agentID string) {
	nodeID, err := uuid.Parse(agentID)
	if err != nil {
		h.logger.Warn("invalid agent id for online status", zap.String("agent_id", agentID), zap.Error(err))
		return
	}

	now := time.Now().UTC()
	if updater, ok := h.nodeRepo.(nodeHeartbeatUpdater); ok {
		if err := updater.UpdateHeartbeat(ctx, nodeID, "online", now); err != nil && !errors.Is(err, repository.ErrNotFound) {
			h.logger.Warn("update node online status failed", zap.String("agent_id", agentID), zap.Error(err))
		}
		return
	}

	node, err := h.nodeRepo.FindByID(ctx, nodeID)
	if err != nil {
		if !errors.Is(err, repository.ErrNotFound) {
			h.logger.Warn("find node failed", zap.String("agent_id", agentID), zap.Error(err))
		}
		return
	}

	node.Status = "online"
	node.LastSeenAt = &now
	if err := h.nodeRepo.Update(ctx, node); err != nil {
		h.logger.Warn("update node failed", zap.String("agent_id", agentID), zap.Error(err))
	}
}

func (h *Hub) setNodeOffline(ctx context.Context, agentID string) {
	nodeID, err := uuid.Parse(agentID)
	if err != nil {
		h.logger.Warn("invalid agent id for offline status", zap.String("agent_id", agentID), zap.Error(err))
		return
	}

	now := time.Now().UTC()
	if updater, ok := h.nodeRepo.(nodeHeartbeatUpdater); ok {
		if err := updater.UpdateHeartbeat(ctx, nodeID, "offline", now); err != nil && !errors.Is(err, repository.ErrNotFound) {
			h.logger.Warn("update node offline status failed", zap.String("agent_id", agentID), zap.Error(err))
		}
		return
	}

	node, err := h.nodeRepo.FindByID(ctx, nodeID)
	if err != nil {
		if !errors.Is(err, repository.ErrNotFound) {
			h.logger.Warn("find node failed", zap.String("agent_id", agentID), zap.Error(err))
		}
		return
	}

	node.Status = "offline"
	node.LastSeenAt = &now
	if err := h.nodeRepo.Update(ctx, node); err != nil {
		h.logger.Warn("update node failed", zap.String("agent_id", agentID), zap.Error(err))
	}
}

func (h *Hub) updateRuntimeInfo(ctx context.Context, agentID, version, arch string, sysInfo map[string]interface{}, status string) {
	nodeID, err := uuid.Parse(agentID)
	if err != nil {
		h.logger.Warn("invalid agent id for runtime update", zap.String("agent_id", agentID), zap.Error(err))
		return
	}

	now := time.Now().UTC()
	if updater, ok := h.nodeRepo.(nodeRuntimeUpdater); ok {
		if err := updater.UpdateRuntimeInfo(ctx, nodeID, version, arch, sysInfo, now, status); err != nil && !errors.Is(err, repository.ErrNotFound) {
			h.logger.Warn("update node runtime failed", zap.String("agent_id", agentID), zap.Error(err))
		}
		return
	}

	node, err := h.nodeRepo.FindByID(ctx, nodeID)
	if err != nil {
		if !errors.Is(err, repository.ErrNotFound) {
			h.logger.Warn("find node failed", zap.String("agent_id", agentID), zap.Error(err))
		}
		return
	}

	if version != "" {
		node.AgentVersion = &version
	}
	if arch != "" {
		node.Arch = arch
	}
	if sysInfo != nil {
		node.SysInfo = sysInfo
	}
	if status != "" {
		node.Status = status
	}
	node.LastSeenAt = &now

	if err := h.nodeRepo.Update(ctx, node); err != nil {
		h.logger.Warn("update node failed", zap.String("agent_id", agentID), zap.Error(err))
	}
}

func (h *Hub) insertDeployLog(ctx context.Context, agentID, step string, progress int, message string) {
	writer, ok := h.nodeRepo.(nodeDeployLogWriter)
	if !ok {
		return
	}

	nodeID, err := uuid.Parse(agentID)
	if err != nil {
		h.logger.Warn("invalid agent id for deploy log", zap.String("agent_id", agentID), zap.Error(err))
		return
	}

	if err := writer.InsertDeployLog(ctx, nodeID, step, progress, message); err != nil {
		h.logger.Warn("insert deploy log failed", zap.String("agent_id", agentID), zap.Error(err))
	}
}

func (h *Hub) broadcastNodeStatus(agentID, status string) {
	h.sendAdminEvent("node.status", map[string]interface{}{
		"agent_id":  agentID,
		"status":    status,
		"timestamp": time.Now().UTC(),
	})
	h.publishEvent("node.status", map[string]interface{}{
		"agent_id":  agentID,
		"status":    status,
		"timestamp": time.Now().UTC(),
	})
}

func (h *Hub) sendAdminEvent(eventName string, payload interface{}) {
	if h.sseSvc == nil {
		return
	}
	h.sseSvc.SendToRole(adminRole, sse.NewEvent(eventName, payload))
}

func (h *Hub) publishEvent(topic string, payload interface{}) {
	if h.eventBus == nil {
		return
	}
	h.eventBus.Publish(topic, payload)
}

func normalizeMsgType(msgType MsgType) MsgType {
	normalized := strings.ToLower(strings.TrimSpace(string(msgType)))
	normalized = strings.ReplaceAll(normalized, "_", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, ".", "")

	switch normalized {
	case strings.ToLower(string(AgentHello)), "agenthello":
		return AgentHello
	case strings.ToLower(string(Ping)), "ping":
		return Ping
	case strings.ToLower(string(Pong)), "pong":
		return Pong
	case strings.ToLower(string(RuleStart)), "rulestart":
		return RuleStart
	case strings.ToLower(string(RuleStop)), "rulestop":
		return RuleStop
	case strings.ToLower(string(RuleRestart)), "rulerestart":
		return RuleRestart
	case strings.ToLower(string(ConfigPush)), "configpush":
		return ConfigPush
	case strings.ToLower(string(StatusReport)), "statusreport":
		return StatusReport
	case strings.ToLower(string(TrafficReport)), "trafficreport":
		return TrafficReport
	case strings.ToLower(string(DeployProgress)), "deployprogress":
		return DeployProgress
	case strings.ToLower(string(Ack)), "ack":
		return Ack
	case strings.ToLower(string(Error)), "error":
		return Error
	default:
		return ""
	}
}

func mapToNode(node *model.NodeAgent) map[string]interface{} {
	if node == nil {
		return nil
	}
	return map[string]interface{}{
		"id":      node.ID.String(),
		"status":  node.Status,
		"version": node.AgentVersion,
	}
}
