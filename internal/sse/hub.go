package sse

import (
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"nodepass-hub/internal/metrics"
)

const (
	heartbeatInterval     = 30 * time.Second
	backpressureFullLimit = 5
)

type SSEHub struct {
	clients  sync.Map
	eventBuf *RingBuffer

	logger *zap.Logger
	stopCh chan struct{}
}

var (
	globalHub     *SSEHub
	globalHubOnce sync.Once
)

func NewHub(logger *zap.Logger) *SSEHub {
	if logger == nil {
		logger = zap.NewNop()
	}

	hub := &SSEHub{
		eventBuf: NewRingBuffer(defaultRingBufferSize),
		logger:   logger,
		stopCh:   make(chan struct{}),
	}

	go hub.startHeartbeat()

	return hub
}

func InitGlobal(logger *zap.Logger) *SSEHub {
	globalHubOnce.Do(func() {
		globalHub = NewHub(logger)
	})
	return globalHub
}

func Global() *SSEHub {
	return globalHub
}

func (h *SSEHub) Register(client *SSEClient) {
	if h == nil || client == nil || client.UserID == "" {
		return
	}

	if current, loaded := h.clients.Load(client.UserID); loaded {
		if oldClient, ok := current.(*SSEClient); ok && oldClient != client {
			oldClient.Close()
		}
	}

	h.clients.Store(client.UserID, client)
	metrics.SetSSEClients(h.ConnectedCount())
}

func (h *SSEHub) Unregister(userID string) {
	if h == nil || userID == "" {
		return
	}

	value, loaded := h.clients.LoadAndDelete(userID)
	if !loaded {
		return
	}

	if client, ok := value.(*SSEClient); ok {
		client.Close()
	}
	metrics.SetSSEClients(h.ConnectedCount())
}

func (h *SSEHub) Broadcast(event SSEEvent) {
	if h == nil {
		return
	}

	h.eventBuf.Push(event)
	h.clients.Range(func(_, value interface{}) bool {
		if client, ok := value.(*SSEClient); ok {
			h.dispatch(client, event)
		}
		return true
	})
}

func (h *SSEHub) SendToUser(userID string, event SSEEvent) {
	if h == nil || userID == "" {
		return
	}

	h.eventBuf.Push(event)
	value, ok := h.clients.Load(userID)
	if !ok {
		return
	}

	client, ok := value.(*SSEClient)
	if !ok {
		return
	}

	h.dispatch(client, event)
}

func (h *SSEHub) SendToRole(role string, event SSEEvent) {
	if h == nil || role == "" {
		return
	}

	h.eventBuf.Push(event)
	h.clients.Range(func(_, value interface{}) bool {
		client, ok := value.(*SSEClient)
		if !ok {
			return true
		}
		if strings.EqualFold(client.Role, role) {
			h.dispatch(client, event)
		}
		return true
	})
}

func (h *SSEHub) SendToUsers(userIDs []string, event SSEEvent) {
	if h == nil || len(userIDs) == 0 {
		return
	}

	h.eventBuf.Push(event)
	for _, userID := range userIDs {
		trimmedID := strings.TrimSpace(userID)
		if trimmedID == "" {
			continue
		}

		value, ok := h.clients.Load(trimmedID)
		if !ok {
			continue
		}
		client, ok := value.(*SSEClient)
		if !ok {
			continue
		}
		h.dispatch(client, event)
	}
}

func (h *SSEHub) Since(lastID string) []SSEEvent {
	if h == nil {
		return nil
	}
	return h.eventBuf.Since(lastID)
}

func (h *SSEHub) Close() {
	if h == nil {
		return
	}

	select {
	case <-h.stopCh:
		return
	default:
		close(h.stopCh)
	}
}

func (h *SSEHub) ConnectedCount() int {
	if h == nil {
		return 0
	}

	count := 0
	h.clients.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

func (h *SSEHub) dispatch(client *SSEClient, event SSEEvent) {
	if client == nil {
		return
	}

	select {
	case <-client.Done:
		return
	case client.Ch <- event:
		client.MarkDispatchSuccess()
		return
	default:
		streak := client.MarkDispatchFull()
		h.logger.Warn("drop sse event due to full buffer",
			zap.String("user_id", client.UserID),
			zap.String("type", event.Type),
			zap.Int32("full_streak", streak),
		)
		if streak >= backpressureFullLimit {
			h.logger.Warn("disconnect slow sse client due to backpressure",
				zap.String("user_id", client.UserID),
				zap.Int32("full_streak", streak),
			)
			h.Unregister(client.UserID)
		}
	}
}

func (h *SSEHub) startHeartbeat() {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-h.stopCh:
			return
		case now := <-ticker.C:
			heartbeat := NewEvent(EventHeartbeat, map[string]interface{}{
				"ts": now.UTC().Format(time.RFC3339Nano),
			})
			h.Broadcast(heartbeat)
		}
	}
}
