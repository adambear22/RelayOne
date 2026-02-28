package event

import (
	"strings"
	"sync"
	"time"
)

const (
	EventUserQuotaExceeded = "user.quota.exceeded"
	EventUserVIPExpired    = "user.vip.expired"
	EventNodeOffline       = "node.offline"
)

type QuotaExceededPayload struct {
	UserID       string `json:"user_id"`
	TrafficUsed  int64  `json:"traffic_used"`
	TrafficQuota int64  `json:"traffic_quota"`
}

type VIPExpiredPayload struct {
	UserID string `json:"user_id"`
}

type NodeOfflinePayload struct {
	NodeID    string    `json:"node_id"`
	Timestamp time.Time `json:"timestamp"`
}

type Bus struct {
	handlers sync.Map
	mu       sync.Mutex
}

func NewBus() *Bus {
	return &Bus{}
}

func (b *Bus) Subscribe(event string, handler func(payload any)) {
	if b == nil || handler == nil {
		return
	}

	eventName := strings.TrimSpace(event)
	if eventName == "" {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	handlers := make([]func(payload any), 0, 1)
	if current, ok := b.handlers.Load(eventName); ok {
		if casted, valid := current.([]func(payload any)); valid {
			handlers = append(handlers, casted...)
		}
	}
	handlers = append(handlers, handler)
	b.handlers.Store(eventName, handlers)
}

func (b *Bus) Publish(event string, payload any) {
	if b == nil {
		return
	}

	eventName := strings.TrimSpace(event)
	if eventName == "" {
		return
	}

	current, ok := b.handlers.Load(eventName)
	if !ok {
		return
	}

	handlers, ok := current.([]func(payload any))
	if !ok || len(handlers) == 0 {
		return
	}

	for _, handler := range handlers {
		if handler == nil {
			continue
		}
		go handler(payload)
	}
}
