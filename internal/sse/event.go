package sse

import (
	"encoding/json"
	"strconv"
	"sync/atomic"
)

type SSEEvent struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Data string `json:"data"`
}

const (
	EventHeartbeat      = "heartbeat"
	EventNodeStatus     = "node.status"
	EventDeployProgress = "deploy.progress"
	EventRuleStatus     = "rule.status"
	EventTrafficUpdate  = "traffic.update"
	EventSystemAlert    = "system.alert"
	EventAnnouncement   = "announcement"
)

var globalEventID int64

func NewEvent(eventType string, payload any) SSEEvent {
	id := atomic.AddInt64(&globalEventID, 1)
	data, err := json.Marshal(payload)
	if err != nil {
		data = []byte("null")
	}

	return SSEEvent{
		ID:   strconv.FormatInt(id, 10),
		Type: eventType,
		Data: string(data),
	}
}
