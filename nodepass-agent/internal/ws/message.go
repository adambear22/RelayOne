package ws

import (
	"encoding/json"
	"strings"
	"time"
)

type HubMessage struct {
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	Payload json.RawMessage `json:"payload"`
}

type AgentMessage struct {
	Type    string          `json:"type"`
	RefID   string          `json:"ref_id,omitempty"`
	Success bool            `json:"success,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type WireMessage struct {
	Type      string          `json:"type"`
	ID        string          `json:"id,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

func MarshalWireMessage(msgType, id string, payload any) ([]byte, error) {
	var payloadRaw json.RawMessage
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		payloadRaw = raw
	}

	return json.Marshal(WireMessage{
		Type:      strings.TrimSpace(msgType),
		ID:        strings.TrimSpace(id),
		Timestamp: time.Now().UTC(),
		Payload:   payloadRaw,
	})
}

func NormalizeInboundType(rawType string) string {
	trimmed := strings.TrimSpace(rawType)
	if trimmed == "" {
		return ""
	}

	normalized := strings.ToLower(trimmed)
	normalized = strings.ReplaceAll(normalized, "_", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, ".", "")

	switch normalized {
	case "heartbeat", "ping":
		return "heartbeat"
	case "pong":
		return "pong"
	case "configpush":
		return "config_push"
	case "rulecreate":
		return "rule_create"
	case "rulestart":
		return "rule_start"
	case "rulestop":
		return "rule_stop"
	case "rulerestart":
		return "rule_restart"
	case "ruledelete":
		return "rule_delete"
	case "relaystart":
		return "relay_start"
	case "configreload":
		return "config_reload"
	case "upgrade":
		return "upgrade"
	case "ack":
		return "ack"
	default:
		return strings.ToLower(trimmed)
	}
}
