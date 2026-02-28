package hub

import (
	"encoding/json"
	"time"
)

type MsgType string

const (
	AgentHello     MsgType = "AgentHello"
	Ping           MsgType = "Ping"
	Pong           MsgType = "Pong"
	RuleStart      MsgType = "RuleStart"
	RuleStop       MsgType = "RuleStop"
	RuleRestart    MsgType = "RuleRestart"
	ConfigPush     MsgType = "ConfigPush"
	StatusReport   MsgType = "StatusReport"
	TrafficReport  MsgType = "TrafficReport"
	DeployProgress MsgType = "DeployProgress"
	Ack            MsgType = "Ack"
	Error          MsgType = "Error"
)

type Message struct {
	Type      MsgType         `json:"type"`
	ID        string          `json:"id"`
	Timestamp time.Time       `json:"timestamp"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

type ConfigPushPayload struct {
	RuleID      string `json:"rule_id"`
	Action      string `json:"action"`
	NodepassURL string `json:"nodepass_url"`
	Target      string `json:"target"`
}

type TrafficReportPayload struct {
	AgentID string          `json:"agent_id"`
	Records []TrafficRecord `json:"records"`
}

type TrafficRecord struct {
	RuleID    string    `json:"rule_id"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
	Timestamp time.Time `json:"timestamp"`
}

type DeployProgressPayload struct {
	AgentID  string `json:"agent_id"`
	Step     string `json:"step"`
	Progress int    `json:"progress"`
	Message  string `json:"message"`
}

type AgentHelloPayload struct {
	AgentID string                 `json:"agent_id"`
	Version string                 `json:"version"`
	Arch    string                 `json:"arch"`
	OS      string                 `json:"os"`
	SysInfo map[string]interface{} `json:"sys_info"`
}
