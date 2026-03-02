package ws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

type HandlerFunc func(ctx context.Context, msg HubMessage) error

type sender interface {
	Send(msg []byte) error
}

type Router struct {
	client         sender
	recv           <-chan []byte
	handlers       map[string]HandlerFunc
	handlerMu      sync.RWMutex
	workerN        int
	jobQueue       chan HubMessage
	handlerTimeout time.Duration
}

func NewRouter(client *WSClient, workerN int) *Router {
	return NewRouterWithChannels(client, client.Recv, workerN)
}

func NewRouterWithChannels(client sender, recv <-chan []byte, workerN int) *Router {
	if workerN <= 0 {
		workerN = 4
	}
	return &Router{
		client:         client,
		recv:           recv,
		handlers:       make(map[string]HandlerFunc),
		workerN:        workerN,
		jobQueue:       make(chan HubMessage, 128),
		handlerTimeout: 30 * time.Second,
	}
}

func (r *Router) Register(msgType string, handler HandlerFunc) {
	r.handlerMu.Lock()
	defer r.handlerMu.Unlock()
	r.handlers[msgType] = handler
}

func (r *Router) Start(ctx context.Context) {
	for i := 0; i < r.workerN; i++ {
		go r.worker(ctx)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-r.recv:
			if !ok {
				return
			}
			if err := r.dispatchRaw(ctx, raw); err != nil {
				continue
			}
		}
	}
}

func (r *Router) dispatchRaw(ctx context.Context, raw []byte) error {
	var msg HubMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return err
	}

	msg.Type = NormalizeInboundType(msg.Type)

	if msg.Type == "heartbeat" {
		return r.sendHeartbeat(msg.ID)
	}
	if msg.Type == "pong" || msg.Type == "ack" {
		return nil
	}
	if msg.Type == "config_push" {
		translated, err := translateConfigPush(msg)
		if err != nil {
			r.sendACK(msg.ID, false, err.Error(), nil)
			return err
		}
		msg = translated
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case r.jobQueue <- msg:
		return nil
	}
}

func (r *Router) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-r.jobQueue:
			handler := r.handlerFor(msg.Type)
			if handler == nil {
				r.sendACK(msg.ID, false, fmt.Sprintf("unsupported message type: %s", msg.Type), nil)
				continue
			}

			handlerCtx, cancel := context.WithTimeout(ctx, r.handlerTimeout)
			err := handler(handlerCtx, msg)
			cancel()
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					r.sendACK(msg.ID, false, "handler timeout", nil)
					continue
				}
				r.sendACK(msg.ID, false, err.Error(), nil)
				continue
			}
			r.sendACK(msg.ID, true, "", nil)
		}
	}
}

func (r *Router) handlerFor(msgType string) HandlerFunc {
	r.handlerMu.RLock()
	defer r.handlerMu.RUnlock()
	handler := r.handlers[msgType]
	if handler != nil {
		return handler
	}
	return r.handlers[NormalizeInboundType(msgType)]
}

func (r *Router) sendHeartbeat(refID string) error {
	encoded, err := MarshalWireMessage("Pong", refID, map[string]int64{"timestamp": time.Now().Unix()})
	if err != nil {
		return err
	}
	return r.client.Send(encoded)
}

func (r *Router) sendACK(refID string, success bool, errMsg string, data interface{}) {
	body := map[string]interface{}{}
	body["success"] = success
	if errMsg != "" {
		body["error"] = errMsg
	}
	if data != nil {
		body["data"] = data
	}

	encoded, err := MarshalWireMessage("Ack", refID, body)
	if err != nil {
		return
	}
	_ = r.client.Send(encoded)
}

func translateConfigPush(msg HubMessage) (HubMessage, error) {
	type configPushPayload struct {
		RuleID      string `json:"rule_id"`
		Action      string `json:"action"`
		NodepassURL string `json:"nodepass_url"`
		Target      string `json:"target"`
	}

	var payload configPushPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return HubMessage{}, err
	}

	action := strings.ToLower(strings.TrimSpace(payload.Action))
	if action == "" {
		return HubMessage{}, errors.New("config push action is empty")
	}

	type rulePayload struct {
		RuleID string `json:"rule_id"`
		URL    string `json:"url,omitempty"`
		Target string `json:"target,omitempty"`
	}
	translatedPayload := rulePayload{
		RuleID: strings.TrimSpace(payload.RuleID),
		URL:    strings.TrimSpace(payload.NodepassURL),
		Target: strings.TrimSpace(payload.Target),
	}
	rawPayload, err := json.Marshal(translatedPayload)
	if err != nil {
		return HubMessage{}, err
	}

	mappedType := mapConfigPushAction(action)
	if mappedType == "rule_start" && translatedPayload.URL != "" {
		mappedType = "rule_create"
	}
	if mappedType == "" {
		return HubMessage{}, fmt.Errorf("unsupported config push action: %s", action)
	}

	return HubMessage{
		Type:    mappedType,
		ID:      msg.ID,
		Payload: rawPayload,
	}, nil
}

func mapConfigPushAction(action string) string {
	switch action {
	case "create", "upsert", "add":
		return "rule_create"
	case "start", "enable", "resume":
		return "rule_start"
	case "sync":
		return "rule_create"
	case "stop", "disable", "pause":
		return "rule_stop"
	case "restart":
		return "rule_restart"
	case "delete", "remove":
		return "rule_delete"
	default:
		return ""
	}
}
