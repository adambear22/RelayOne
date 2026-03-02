package ws

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeSender struct {
	sent chan []byte
}

func (f *fakeSender) Send(msg []byte) error {
	f.sent <- msg
	return nil
}

func TestRouterProcessesConcurrentJobsAndACK(t *testing.T) {
	recv := make(chan []byte, 128)
	sender := &fakeSender{sent: make(chan []byte, 256)}
	router := NewRouterWithChannels(sender, recv, 4)

	var handled atomic.Int32
	router.Register("rule_start", func(ctx context.Context, msg HubMessage) error {
		handled.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go router.Start(ctx)

	const total = 100
	for i := 0; i < total; i++ {
		msg := HubMessage{Type: "rule_start", ID: "msg-" + strconv.Itoa(i+1)}
		raw, _ := json.Marshal(msg)
		recv <- raw
	}

	deadline := time.After(5 * time.Second)
	ackCount := 0
	for ackCount < total {
		select {
		case raw := <-sender.sent:
			var ack WireMessage
			if err := json.Unmarshal(raw, &ack); err != nil {
				t.Fatalf("decode ack: %v", err)
			}
			if ack.Type == "Ack" {
				ackCount++
			}
		case <-deadline:
			t.Fatalf("timed out waiting for ack, got %d", ackCount)
		}
	}

	if handled.Load() != total {
		t.Fatalf("expected %d handled, got %d", total, handled.Load())
	}
}

func TestRouterHeartbeatBypassQueue(t *testing.T) {
	recv := make(chan []byte, 1)
	sender := &fakeSender{sent: make(chan []byte, 1)}
	router := NewRouterWithChannels(sender, recv, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go router.Start(ctx)

	raw, _ := json.Marshal(HubMessage{Type: "heartbeat", ID: "hb-1"})
	recv <- raw

	select {
	case out := <-sender.sent:
		var msg WireMessage
		if err := json.Unmarshal(out, &msg); err != nil {
			t.Fatalf("decode heartbeat response: %v", err)
		}
		if msg.Type != "Pong" {
			t.Fatalf("unexpected type: %s", msg.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for heartbeat response")
	}
}

func TestRouterNoDeadlockWithBurst(t *testing.T) {
	recv := make(chan []byte, 256)
	sender := &fakeSender{sent: make(chan []byte, 256)}
	router := NewRouterWithChannels(sender, recv, 8)

	var mu sync.Mutex
	order := make([]string, 0, 100)
	router.Register("rule_start", func(ctx context.Context, msg HubMessage) error {
		mu.Lock()
		order = append(order, msg.ID)
		mu.Unlock()
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go router.Start(ctx)

	for i := 0; i < 100; i++ {
		payload, _ := json.Marshal(HubMessage{Type: "rule_start", ID: "id"})
		recv <- payload
	}

	time.Sleep(500 * time.Millisecond)
	mu.Lock()
	processed := len(order)
	mu.Unlock()
	if processed == 0 {
		t.Fatalf("expected messages processed")
	}
}

func TestRouterConfigPushTranslation(t *testing.T) {
	recv := make(chan []byte, 1)
	sender := &fakeSender{sent: make(chan []byte, 1)}
	router := NewRouterWithChannels(sender, recv, 1)

	called := make(chan HubMessage, 1)
	router.Register("rule_start", func(ctx context.Context, msg HubMessage) error {
		called <- msg
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go router.Start(ctx)

	pushPayload, _ := json.Marshal(map[string]any{
		"rule_id": "rule-1",
		"action":  "start",
	})
	raw, _ := json.Marshal(HubMessage{
		Type:    "ConfigPush",
		ID:      "cfg-1",
		Payload: pushPayload,
	})
	recv <- raw

	select {
	case msg := <-called:
		if msg.Type != "rule_start" {
			t.Fatalf("unexpected translated type: %s", msg.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for translated config push")
	}
}
