package ws

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestWSClientReconnects(t *testing.T) {
	var connections atomic.Int32
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		count := connections.Add(1)
		if count == 1 {
			_ = conn.Close()
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	client := NewClient(srv.URL+"/ws/agent", "agent-1", "token-1")
	client.pingInterval = 200 * time.Millisecond
	client.pongTimeout = 100 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go client.Start(ctx)
	defer client.Close()

	if err := client.WaitForConnection(4 * time.Second); err != nil {
		t.Fatalf("wait for connection: %v", err)
	}

	if connections.Load() < 2 {
		t.Fatalf("expected reconnect attempt, got %d connections", connections.Load())
	}
}

func TestBuildURLIncludesAgentIDAndToken(t *testing.T) {
	client := NewClient("https://hub.example.com/ws/agent", "agent-42", "token-42")
	built, err := client.buildURL()
	if err != nil {
		t.Fatalf("buildURL: %v", err)
	}

	parsed, err := url.Parse(built)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	if parsed.Scheme != "wss" {
		t.Fatalf("unexpected scheme: %s", parsed.Scheme)
	}
	if parsed.Query().Get("agent_id") != "agent-42" {
		t.Fatalf("missing agent_id query")
	}
	if parsed.Query().Get("token") != "token-42" {
		t.Fatalf("missing token query")
	}
}

func TestClientSendsAgentHelloOnConnect(t *testing.T) {
	received := make(chan WireMessage, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		_, raw, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var msg WireMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			return
		}
		received <- msg
	}))
	defer srv.Close()

	client := NewClient(srv.URL+"/ws/agent", "agent-hello", "token-hello")
	client.SetVersion("v-test")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.Start(ctx)
	defer client.Close()

	select {
	case msg := <-received:
		if msg.Type != "AgentHello" {
			t.Fatalf("unexpected message type: %s", msg.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for AgentHello")
	}
}

func TestClientWaitForACK(t *testing.T) {
	receivedID := make(chan string, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		_, _, _ = conn.ReadMessage() // AgentHello

		_, raw, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var msg WireMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			return
		}
		receivedID <- msg.ID

		ackRaw, _ := MarshalWireMessage("Ack", msg.ID, map[string]any{"success": true})
		_ = conn.WriteMessage(websocket.TextMessage, ackRaw)
	}))
	defer srv.Close()

	client := NewClient(srv.URL+"/ws/agent", "agent-ack", "token-ack")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.Start(ctx)
	defer client.Close()

	if err := client.WaitForConnection(2 * time.Second); err != nil {
		t.Fatalf("wait connection: %v", err)
	}

	outboundID := "traffic-123"
	raw, _ := MarshalWireMessage("TrafficReport", outboundID, map[string]any{
		"agent_id": "agent-ack",
		"records":  []any{},
	})
	if err := client.Send(raw); err != nil {
		t.Fatalf("send: %v", err)
	}

	select {
	case got := <-receivedID:
		if got != outboundID {
			t.Fatalf("unexpected received id: %s", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting server receive")
	}

	if ok := client.WaitForACK(outboundID, 2*time.Second); !ok {
		t.Fatalf("expected ack to be observed")
	}
}

func TestWaitForACKWhenAckArrivesEarly(t *testing.T) {
	client := NewClient("ws://localhost/ws/agent", "agent-early", "token")
	ackRaw, _ := MarshalWireMessage("Ack", "early-1", map[string]any{"success": true})
	if handled := client.handleControlMessage(ackRaw); !handled {
		t.Fatalf("expected control message to be handled")
	}

	if ok := client.WaitForACK("early-1", 200*time.Millisecond); !ok {
		t.Fatalf("expected early ack to be consumed")
	}
}
