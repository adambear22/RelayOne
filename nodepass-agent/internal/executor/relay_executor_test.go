package executor

import (
	"context"
	"encoding/json"
	"testing"

	"nodepass-agent/internal/ws"
)

func TestRelayEntryCreatesTwoInstances(t *testing.T) {
	mock := newMockNPAPI()
	cache := NewInstanceCache(t.TempDir())
	relay := NewRelayExecutor(mock, cache)

	payload, _ := json.Marshal(RelayStartPayload{
		Role:        "entry",
		EntryRuleID: "entry-rule",
		ListenPort:  1080,
		MiddlePort:  2080,
		TLSMode:     1,
		LogLevel:    2,
	})
	msg := ws.HubMessage{Type: "relay_start", ID: "relay-1", Payload: payload}

	if err := relay.HandleRelayStart(context.Background(), msg); err != nil {
		t.Fatalf("handle relay entry: %v", err)
	}

	if len(mock.instances) != 2 {
		t.Fatalf("expected 2 relay instances, got %d", len(mock.instances))
	}
	if _, ok := cache.Get("entry-rule"); !ok {
		t.Fatalf("expected entry cache item")
	}
	if _, ok := cache.Get("entry-rule_middle"); !ok {
		t.Fatalf("expected middle cache item")
	}
}

func TestRelayEntryRollbackOnSecondStartFailure(t *testing.T) {
	mock := newMockNPAPI()
	mock.failStartAt = 2
	cache := NewInstanceCache(t.TempDir())
	relay := NewRelayExecutor(mock, cache)

	payload, _ := json.Marshal(RelayStartPayload{
		Role:        "entry",
		EntryRuleID: "entry-rule",
		ListenPort:  1080,
		MiddlePort:  2080,
		TLSMode:     1,
		LogLevel:    2,
	})
	msg := ws.HubMessage{Type: "relay_start", ID: "relay-fail-1", Payload: payload}

	err := relay.HandleRelayStart(context.Background(), msg)
	if err == nil {
		t.Fatalf("expected relay entry to fail")
	}
	if len(mock.instances) != 0 {
		t.Fatalf("expected rollback to delete created instances, got %d", len(mock.instances))
	}
	if _, ok := cache.Get("entry-rule"); ok {
		t.Fatalf("expected no cache item on failed relay entry")
	}
}

func TestRelayExitRollbackOnStartFailure(t *testing.T) {
	mock := newMockNPAPI()
	mock.failStartAt = 1
	cache := NewInstanceCache(t.TempDir())
	relay := NewRelayExecutor(mock, cache)

	payload, _ := json.Marshal(RelayStartPayload{
		Role:       "exit",
		ExitRuleID: "exit-rule",
		MiddleHost: "127.0.0.1",
		MiddlePort: 2080,
		TargetHost: "10.0.0.10",
		TargetPort: 443,
		TLSMode:    1,
		LogLevel:   2,
	})
	msg := ws.HubMessage{Type: "relay_start", ID: "relay-fail-2", Payload: payload}

	err := relay.HandleRelayStart(context.Background(), msg)
	if err == nil {
		t.Fatalf("expected relay exit to fail")
	}
	if len(mock.instances) != 0 {
		t.Fatalf("expected failed exit start to rollback instance")
	}
	if _, ok := cache.Get("exit-rule"); ok {
		t.Fatalf("expected no cache item on failed relay exit")
	}
}
