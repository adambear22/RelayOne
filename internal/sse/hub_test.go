package sse

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

func newTestHub() *SSEHub {
	return &SSEHub{
		eventBuf: NewRingBuffer(defaultRingBufferSize),
		logger:   zap.NewNop(),
		stopCh:   make(chan struct{}),
	}
}

func TestBroadcast_AllClientsReceive(t *testing.T) {
	t.Parallel()

	hub := newTestHub()
	clientA := NewClient("u1", "user")
	clientB := NewClient("u2", "admin")
	hub.Register(clientA)
	hub.Register(clientB)

	event := NewEvent(EventNodeStatus, map[string]any{"status": "online"})
	hub.Broadcast(event)

	assertEventType(t, clientA.Ch, EventNodeStatus)
	assertEventType(t, clientB.Ch, EventNodeStatus)
}

func TestSendToRole_OnlyMatchingRoleReceives(t *testing.T) {
	t.Parallel()

	hub := newTestHub()
	admin := NewClient("admin-1", "admin")
	user := NewClient("user-1", "user")
	hub.Register(admin)
	hub.Register(user)

	event := NewEvent(EventSystemAlert, map[string]any{"title": "maintenance"})
	hub.SendToRole("admin", event)

	assertEventType(t, admin.Ch, EventSystemAlert)
	assertNoEvent(t, user.Ch)
}

func TestSendToUser_PreciseDelivery(t *testing.T) {
	t.Parallel()

	hub := newTestHub()
	target := NewClient("target", "user")
	other := NewClient("other", "user")
	hub.Register(target)
	hub.Register(other)

	event := NewEvent(EventTrafficUpdate, map[string]any{"used": 123})
	hub.SendToUser("target", event)

	assertEventType(t, target.Ch, EventTrafficUpdate)
	assertNoEvent(t, other.Ch)
}

func TestBackpressure_SlowClientDoesNotBlockOthers(t *testing.T) {
	t.Parallel()

	hub := newTestHub()
	slow := &SSEClient{
		UserID: "slow",
		Role:   "user",
		Ch:     make(chan SSEEvent, 1),
		Done:   make(chan struct{}),
	}
	fast := &SSEClient{
		UserID: "fast",
		Role:   "user",
		Ch:     make(chan SSEEvent, 1),
		Done:   make(chan struct{}),
	}
	// Fill slow client queue so dispatch takes non-blocking fallback path.
	slow.Ch <- NewEvent(EventHeartbeat, map[string]any{"seed": true})

	hub.Register(slow)
	hub.Register(fast)

	event := NewEvent(EventRuleStatus, map[string]any{"status": "running"})
	hub.Broadcast(event)

	assertEventType(t, fast.Ch, EventRuleStatus)
}

func TestRingBuffer_Since_ReturnsCorrectEvents(t *testing.T) {
	t.Parallel()

	rb := NewRingBuffer(10)
	rb.Push(SSEEvent{ID: "1", Type: EventHeartbeat})
	rb.Push(SSEEvent{ID: "2", Type: EventNodeStatus})
	rb.Push(SSEEvent{ID: "3", Type: EventRuleStatus})

	events := rb.Since("1")
	if len(events) != 2 {
		t.Fatalf("expected 2 events after id=1, got %d", len(events))
	}
	if events[0].ID != "2" || events[1].ID != "3" {
		t.Fatalf("unexpected event sequence: %+v", events)
	}
}

func TestRingBuffer_EvictsOldestWhenFull(t *testing.T) {
	t.Parallel()

	rb := NewRingBuffer(3)
	rb.Push(SSEEvent{ID: "1", Type: EventHeartbeat})
	rb.Push(SSEEvent{ID: "2", Type: EventNodeStatus})
	rb.Push(SSEEvent{ID: "3", Type: EventRuleStatus})
	rb.Push(SSEEvent{ID: "4", Type: EventTrafficUpdate})

	events := rb.Since("")
	if len(events) != 3 {
		t.Fatalf("expected 3 events in ring buffer, got %d", len(events))
	}
	if events[0].ID != "2" || events[1].ID != "3" || events[2].ID != "4" {
		t.Fatalf("unexpected buffer contents after eviction: %+v", events)
	}
}

func assertEventType(t *testing.T, ch <-chan SSEEvent, wantType string) {
	t.Helper()
	select {
	case event := <-ch:
		if event.Type != wantType {
			t.Fatalf("expected event type %q, got %q", wantType, event.Type)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timed out waiting for event type %q", wantType)
	}
}

func assertNoEvent(t *testing.T, ch <-chan SSEEvent) {
	t.Helper()
	select {
	case event := <-ch:
		t.Fatalf("expected no event, got %+v", event)
	case <-time.After(100 * time.Millisecond):
	}
}
