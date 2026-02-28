package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"nodepass-hub/internal/event"
)

func newUnitTrafficService() *trafficService {
	return &trafficService{
		logger:          zap.NewNop(),
		primaryBuffer:   make(map[hourlyUpsertKey]hourlyUpsertRecord),
		secondaryBuffer: make(map[hourlyUpsertKey]hourlyUpsertRecord),
		stopCh:          make(chan struct{}),
	}
}

func TestHandleReport_RatioCalculation(t *testing.T) {
	t.Parallel()

	svc := newUnitTrafficService()
	ownerID := uuid.New()
	ruleID := uuid.New()

	var billedDelta int64
	svc.lookupBillingInfoFn = func(_ context.Context, gotRuleID uuid.UUID) (*billingInfo, error) {
		if gotRuleID != ruleID {
			t.Fatalf("unexpected rule id: %s", gotRuleID)
		}
		return &billingInfo{
			OwnerID:   ownerID,
			NodeRatio: 1.5,
			VIPRatio:  2.0,
		}, nil
	}
	svc.incrementUserTrafficFn = func(_ context.Context, gotUserID uuid.UUID, delta int64) (int64, int64, error) {
		if gotUserID != ownerID {
			t.Fatalf("unexpected user id: %s", gotUserID)
		}
		billedDelta = delta
		return delta, 10_000, nil
	}

	err := svc.HandleReport(context.Background(), "agent-1", []TrafficRecord{{
		RuleID:    ruleID.String(),
		BytesIn:   40,
		BytesOut:  60,
		Timestamp: time.Now().UTC(),
	}})
	if err != nil {
		t.Fatalf("HandleReport returned error: %v", err)
	}

	if billedDelta != 300 {
		t.Fatalf("expected billed bytes 300, got %d", billedDelta)
	}
}

func TestHandleReport_QuotaExceeded(t *testing.T) {
	t.Parallel()

	bus := event.NewBus()
	svc := newUnitTrafficService()
	svc.eventBus = bus

	ownerID := uuid.New()
	ruleID := uuid.New()

	gotQuotaEvent := make(chan event.QuotaExceededPayload, 1)
	bus.Subscribe(event.EventUserQuotaExceeded, func(payload any) {
		entry, ok := payload.(event.QuotaExceededPayload)
		if !ok {
			return
		}
		select {
		case gotQuotaEvent <- entry:
		default:
		}
	})

	svc.lookupBillingInfoFn = func(_ context.Context, _ uuid.UUID) (*billingInfo, error) {
		return &billingInfo{
			OwnerID:   ownerID,
			NodeRatio: 1,
			VIPRatio:  1,
		}, nil
	}
	svc.incrementUserTrafficFn = func(_ context.Context, _ uuid.UUID, delta int64) (int64, int64, error) {
		return delta, delta, nil
	}

	err := svc.HandleReport(context.Background(), "agent-1", []TrafficRecord{{
		RuleID:    ruleID.String(),
		BytesIn:   500,
		BytesOut:  500,
		Timestamp: time.Now().UTC(),
	}})
	if err != nil {
		t.Fatalf("HandleReport returned error: %v", err)
	}

	select {
	case payload := <-gotQuotaEvent:
		if payload.UserID != ownerID.String() {
			t.Fatalf("unexpected user id in event: %s", payload.UserID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected quota exceeded event")
	}
}

func TestHandleReport_ConcurrentSafety(t *testing.T) {
	t.Parallel()

	svc := newUnitTrafficService()
	ownerID := uuid.New()
	ruleID := uuid.New()

	svc.lookupBillingInfoFn = func(_ context.Context, _ uuid.UUID) (*billingInfo, error) {
		return &billingInfo{
			OwnerID:   ownerID,
			NodeRatio: 1,
			VIPRatio:  1,
		}, nil
	}

	var (
		mu   sync.Mutex
		used int64
	)
	svc.incrementUserTrafficFn = func(_ context.Context, _ uuid.UUID, delta int64) (int64, int64, error) {
		mu.Lock()
		defer mu.Unlock()
		used += delta
		return used, 1 << 60, nil
	}

	const workers = 100
	errCh := make(chan error, workers)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := svc.HandleReport(context.Background(), "agent-1", []TrafficRecord{{
				RuleID:    ruleID.String(),
				BytesIn:   1,
				BytesOut:  1,
				Timestamp: time.Now().UTC(),
			}})
			errCh <- err
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("HandleReport returned error: %v", err)
		}
	}

	mu.Lock()
	finalUsed := used
	mu.Unlock()

	const expected = int64(workers * 2)
	if finalUsed != expected {
		t.Fatalf("expected traffic_used %d, got %d", expected, finalUsed)
	}
}
