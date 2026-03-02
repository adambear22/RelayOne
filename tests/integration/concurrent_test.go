//go:build integration

package integration

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"nodepass-hub/internal/service"
)

func TestConcurrentTrafficReport(t *testing.T) {
	user, userToken := createRegularUser(t)
	node := createNode(t, userToken)
	rule := createRule(t, userToken, node.ID)

	const workers = 100
	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := getEnv(t).trafficSvc.HandleReport(context.Background(), node.ID.String(), []service.TrafficRecord{
				{
					RuleID:    rule.ID.String(),
					BytesIn:   10,
					BytesOut:  10,
					Timestamp: time.Now().UTC(),
				},
			})
			if err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent traffic report failed: %v", err)
		}
	}

	userAfter := userByID(t, user.ID)
	if userAfter.TrafficUsed != int64(workers*20) {
		t.Fatalf("expected traffic_used=%d, got %d", workers*20, userAfter.TrafficUsed)
	}
}

func TestConcurrentBenefitCodeRedeem(t *testing.T) {
	codes, err := getEnv(t).codeService.BatchGenerate(
		context.Background(),
		getEnv(t).adminID.String(),
		service.BatchGenerateRequest{
			Count:        1,
			VIPLevel:     1,
			DurationDays: 30,
			ValidDays:    30,
		},
	)
	if err != nil {
		t.Fatalf("batch generate code failed: %v", err)
	}
	if len(codes) != 1 {
		t.Fatalf("expected one code, got %d", len(codes))
	}
	code := codes[0].Code

	const workers = 10
	userIDs := make([]uuid.UUID, 0, workers)
	for i := 0; i < workers; i++ {
		user, _ := createRegularUser(t)
		userIDs = append(userIDs, user.ID)
	}

	var successCount int32
	var wg sync.WaitGroup
	for _, userID := range userIDs {
		wg.Add(1)
		go func(uid uuid.UUID) {
			defer wg.Done()
			err := getEnv(t).codeService.Redeem(context.Background(), uid.String(), code)
			if err == nil {
				atomic.AddInt32(&successCount, 1)
			}
		}(userID)
	}
	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected only one redeem success, got %d", successCount)
	}
}
