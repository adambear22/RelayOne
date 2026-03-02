package hub

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
	"nodepass-hub/internal/service"
)

type heartbeatRecord struct {
	status string
	seenAt time.Time
}

type fakeNodeRepository struct {
	mu         sync.Mutex
	heartbeats map[uuid.UUID]heartbeatRecord
}

type fakeTrafficService struct {
	handleErr error
}

func (s *fakeTrafficService) HandleReport(ctx context.Context, agentID string, records []service.TrafficRecord) error {
	_ = ctx
	_ = agentID
	_ = records
	return s.handleErr
}

func (s *fakeTrafficService) QueryStats(context.Context, string, string, time.Time, time.Time) ([]service.TrafficStat, error) {
	return nil, nil
}

func (s *fakeTrafficService) QueryUserDailyStats(context.Context, string, int) ([]*service.DailyStat, error) {
	return nil, nil
}

func (s *fakeTrafficService) QueryUserMonthlyStats(context.Context, string, int) ([]*service.MonthlyStat, error) {
	return nil, nil
}

func (s *fakeTrafficService) QueryRuleStats(context.Context, string, time.Time, time.Time) ([]*service.HourlyPoint, error) {
	return nil, nil
}

func (s *fakeTrafficService) AdminOverview(context.Context) (*service.TrafficOverview, error) {
	return nil, nil
}

func (s *fakeTrafficService) ResetUserQuota(context.Context, string) error {
	return nil
}

func (s *fakeTrafficService) ResetAllMonthlyQuotas(context.Context) (int64, error) {
	return 0, nil
}

func (s *fakeTrafficService) BatchSyncQuota(context.Context) error {
	return nil
}

func newFakeNodeRepository() *fakeNodeRepository {
	return &fakeNodeRepository{heartbeats: make(map[uuid.UUID]heartbeatRecord)}
}

func (r *fakeNodeRepository) FindByID(_ context.Context, id uuid.UUID) (*model.NodeAgent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, ok := r.heartbeats[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	seen := record.seenAt
	return &model.NodeAgent{ID: id, Status: record.status, LastSeenAt: &seen}, nil
}

func (r *fakeNodeRepository) FindByOwner(context.Context, uuid.UUID, repository.Pagination) ([]*model.NodeAgent, error) {
	return nil, nil
}

func (r *fakeNodeRepository) Create(context.Context, *model.NodeAgent) error {
	return nil
}

func (r *fakeNodeRepository) Update(context.Context, *model.NodeAgent) error {
	return nil
}

func (r *fakeNodeRepository) UpdateStatus(context.Context, uuid.UUID, string) error {
	return nil
}

func (r *fakeNodeRepository) UpdateDeployStatus(context.Context, uuid.UUID, string, *string) error {
	return nil
}

func (r *fakeNodeRepository) List(context.Context, repository.NodeListFilter) ([]*model.NodeAgent, error) {
	return nil, nil
}

func (r *fakeNodeRepository) UpdateHeartbeat(_ context.Context, id uuid.UUID, status string, lastSeenAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.heartbeats[id] = heartbeatRecord{status: status, seenAt: lastSeenAt}
	return nil
}

func (r *fakeNodeRepository) lastStatus(id uuid.UUID) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, ok := r.heartbeats[id]
	if !ok {
		return "", false
	}
	return record.status, true
}

func TestRegister_MarksNodeOnline(t *testing.T) {
	t.Parallel()

	repo := newFakeNodeRepository()
	nodeID := uuid.New()
	h := &Hub{
		nodeRepo: repo,
		logger:   zap.NewNop(),
		stopCh:   make(chan struct{}),
	}

	client := &AgentClient{
		ID:   nodeID.String(),
		Send: make(chan []byte, 1),
		Done: make(chan struct{}),
	}

	h.Register(client)

	status, ok := repo.lastStatus(nodeID)
	if !ok {
		t.Fatal("expected heartbeat update after register")
	}
	if status != "online" {
		t.Fatalf("expected online status, got %q", status)
	}
}

func TestUnregister_MarksNodeOfflineAfterTimeout(t *testing.T) {
	repo := newFakeNodeRepository()
	nodeID := uuid.New()
	h := &Hub{
		nodeRepo:     repo,
		logger:       zap.NewNop(),
		stopCh:       make(chan struct{}),
		reconnectTTL: 20 * time.Millisecond,
	}

	client := &AgentClient{
		ID:   nodeID.String(),
		Send: make(chan []byte, 1),
		Done: make(chan struct{}),
	}

	h.Register(client)
	h.Unregister(client)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status, ok := repo.lastStatus(nodeID)
		if ok && status == "offline" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("expected node status to become offline after unregister timeout")
}

func TestSendToAgent_NonBlockingOnFullChannel(t *testing.T) {
	t.Parallel()

	h := &Hub{logger: zap.NewNop()}
	client := &AgentClient{
		ID:   "agent-1",
		Send: make(chan []byte, 1),
		Done: make(chan struct{}),
	}
	client.Send <- []byte(`{"type":"occupied"}`)
	h.clients.Store(client.ID, client)

	done := make(chan error, 1)
	go func() {
		done <- h.SendToAgent(client.ID, Message{Type: ConfigPush})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("SendToAgent blocked on full channel")
	}

	if got := len(client.Send); got != 1 {
		t.Fatalf("expected full channel to stay at length 1, got %d", got)
	}
}

func TestHandleTrafficReport_SendsAck(t *testing.T) {
	t.Parallel()

	client := &AgentClient{
		ID:   uuid.New().String(),
		Send: make(chan []byte, 2),
		Done: make(chan struct{}),
	}
	h := &Hub{
		trafficSvc: &fakeTrafficService{},
		logger:     zap.NewNop(),
		stopCh:     make(chan struct{}),
	}

	payload, err := json.Marshal(TrafficReportPayload{
		AgentID: client.ID,
		Records: []TrafficRecord{{
			RuleID:    uuid.New().String(),
			BytesIn:   10,
			BytesOut:  20,
			Timestamp: time.Now().UTC(),
		}},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	requestID := uuid.NewString()
	h.handleTrafficReport(client, Message{
		Type:    TrafficReport,
		ID:      requestID,
		Payload: payload,
	})

	select {
	case raw := <-client.Send:
		var ack Message
		if err := json.Unmarshal(raw, &ack); err != nil {
			t.Fatalf("decode ack: %v", err)
		}
		if ack.Type != Ack {
			t.Fatalf("expected Ack type, got %s", ack.Type)
		}
		if ack.ID != requestID {
			t.Fatalf("unexpected ack id: %s", ack.ID)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for traffic ack")
	}
}
