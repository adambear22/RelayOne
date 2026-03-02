package executor

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"nodepass-agent/internal/npapi"
	"nodepass-agent/internal/ws"
)

type mockNPAPI struct {
	instances      map[string]npapi.Instance
	createdOrder   []string
	createCount    int
	deleteCount    int
	startCount     int
	stopCount      int
	nextInstanceID int
	failCreateAt   int
	failStartAt    int
}

func newMockNPAPI() *mockNPAPI {
	return &mockNPAPI{instances: map[string]npapi.Instance{}, nextInstanceID: 1}
}

func (m *mockNPAPI) ListInstances() ([]npapi.Instance, error) {
	out := make([]npapi.Instance, 0, len(m.instances))
	for _, ins := range m.instances {
		out = append(out, ins)
	}
	return out, nil
}

func (m *mockNPAPI) GetInstance(id string) (*npapi.Instance, error) {
	ins, ok := m.instances[id]
	if !ok {
		return nil, npapi.ErrNotFound
	}
	return &ins, nil
}

func (m *mockNPAPI) CreateInstance(req npapi.CreateInstanceRequest) (*npapi.Instance, error) {
	if m.failCreateAt > 0 && m.createCount+1 == m.failCreateAt {
		m.createCount++
		return nil, errors.New("create failed")
	}
	id := "ins-" + strconv.Itoa(m.nextInstanceID)
	m.nextInstanceID++
	ins := npapi.Instance{ID: id, URL: req.URL, Status: "created"}
	m.instances[id] = ins
	m.createCount++
	m.createdOrder = append(m.createdOrder, id)
	return &ins, nil
}

func (m *mockNPAPI) DeleteInstance(id string) error {
	delete(m.instances, id)
	m.deleteCount++
	return nil
}

func (m *mockNPAPI) StartInstance(id string) error {
	if m.failStartAt > 0 && m.startCount+1 == m.failStartAt {
		m.startCount++
		return errors.New("start failed")
	}
	ins := m.instances[id]
	ins.Status = "running"
	m.instances[id] = ins
	m.startCount++
	return nil
}

func (m *mockNPAPI) StopInstance(id string) error {
	ins := m.instances[id]
	ins.Status = "stopped"
	m.instances[id] = ins
	m.stopCount++
	return nil
}

func (m *mockNPAPI) UpdateInstance(id string, req npapi.UpdateInstanceRequest) (*npapi.Instance, error) {
	ins := m.instances[id]
	if req.URL != "" {
		ins.URL = req.URL
	}
	m.instances[id] = ins
	return &ins, nil
}

func TestHandleRuleCreateStoresCache(t *testing.T) {
	mock := newMockNPAPI()
	cache := NewInstanceCache(t.TempDir())
	exec := New(mock, cache)

	payload, _ := json.Marshal(RulePayload{
		RuleID:     "rule-1",
		Mode:       "server",
		ListenPort: 1080,
		Target:     "127.0.0.1:8080",
	})
	msg := ws.HubMessage{Type: "rule_create", ID: "m1", Payload: payload}

	if err := exec.HandleRuleCreate(context.Background(), msg); err != nil {
		t.Fatalf("handle rule create: %v", err)
	}

	item, ok := cache.Get("rule-1")
	if !ok || item.InstanceID == "" {
		t.Fatalf("expected cache item for rule-1")
	}
	if item.Status != "running" {
		t.Fatalf("unexpected status: %s", item.Status)
	}
}

func TestRecoverFromCacheCleansOrphans(t *testing.T) {
	mock := newMockNPAPI()
	cache := NewInstanceCache(t.TempDir())

	_ = cache.Set(CacheItem{RuleID: "rule-a", InstanceID: "ins-a", Status: "running"})
	_ = cache.Set(CacheItem{RuleID: "rule-b", InstanceID: "ins-b", Status: "running"})

	mock.instances["ins-a"] = npapi.Instance{ID: "ins-a", RuleID: "rule-a", Status: "running"}
	mock.instances["ins-x"] = npapi.Instance{ID: "ins-x", RuleID: "rule-x", Status: "running"}

	exec := New(mock, cache)
	if err := exec.RecoverFromCache(); err != nil {
		t.Fatalf("recover: %v", err)
	}

	if _, ok := cache.Get("rule-b"); ok {
		t.Fatalf("expected stale cache rule-b removed")
	}
	if _, ok := mock.instances["ins-x"]; ok {
		t.Fatalf("expected orphan instance deleted")
	}
}

func TestBuildServerAndClientURL(t *testing.T) {
	serverURL := BuildServerURL("0.0.0.0:1080", "127.0.0.1:8080", "p1", 1, 2)
	if serverURL == "" {
		t.Fatalf("expected server url")
	}
	clientURL := BuildClientURL("1.1.1.1:9000", "127.0.0.1:80", "p2", 1, 2)
	if clientURL == "" {
		t.Fatalf("expected client url")
	}
}
