package watchdog

import (
	"context"
	"sync"
	"testing"
	"time"

	"nodepass-agent/internal/config"
	"nodepass-agent/internal/process"
)

type mockManager struct {
	exitCh     chan struct{}
	startCount int
	mu         sync.Mutex
}

func (m *mockManager) Start() error {
	m.mu.Lock()
	m.startCount++
	m.mu.Unlock()
	return nil
}

func (m *mockManager) WaitForCredentials(timeout time.Duration) (process.Credentials, error) {
	_ = timeout
	return process.Credentials{MasterAddr: "http://127.0.0.1:19090", APIKey: "new-key"}, nil
}

func (m *mockManager) ExitCh() <-chan struct{} {
	return m.exitCh
}

func TestWatchdogRestartOnExit(t *testing.T) {
	mgr := &mockManager{exitCh: make(chan struct{})}
	wd := New(mgr, &config.AgentConf{}, t.TempDir(), nil)
	wd.validateFn = func(workDir, masterAddr, apiKey string) (bool, error) {
		return true, nil
	}
	wd.saveFn = func(workDir string, conf *config.AgentConf) error { return nil }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go wd.Start(ctx)

	close(mgr.exitCh)
	time.Sleep(1500 * time.Millisecond)

	mgr.mu.Lock()
	startCount := mgr.startCount
	mgr.mu.Unlock()
	if startCount == 0 {
		t.Fatalf("expected restart to call Start")
	}

	stats := wd.Stats()
	if stats.TotalRestarts == 0 {
		t.Fatalf("expected restart stats to be updated")
	}
}

func TestBackoffDelayRange(t *testing.T) {
	mgr := &mockManager{exitCh: make(chan struct{})}
	wd := New(mgr, &config.AgentConf{}, t.TempDir(), nil)
	wd.rnd.Seed(1)

	delay := wd.backoffDelay(3)
	if delay < 7*time.Second || delay > 11*time.Second {
		t.Fatalf("unexpected delay for attempt=3: %s", delay)
	}
}
