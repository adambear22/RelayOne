package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"nodepass-agent/internal/config"
	"nodepass-agent/internal/process"
)

func TestEnsureCredentialsUsesCachedWhenValid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/info" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	conf := &config.AgentConf{MasterAddr: srv.URL, APIKey: "k"}
	creds, err := ensureCredentials(t.TempDir(), conf, nil)
	if err != nil {
		t.Fatalf("ensureCredentials: %v", err)
	}
	if creds.MasterAddr != srv.URL {
		t.Fatalf("unexpected master addr: %s", creds.MasterAddr)
	}
}

func TestEnsureCredentialsFailsWithoutManagerWhenMissing(t *testing.T) {
	_, err := ensureCredentials(t.TempDir(), &config.AgentConf{}, nil)
	if err == nil {
		t.Fatalf("expected error when manager is nil and credentials are missing")
	}
}

func TestEnsureCredentialsWaitsForManager(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script helper is unix-only")
	}

	workDir := t.TempDir()
	binPath := filepath.Join(workDir, "nodepass")
	script := "#!/bin/sh\n" +
		"echo 'MASTER_ADDR=127.0.0.1:19090'\n" +
		"echo 'API_KEY=test-key'\n" +
		"while true; do sleep 1; done\n"
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write helper binary: %v", err)
	}

	manager := process.NewProcessManager(binPath, workDir)
	if err := manager.Start(); err != nil {
		t.Fatalf("start manager: %v", err)
	}
	defer manager.Stop()

	conf := &config.AgentConf{}
	creds, err := ensureCredentials(workDir, conf, manager)
	if err != nil {
		t.Fatalf("ensureCredentials: %v", err)
	}
	if creds.APIKey != "test-key" {
		t.Fatalf("unexpected api key: %s", creds.APIKey)
	}

	loaded, err := config.Load(workDir)
	if err != nil {
		t.Fatalf("load saved conf: %v", err)
	}
	if loaded.APIKey != "test-key" {
		t.Fatalf("expected persisted api key")
	}
}

func TestResolveRuntimeConfigFallbackToLegacyFile(t *testing.T) {
	clearEnvForConfig(t)

	workDir := t.TempDir()
	configPath := filepath.Join(workDir, "agent.conf")
	content := strings.Join([]string{
		"[agent]",
		"panel_url = ws://127.0.0.1:8080/ws/agent",
		"agent_id = agent-from-file",
		"deploy_token = token-from-file",
		"",
	}, "\n")
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := resolveRuntimeConfig(configPath, workDir)
	if err != nil {
		t.Fatalf("resolveRuntimeConfig: %v", err)
	}
	if cfg.HubURL != "ws://127.0.0.1:8080/ws/agent" {
		t.Fatalf("unexpected hub url: %s", cfg.HubURL)
	}
	if cfg.AgentID != "agent-from-file" {
		t.Fatalf("unexpected agent id: %s", cfg.AgentID)
	}
	if cfg.InternalToken != "token-from-file" {
		t.Fatalf("unexpected token")
	}
}

func clearEnvForConfig(t *testing.T) {
	t.Helper()
	keys := []string{
		"HUB_URL",
		"HUB_WS_URL",
		"AGENT_ID",
		"INTERNAL_TOKEN",
		"AGENT_TOKEN",
		"WORK_DIR",
		"LOG_LEVEL",
		"METRICS_INTERVAL",
		"TRAFFIC_INTERVAL",
	}
	for _, key := range keys {
		prev, existed := os.LookupEnv(key)
		_ = os.Unsetenv(key)
		if existed {
			envKey := key
			value := prev
			t.Cleanup(func() {
				_ = os.Setenv(envKey, value)
			})
		}
	}
}
