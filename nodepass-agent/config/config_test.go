package config

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig("")
	if cfg.path != defaultConfigPath {
		t.Fatalf("expected default path %q, got %q", defaultConfigPath, cfg.path)
	}
	if cfg.NodePass.MasterPort != defaultMasterPort {
		t.Fatalf("unexpected default master port: %d", cfg.NodePass.MasterPort)
	}
	if cfg.NodePass.StartTimeout != defaultStartTimeout {
		t.Fatalf("unexpected default start timeout: %d", cfg.NodePass.StartTimeout)
	}
	if cfg.Panel.HeartbeatInterval != defaultHeartbeatSeconds {
		t.Fatalf("unexpected default heartbeat interval: %d", cfg.Panel.HeartbeatInterval)
	}
	if cfg.Panel.CommandTimeout != defaultCommandTimeout {
		t.Fatalf("unexpected default command timeout: %d", cfg.Panel.CommandTimeout)
	}
}

func TestLoadWhenFileMissingReturnsDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.conf")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.path != path {
		t.Fatalf("expected path %q, got %q", path, cfg.path)
	}
	if cfg.NodePass.MasterPort != defaultMasterPort {
		t.Fatalf("expected default master port, got %d", cfg.NodePass.MasterPort)
	}
}

func TestLoadParsesConfigFile(t *testing.T) {
	content := strings.Join([]string{
		"# custom comment",
		"[agent]",
		"agent_id = test-agent",
		"panel_url = wss://panel.example/ws",
		"deploy_token = tok_123",
		"connect_addr = 10.0.0.1",
		"egress_network = eth0",
		"",
		"[nodepass]",
		"DEPLOY_DEFAULT_MASTER_ADDR = http://127.0.0.1:9090",
		"DEPLOY_DEFAULT_MASTER_API_KEY = npk_abc",
		"master_port = 12345",
		"start_timeout = 45",
		"",
		"[panel]",
		"heartbeat_interval = 12",
		"command_timeout = 18",
	}, "\n") + "\n"

	path := filepath.Join(t.TempDir(), "agent.conf")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Agent.AgentID != "test-agent" {
		t.Fatalf("unexpected AgentID: %q", cfg.Agent.AgentID)
	}
	if cfg.NodePass.MasterAddr != "http://127.0.0.1:9090" {
		t.Fatalf("unexpected MasterAddr: %q", cfg.NodePass.MasterAddr)
	}
	if cfg.NodePass.APIKey != "npk_abc" {
		t.Fatalf("unexpected API key: %q", cfg.NodePass.APIKey)
	}
	if cfg.NodePass.MasterPort != 12345 {
		t.Fatalf("unexpected master port: %d", cfg.NodePass.MasterPort)
	}
	if cfg.Panel.CommandTimeout != 18 {
		t.Fatalf("unexpected command timeout: %d", cfg.Panel.CommandTimeout)
	}
}

func TestSavePreservesCommentsAndUpdatesCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.conf")
	seed := strings.Join([]string{
		"# keep this comment",
		"[nodepass]",
		"DEPLOY_DEFAULT_MASTER_ADDR = http://127.0.0.1:9000 # old addr",
		"DEPLOY_DEFAULT_MASTER_API_KEY = old_key # old key",
		"master_port = 9000",
		"start_timeout = 20",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if err := cfg.SetCredentials("http://127.0.0.1:9090", "npk_new"); err != nil {
		t.Fatalf("SetCredentials returned error: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "# keep this comment") {
		t.Fatalf("expected original comment to be preserved")
	}
	if !strings.Contains(text, "DEPLOY_DEFAULT_MASTER_ADDR = http://127.0.0.1:9090") {
		t.Fatalf("expected updated master addr, got: %s", text)
	}
	if !strings.Contains(text, "DEPLOY_DEFAULT_MASTER_API_KEY = npk_new") {
		t.Fatalf("expected updated api key, got: %s", text)
	}
}

func TestSetCredentialsCreatesFileWhenMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.conf")
	cfg := DefaultConfig(path)

	if err := cfg.SetCredentials("http://127.0.0.1:9090", "npk_created"); err != nil {
		t.Fatalf("SetCredentials returned error: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "DEPLOY_DEFAULT_MASTER_ADDR = http://127.0.0.1:9090") {
		t.Fatalf("master addr not written: %s", text)
	}
	if !strings.Contains(text, "DEPLOY_DEFAULT_MASTER_API_KEY = npk_created") {
		t.Fatalf("api key not written: %s", text)
	}
}

func TestHasValidCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/info" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if got := r.Header.Get("X-API-Key"); got != "npk_ok" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	cfg := DefaultConfig("")
	cfg.NodePass.MasterAddr = server.URL
	cfg.NodePass.APIKey = "npk_ok"
	if !cfg.HasValidCredentials() {
		t.Fatalf("expected credentials to be valid")
	}

	cfg.NodePass.APIKey = "invalid"
	if cfg.HasValidCredentials() {
		t.Fatalf("expected credentials to be invalid")
	}

	cfg.NodePass.MasterAddr = ""
	if cfg.HasValidCredentials() {
		t.Fatalf("expected empty address to be invalid")
	}
}

func TestSaveKeepsCustomCommentOutsideManagedKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.conf")
	seed := strings.Join([]string{
		"[agent]",
		"panel_url = wss://panel.example/ws",
		"# custom line should stay",
		"deploy_token = tok",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	cfg.Agent.AgentID = "id-1"
	cfg.NodePass.MasterAddr = "http://127.0.0.1:9090"
	cfg.NodePass.APIKey = "npk_x"
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if !strings.Contains(string(raw), "# custom line should stay") {
		t.Fatalf("expected custom comment to stay, got:\n%s", string(raw))
	}
}

func TestHasValidCredentialsHandlesServerDown(t *testing.T) {
	cfg := DefaultConfig("")
	cfg.NodePass.MasterAddr = "http://127.0.0.1:1"
	cfg.NodePass.APIKey = "npk_ok"
	if cfg.HasValidCredentials() {
		t.Fatalf("expected false for unreachable server")
	}
}

func TestStringReturnsCurrentSource(t *testing.T) {
	cfg := DefaultConfig(filepath.Join(t.TempDir(), "agent.conf"))
	cfg.Agent.AgentID = "agent-x"
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	got := cfg.String()
	if !strings.Contains(got, "agent_id = agent-x") {
		t.Fatalf("String() missing expected content: %s", got)
	}
}

func TestLoadInvalidNumbersFallbackToDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.conf")
	seed := fmt.Sprintf("[nodepass]\nmaster_port = x\nstart_timeout = y\n[panel]\nheartbeat_interval = z\ncommand_timeout = q\n")
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.NodePass.MasterPort != defaultMasterPort {
		t.Fatalf("expected default master port, got %d", cfg.NodePass.MasterPort)
	}
	if cfg.NodePass.StartTimeout != defaultStartTimeout {
		t.Fatalf("expected default start timeout, got %d", cfg.NodePass.StartTimeout)
	}
	if cfg.Panel.HeartbeatInterval != defaultHeartbeatSeconds {
		t.Fatalf("expected default heartbeat interval, got %d", cfg.Panel.HeartbeatInterval)
	}
	if cfg.Panel.CommandTimeout != defaultCommandTimeout {
		t.Fatalf("expected default command timeout, got %d", cfg.Panel.CommandTimeout)
	}
}
