package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadLegacyAgentConf(t *testing.T) {
	workDir := t.TempDir()
	path := filepath.Join(workDir, "agent.conf")
	content := strings.Join([]string{
		"[nodepass]",
		"DEPLOY_DEFAULT_MASTER_ADDR=http://127.0.0.1:19090",
		"DEPLOY_DEFAULT_MASTER_API_KEY=legacy-key",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write legacy conf: %v", err)
	}

	conf, err := Load(workDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if conf.MasterAddr != "http://127.0.0.1:19090" {
		t.Fatalf("unexpected master addr: %s", conf.MasterAddr)
	}
	if conf.APIKey != "legacy-key" {
		t.Fatalf("unexpected api key: %s", conf.APIKey)
	}
}

func TestSaveLegacyAgentConfKeepsFormat(t *testing.T) {
	workDir := t.TempDir()
	path := filepath.Join(workDir, "agent.conf")
	content := strings.Join([]string{
		"[agent]",
		"agent_id=agent-1",
		"",
		"[nodepass]",
		"DEPLOY_DEFAULT_MASTER_ADDR=http://old:19090",
		"DEPLOY_DEFAULT_MASTER_API_KEY=old-key",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write legacy conf: %v", err)
	}

	if err := Save(workDir, &AgentConf{MasterAddr: "http://new:19090", APIKey: "new-key"}); err != nil {
		t.Fatalf("save: %v", err)
	}

	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read updated: %v", err)
	}
	text := string(updated)
	if !strings.Contains(text, "[agent]") {
		t.Fatalf("expected legacy sections to be preserved")
	}
	if !strings.Contains(text, "DEPLOY_DEFAULT_MASTER_ADDR=http://new:19090") {
		t.Fatalf("expected updated master addr in legacy conf")
	}
	if !strings.Contains(text, "DEPLOY_DEFAULT_MASTER_API_KEY=new-key") {
		t.Fatalf("expected updated api key in legacy conf")
	}
}

func TestSaveAndLoadJSONAgentConf(t *testing.T) {
	workDir := t.TempDir()
	if err := Save(workDir, &AgentConf{MasterAddr: "http://127.0.0.1:9090", APIKey: "json-key"}); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := Load(workDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.MasterAddr != "http://127.0.0.1:9090" || loaded.APIKey != "json-key" {
		t.Fatalf("unexpected loaded conf: %+v", loaded)
	}
}
