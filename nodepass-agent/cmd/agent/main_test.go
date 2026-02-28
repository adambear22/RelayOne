package main

import (
	"os"
	"testing"

	agentconfig "nodepass-agent/config"
)

func TestLoadHubConfigFromConfig(t *testing.T) {
	cfg := agentconfig.DefaultConfig("")
	cfg.Agent.PanelURL = "wss://panel.example/ws/agent"
	cfg.Agent.AgentID = "agent-1"
	cfg.Agent.DeployToken = "token-1"

	resetHubEnv(t)
	hubCfg, err := loadHubConfig(cfg)
	if err != nil {
		t.Fatalf("loadHubConfig returned error: %v", err)
	}
	if hubCfg.HubWSURL != cfg.Agent.PanelURL {
		t.Fatalf("unexpected HubWSURL: %q", hubCfg.HubWSURL)
	}
	if hubCfg.AgentID != cfg.Agent.AgentID {
		t.Fatalf("unexpected AgentID: %q", hubCfg.AgentID)
	}
	if hubCfg.AgentToken != cfg.Agent.DeployToken {
		t.Fatalf("unexpected AgentToken: %q", hubCfg.AgentToken)
	}
}

func TestLoadHubConfigEnvOverridesConfig(t *testing.T) {
	cfg := agentconfig.DefaultConfig("")
	cfg.Agent.PanelURL = "wss://config/ws"
	cfg.Agent.AgentID = "config-agent"
	cfg.Agent.DeployToken = "config-token"

	setenv(t, "HUB_WS_URL", "wss://env/ws")
	setenv(t, "AGENT_ID", "env-agent")
	setenv(t, "AGENT_TOKEN", "env-token")

	hubCfg, err := loadHubConfig(cfg)
	if err != nil {
		t.Fatalf("loadHubConfig returned error: %v", err)
	}
	if hubCfg.HubWSURL != "wss://env/ws" {
		t.Fatalf("unexpected HubWSURL: %q", hubCfg.HubWSURL)
	}
	if hubCfg.AgentID != "env-agent" {
		t.Fatalf("unexpected AgentID: %q", hubCfg.AgentID)
	}
	if hubCfg.AgentToken != "env-token" {
		t.Fatalf("unexpected AgentToken: %q", hubCfg.AgentToken)
	}
}

func TestLoadHubConfigRequiresValues(t *testing.T) {
	cfg := agentconfig.DefaultConfig("")
	resetHubEnv(t)

	_, err := loadHubConfig(cfg)
	if err == nil {
		t.Fatalf("expected error when required values are missing")
	}
}

func TestMergeConfigFromEnv(t *testing.T) {
	cfg := agentconfig.DefaultConfig("")
	resetHubEnv(t)

	setenv(t, "HUB_WS_URL", "wss://panel.example/ws")
	setenv(t, "AGENT_ID", "agent-xyz")
	setenv(t, "AGENT_TOKEN", "tok-xyz")

	changed := mergeConfigFromEnv(cfg)
	if !changed {
		t.Fatalf("expected config to be changed")
	}
	if cfg.Agent.PanelURL != "wss://panel.example/ws" {
		t.Fatalf("unexpected panel_url: %q", cfg.Agent.PanelURL)
	}
	if cfg.Agent.AgentID != "agent-xyz" {
		t.Fatalf("unexpected agent_id: %q", cfg.Agent.AgentID)
	}
	if cfg.Agent.DeployToken != "tok-xyz" {
		t.Fatalf("unexpected deploy_token: %q", cfg.Agent.DeployToken)
	}

	changed = mergeConfigFromEnv(cfg)
	if changed {
		t.Fatalf("expected second merge to be no-op")
	}
}

func resetHubEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"HUB_WS_URL", "AGENT_ID", "AGENT_TOKEN"} {
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("Unsetenv %s failed: %v", key, err)
		}
	}
}

func setenv(t *testing.T, key, value string) {
	t.Helper()
	if err := os.Setenv(key, value); err != nil {
		t.Fatalf("Setenv %s failed: %v", key, err)
	}
	t.Cleanup(func() {
		_ = os.Unsetenv(key)
	})
}
