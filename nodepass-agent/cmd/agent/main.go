package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	agentconfig "nodepass-agent/config"
	"nodepass-agent/embedfs"
	"nodepass-agent/extractor"
	"nodepass-agent/internal/hub_client"
	"nodepass-agent/internal/nodepass"
	mastermgr "nodepass-agent/manager"
)

var (
	Version = "dev"
	Commit  = "unknown"
)

const (
	defaultAgentConfigPath = "/opt/nodepass-agent/agent.conf"
	defaultAgentWorkDir    = "/opt/nodepass-agent"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			os.Exit(runHealthcheck())
		}
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, logger, os.Args[1:]); err != nil {
		logger.Error("agent exited with error", slog.Any("err", err))
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("nodepass-agent", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	configPath := fs.String("config", defaultAgentConfigPath, "agent config file path")
	workDir := fs.String("workdir", defaultAgentWorkDir, "agent working directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if len(fs.Args()) > 0 {
		switch fs.Args()[0] {
		case "extract-only", "--extract-only":
			nodepassPath, err := extractNodePassBinary(logger, *workDir)
			if err != nil {
				return err
			}
			fmt.Println(nodepassPath)
			return nil
		}
	}

	logger.Info("agent starting", slog.String("version", Version), slog.String("commit", Commit))

	cfg, err := agentconfig.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	cfgChanged := mergeConfigFromEnv(cfg)
	if cfgChanged {
		if err := cfg.Save(); err != nil {
			return fmt.Errorf("persist base config from env: %w", err)
		}
	}

	nodepassPath, err := extractNodePassBinary(logger, *workDir)
	if err != nil {
		return fmt.Errorf("extract nodepass: %w", err)
	}

	masterManager := mastermgr.New(nodepassPath, cfg.NodePass.MasterPort)
	masterManager.StartTimeout = time.Duration(cfg.NodePass.StartTimeout) * time.Second
	masterManager.SetCredentials(mastermgr.Credentials{
		MasterAddr: cfg.NodePass.MasterAddr,
		APIKey:     cfg.NodePass.APIKey,
	})

	runtimeManager := nodepass.NewManager(nodepassPath, logger)
	var client *hub_client.Client
	masterManager.OnRenew = func(newCreds mastermgr.Credentials) {
		if err := cfg.SetCredentials(newCreds.MasterAddr, newCreds.APIKey); err != nil {
			logger.Error("save renewed credentials failed", slog.Any("err", err))
		}
		if client != nil {
			client.UpdateNodePassCredentials(newCreds.MasterAddr, newCreds.APIKey)
		}
		logger.Info("credentials renewed via watchdog")
	}

	if cfg.HasValidCredentials() {
		logger.Info("using cached credentials from agent.conf")
		if err := masterManager.StartManaged(ctx); err != nil {
			return fmt.Errorf("start nodepass managed: %w", err)
		}
	} else {
		logger.Info("starting nodepass, waiting for credentials")
		creds, err := masterManager.Start(ctx)
		if err != nil {
			return fmt.Errorf("start nodepass: %w", err)
		}
		if err := cfg.SetCredentials(creds.MasterAddr, creds.APIKey); err != nil {
			return fmt.Errorf("save credentials: %w", err)
		}
		logger.Info(
			"credentials saved to agent.conf",
			slog.String("master_addr", creds.MasterAddr),
			slog.String("api_key_prefix", maskSecretPrefix(creds.APIKey)),
		)
	}

	hubCfg, err := loadHubConfig(cfg)
	if err != nil {
		return err
	}
	client = hub_client.NewClient(hubCfg, runtimeManager, logger)
	runtimeManager.StartTrafficReporter(client)

	if err := client.Start(ctx); err != nil {
		return fmt.Errorf("connect hub: %w", err)
	}
	if err := client.SendDeployProgress("connected", 100, "agent connected"); err != nil {
		logger.Warn("send connected progress failed", slog.Any("err", err))
	}

	<-ctx.Done()
	client.Close()
	_ = masterManager.Stop()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	runtimeManager.Shutdown(shutdownCtx)
	return nil
}

func extractNodePassBinary(logger *slog.Logger, workDir string) (string, error) {
	if strings.TrimSpace(workDir) == "" {
		workDir = strings.TrimSpace(os.Getenv("NODEPASS_WORK_DIR"))
	}
	ex := extractor.New(workDir)
	if err := ex.Extract(embedfs.NodepassFiles); err != nil {
		return "", err
	}

	if logger != nil {
		logger.Info("nodepass binary ready", slog.String("path", ex.BinPath))
	}

	return ex.BinPath, nil
}

func loadHubConfig(cfg *agentconfig.Config) (hub_client.Config, error) {
	hubWSURL := firstNonEmpty(os.Getenv("HUB_WS_URL"), cfg.Agent.PanelURL)
	agentID := firstNonEmpty(os.Getenv("AGENT_ID"), cfg.Agent.AgentID)
	agentToken := firstNonEmpty(os.Getenv("AGENT_TOKEN"), cfg.Agent.DeployToken)

	if strings.TrimSpace(hubWSURL) == "" {
		return hub_client.Config{}, errors.New("hub ws url is required (HUB_WS_URL or agent.panel_url)")
	}
	if strings.TrimSpace(agentID) == "" {
		return hub_client.Config{}, errors.New("agent id is required (AGENT_ID or agent.agent_id)")
	}
	if strings.TrimSpace(agentToken) == "" {
		return hub_client.Config{}, errors.New("agent token is required (AGENT_TOKEN or agent.deploy_token)")
	}

	version := strings.TrimSpace(Version)
	if version == "" {
		version = "dev"
	}

	return hub_client.Config{
		HubWSURL:   strings.TrimSpace(hubWSURL),
		AgentID:    strings.TrimSpace(agentID),
		AgentToken: strings.TrimSpace(agentToken),
		Version:    version,
	}, nil
}

func mergeConfigFromEnv(cfg *agentconfig.Config) bool {
	changed := false

	if v := strings.TrimSpace(os.Getenv("HUB_WS_URL")); v != "" && strings.TrimSpace(cfg.Agent.PanelURL) == "" {
		cfg.Agent.PanelURL = v
		changed = true
	}
	if v := strings.TrimSpace(os.Getenv("AGENT_ID")); v != "" && strings.TrimSpace(cfg.Agent.AgentID) == "" {
		cfg.Agent.AgentID = v
		changed = true
	}
	if v := strings.TrimSpace(os.Getenv("AGENT_TOKEN")); v != "" && strings.TrimSpace(cfg.Agent.DeployToken) == "" {
		cfg.Agent.DeployToken = v
		changed = true
	}

	return changed
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func maskSecretPrefix(secret string) string {
	trimmed := strings.TrimSpace(secret)
	if trimmed == "" {
		return ""
	}
	if len(trimmed) <= 8 {
		return trimmed
	}
	return trimmed[:8] + "..."
}

func runHealthcheck() int {
	required := []string{"HUB_WS_URL", "AGENT_ID", "AGENT_TOKEN"}
	for _, envKey := range required {
		if strings.TrimSpace(os.Getenv(envKey)) == "" {
			return 1
		}
	}
	return 0
}
