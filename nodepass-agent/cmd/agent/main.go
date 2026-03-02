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
	"strconv"
	"strings"
	"syscall"
	"time"

	legacyconfig "nodepass-agent/config"
	"nodepass-agent/internal/config"
	"nodepass-agent/internal/executor"
	"nodepass-agent/internal/metrics"
	"nodepass-agent/internal/npapi"
	"nodepass-agent/internal/process"
	"nodepass-agent/internal/reporter"
	"nodepass-agent/internal/upgrader"
	"nodepass-agent/internal/watchdog"
	"nodepass-agent/internal/ws"
)

const (
	defaultConfigPath = "/opt/nodepass-agent/agent.conf"
	defaultWorkDir    = "/opt/nodepass-agent"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	args := os.Args[1:]
	healthcheck := false
	if len(args) > 0 && args[0] == "healthcheck" {
		healthcheck = true
		args = args[1:]
	}

	configPath, workDir, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if healthcheck {
		if err := runHealthcheck(configPath, workDir); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	if err := run(ctx, logger, configPath, workDir); err != nil {
		logger.Error("agent exited", slog.Any("err", err))
		os.Exit(1)
	}
}

func parseArgs(args []string) (configPath string, workDir string, err error) {
	fs := flag.NewFlagSet("nodepass-agent", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	cfgPath := fs.String("config", defaultConfigPath, "agent config path")
	wd := fs.String("workdir", firstNonEmpty(strings.TrimSpace(os.Getenv("WORK_DIR")), defaultWorkDir), "agent work directory")

	if parseErr := fs.Parse(args); parseErr != nil {
		return "", "", parseErr
	}

	return strings.TrimSpace(*cfgPath), strings.TrimSpace(*wd), nil
}

func run(ctx context.Context, logger *slog.Logger, configPath, workDir string) error {
	cfg, err := resolveRuntimeConfig(configPath, workDir)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger.Info("agent boot", slog.String("version", Version), slog.String("build_time", BuildTime))

	if err := os.MkdirAll(cfg.WorkDir, 0o755); err != nil {
		return fmt.Errorf("prepare work dir: %w", err)
	}

	extractor := process.NewExtractor(cfg.WorkDir)
	if err := extractor.Extract(); err != nil {
		return fmt.Errorf("extract nodepass binary: %w", err)
	}

	agentConf, err := config.Load(cfg.WorkDir)
	if err != nil {
		return fmt.Errorf("load agent.conf: %w", err)
	}

	manager := process.NewProcessManager(extractor.BinPath, cfg.WorkDir)
	if err := manager.Start(); err != nil {
		return fmt.Errorf("start nodepass process: %w", err)
	}

	credentials, err := ensureCredentials(cfg.WorkDir, agentConf, manager)
	if err != nil {
		return err
	}

	npClient := npapi.New(credentials.MasterAddr, credentials.APIKey)

	wd := watchdog.New(manager, agentConf, cfg.WorkDir, func(newCreds process.Credentials) {
		npClient.UpdateCredentials(newCreds.MasterAddr, newCreds.APIKey)
	})
	go wd.Start(ctx)

	wsClient := ws.NewClient(cfg.HubURL, cfg.AgentID, cfg.InternalToken)
	wsClient.SetVersion(Version)
	go wsClient.Start(ctx)
	if err := wsClient.WaitForConnection(30 * time.Second); err != nil {
		logger.Warn("wait websocket connection failed", slog.Any("err", err))
	}

	cache := executor.NewInstanceCache(cfg.WorkDir)
	exec := executor.New(npClient, cache)
	if err := exec.RecoverFromCache(); err != nil {
		logger.Warn("cache recovery failed", slog.Any("err", err))
	}
	relayExec := executor.NewRelayExecutor(npClient, cache)
	agentUpgrader := upgrader.New(cfg.WorkDir, currentVersion)

	router := ws.NewRouter(wsClient, 4)
	router.Register("rule_create", exec.HandleRuleCreate)
	router.Register("rule_start", exec.HandleRuleStart)
	router.Register("rule_stop", exec.HandleRuleStop)
	router.Register("rule_restart", exec.HandleRuleRestart)
	router.Register("rule_delete", exec.HandleRuleDelete)
	router.Register("relay_start", relayExec.HandleRelayStart)
	router.Register("config_reload", exec.HandleConfigReload)
	router.Register("upgrade", func(ctx context.Context, msg ws.HubMessage) error {
		if err := agentUpgrader.HandleUpgrade(ctx, msg); err != nil {
			return err
		}

		go func() {
			time.Sleep(300 * time.Millisecond)
			if err := agentUpgrader.ExecPending(); err != nil && !errors.Is(err, upgrader.ErrNoPendingUpgrade) {
				logger.Error("agent exec upgrade failed", slog.Any("err", err))
			}
		}()
		return nil
	})
	go router.Start(ctx)

	collector := metrics.NewCollector(
		time.Duration(cfg.MetricsInterval)*time.Second,
		wsClient,
		npClient,
		cfg.AgentID,
	)
	go collector.Start(ctx)

	trafficReporter := reporter.NewTrafficReporter(
		time.Duration(cfg.TrafficInterval)*time.Second,
		wsClient,
		npClient,
		cfg.WorkDir,
		cfg.AgentID,
	)
	go trafficReporter.Start(ctx)

	<-ctx.Done()
	logger.Info("agent shutting down")
	wsClient.Close()
	_ = wd.Stop()
	_ = manager.Stop()
	return nil
}

func resolveRuntimeConfig(configPath, workDir string) (*config.Config, error) {
	envCfg, envErr := config.LoadFromEnv()
	if envErr == nil {
		if strings.TrimSpace(workDir) != "" {
			envCfg.WorkDir = strings.TrimSpace(workDir)
		}
		return envCfg, nil
	}

	legacyCfg, legacyErr := legacyconfig.Load(configPath)
	if legacyErr != nil {
		return nil, fmt.Errorf("env config error: %v; legacy config error: %w", envErr, legacyErr)
	}

	resolved := &config.Config{
		HubURL:          firstNonEmpty(os.Getenv("HUB_URL"), os.Getenv("HUB_WS_URL"), legacyCfg.Agent.PanelURL),
		AgentID:         firstNonEmpty(os.Getenv("AGENT_ID"), legacyCfg.Agent.AgentID),
		InternalToken:   firstNonEmpty(os.Getenv("INTERNAL_TOKEN"), os.Getenv("AGENT_TOKEN"), legacyCfg.Agent.DeployToken),
		WorkDir:         firstNonEmpty(os.Getenv("WORK_DIR"), workDir, defaultWorkDir),
		LogLevel:        firstNonEmpty(os.Getenv("LOG_LEVEL"), "info"),
		MetricsInterval: envInt("METRICS_INTERVAL", 30),
		TrafficInterval: envInt("TRAFFIC_INTERVAL", 60),
	}

	if strings.TrimSpace(resolved.HubURL) == "" {
		return nil, errors.New("HUB_URL/HUB_WS_URL is required")
	}
	if strings.TrimSpace(resolved.AgentID) == "" {
		return nil, errors.New("AGENT_ID is required")
	}
	if strings.TrimSpace(resolved.InternalToken) == "" {
		return nil, errors.New("INTERNAL_TOKEN or AGENT_TOKEN is required")
	}
	if resolved.MetricsInterval <= 0 {
		resolved.MetricsInterval = 30
	}
	if resolved.TrafficInterval <= 0 {
		resolved.TrafficInterval = 60
	}
	return resolved, nil
}

func ensureCredentials(workDir string, conf *config.AgentConf, manager *process.ProcessManager) (process.Credentials, error) {
	if conf == nil {
		conf = &config.AgentConf{}
	}

	valid, err := config.Validate(workDir, conf.MasterAddr, conf.APIKey)
	if err == nil && valid {
		return process.Credentials{MasterAddr: conf.MasterAddr, APIKey: conf.APIKey}, nil
	}

	if manager == nil {
		return process.Credentials{}, errors.New("process manager is required when credentials are missing")
	}

	creds, err := manager.WaitForCredentials(30 * time.Second)
	if err != nil {
		if valid {
			return process.Credentials{MasterAddr: conf.MasterAddr, APIKey: conf.APIKey}, nil
		}
		return process.Credentials{}, fmt.Errorf("wait credentials: %w", err)
	}

	conf.MasterAddr = creds.MasterAddr
	conf.APIKey = creds.APIKey
	if saveErr := config.Save(workDir, conf); saveErr != nil {
		return process.Credentials{}, fmt.Errorf("save agent.conf: %w", saveErr)
	}
	return creds, nil
}

func runHealthcheck(configPath, workDir string) error {
	cfg, err := resolveRuntimeConfig(configPath, workDir)
	if err != nil {
		return err
	}
	if cfg.HubURL == "" || cfg.AgentID == "" {
		return errors.New("healthcheck: missing required config")
	}
	return nil
}

func currentVersion() string {
	return Version
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
