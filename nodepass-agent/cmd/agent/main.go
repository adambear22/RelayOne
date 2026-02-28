package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	agent "nodepass-agent"
	"nodepass-agent/internal/hub_client"
	"nodepass-agent/internal/nodepass"
)

var (
	Version = "dev"
	Commit  = "unknown"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(runHealthcheck())
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger.Info("agent starting", slog.String("version", Version), slog.String("commit", Commit))

	nodepassPath, err := agent.ExtractNodePass(runtime.GOARCH, Version)
	if err != nil {
		logger.Error("extract nodepass failed", slog.Any("err", err))
		os.Exit(1)
	}

	manager := nodepass.NewManager(nodepassPath, logger)
	cfg, err := hub_client.LoadConfigFromEnv(Version)
	if err != nil {
		logger.Error("load hub config failed", slog.Any("err", err))
		os.Exit(1)
	}

	client := hub_client.NewClient(cfg, manager, logger)
	manager.StartTrafficReporter(client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := client.Start(ctx); err != nil {
		logger.Error("connect hub failed", slog.Any("err", err))
		os.Exit(1)
	}

	if err := client.SendDeployProgress("connected", 100, "agent connected"); err != nil {
		logger.Warn("send connected progress failed", slog.Any("err", err))
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	cancel()
	client.Close()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	manager.Shutdown(shutdownCtx)
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
