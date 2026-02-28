package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"nodepass-agent/embedfs"
	"nodepass-agent/extractor"
	"nodepass-agent/internal/hub_client"
	"nodepass-agent/internal/nodepass"
)

var (
	Version = "dev"
	Commit  = "unknown"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			os.Exit(runHealthcheck())
		case "extract-only", "--extract-only":
			logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
			nodepassPath, err := extractNodePassBinary(logger)
			if err != nil {
				logger.Error("extract nodepass failed", slog.Any("err", err))
				os.Exit(1)
			}
			fmt.Println(nodepassPath)
			return
		}
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger.Info("agent starting", slog.String("version", Version), slog.String("commit", Commit))

	nodepassPath, err := extractNodePassBinary(logger)
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

func extractNodePassBinary(logger *slog.Logger) (string, error) {
	workDir := strings.TrimSpace(os.Getenv("NODEPASS_WORK_DIR"))
	ex := extractor.New(workDir)
	if err := ex.Extract(embedfs.NodepassFiles); err != nil {
		return "", err
	}

	if logger != nil {
		logger.Info("nodepass binary ready", slog.String("path", ex.BinPath))
	}

	return ex.BinPath, nil
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
