package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	HubURL          string `env:"HUB_URL,required"`
	AgentID         string `env:"AGENT_ID,required"`
	InternalToken   string `env:"INTERNAL_TOKEN,required"`
	WorkDir         string `env:"WORK_DIR" envDefault:"/var/lib/nodepass-agent"`
	LogLevel        string `env:"LOG_LEVEL" envDefault:"info"`
	MetricsInterval int    `env:"METRICS_INTERVAL" envDefault:"30"`
	TrafficInterval int    `env:"TRAFFIC_INTERVAL" envDefault:"60"`
}

func LoadFromEnv() (*Config, error) {
	cfg := &Config{
		HubURL:          strings.TrimSpace(os.Getenv("HUB_URL")),
		AgentID:         strings.TrimSpace(os.Getenv("AGENT_ID")),
		InternalToken:   strings.TrimSpace(os.Getenv("INTERNAL_TOKEN")),
		WorkDir:         defaultString(os.Getenv("WORK_DIR"), "/var/lib/nodepass-agent"),
		LogLevel:        defaultString(os.Getenv("LOG_LEVEL"), "info"),
		MetricsInterval: defaultInt(os.Getenv("METRICS_INTERVAL"), 30),
		TrafficInterval: defaultInt(os.Getenv("TRAFFIC_INTERVAL"), 60),
	}

	if cfg.HubURL == "" {
		return nil, errors.New("HUB_URL is required")
	}
	if cfg.AgentID == "" {
		return nil, errors.New("AGENT_ID is required")
	}
	if cfg.InternalToken == "" {
		return nil, errors.New("INTERNAL_TOKEN is required")
	}
	if cfg.MetricsInterval <= 0 {
		cfg.MetricsInterval = 30
	}
	if cfg.TrafficInterval <= 0 {
		cfg.TrafficInterval = 60
	}
	return cfg, nil
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func defaultInt(value string, fallback int) int {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(trimmed)
	if err != nil {
		return fallback
	}
	return parsed
}
