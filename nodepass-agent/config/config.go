package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultConfigPath       = "/opt/nodepass-agent/agent.conf"
	defaultMasterPort       = 9090
	defaultStartTimeout     = 30
	defaultHeartbeatSeconds = 30
	defaultCommandTimeout   = 30
)

var (
	sectionLineRE = regexp.MustCompile(`^\s*\[([^\]]+)\]\s*$`)
	keyValueLine  = regexp.MustCompile(`^(\s*)([A-Za-z0-9_.-]+)(\s*=\s*)(.*)$`)
)

type Config struct {
	Agent    AgentSection
	NodePass NodePassSection
	Panel    PanelSection
	path     string

	sourceLines []string
}

type AgentSection struct {
	AgentID       string
	PanelURL      string
	DeployToken   string
	ConnectAddr   string
	EgressNetwork string
}

type NodePassSection struct {
	MasterAddr   string `ini:"DEPLOY_DEFAULT_MASTER_ADDR"`
	APIKey       string `ini:"DEPLOY_DEFAULT_MASTER_API_KEY"`
	MasterPort   int    `ini:"master_port"`
	StartTimeout int    `ini:"start_timeout"`
}

type PanelSection struct {
	HeartbeatInterval int
	CommandTimeout    int
}

func Load(path string) (*Config, error) {
	cleanPath := normalizePath(path)
	raw, err := os.ReadFile(cleanPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DefaultConfig(cleanPath), nil
		}
		return nil, err
	}

	cfg := DefaultConfig(cleanPath)
	cfg.sourceLines = splitLines(string(raw))
	parseLinesIntoConfig(cfg.sourceLines, cfg)
	cfg.applyDefaults()
	return cfg, nil
}

func (c *Config) Save() error {
	if c == nil {
		return errors.New("config is nil")
	}

	c.path = normalizePath(c.path)
	c.applyDefaults()

	lines := c.sourceLines
	if len(lines) == 0 {
		lines = defaultTemplateLines(c)
	} else {
		lines = append([]string(nil), lines...)
	}

	lines = upsertSectionKey(lines, "agent", "agent_id", c.Agent.AgentID)
	lines = upsertSectionKey(lines, "agent", "panel_url", c.Agent.PanelURL)
	lines = upsertSectionKey(lines, "agent", "deploy_token", c.Agent.DeployToken)
	lines = upsertSectionKey(lines, "agent", "connect_addr", c.Agent.ConnectAddr)
	lines = upsertSectionKey(lines, "agent", "egress_network", c.Agent.EgressNetwork)

	lines = upsertSectionKey(lines, "nodepass", "DEPLOY_DEFAULT_MASTER_ADDR", c.NodePass.MasterAddr)
	lines = upsertSectionKey(lines, "nodepass", "DEPLOY_DEFAULT_MASTER_API_KEY", c.NodePass.APIKey)
	lines = upsertSectionKey(lines, "nodepass", "master_port", strconv.Itoa(c.NodePass.MasterPort))
	lines = upsertSectionKey(lines, "nodepass", "start_timeout", strconv.Itoa(c.NodePass.StartTimeout))

	lines = upsertSectionKey(lines, "panel", "heartbeat_interval", strconv.Itoa(c.Panel.HeartbeatInterval))
	lines = upsertSectionKey(lines, "panel", "command_timeout", strconv.Itoa(c.Panel.CommandTimeout))

	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(c.path), ".agent.conf.*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()

	content := strings.Join(lines, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if _, err := tmpFile.WriteString(content); err != nil {
		tmpFile.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Chmod(0o600); err != nil {
		tmpFile.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	if err := os.Rename(tmpPath, c.path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	c.sourceLines = lines
	return nil
}

func (c *Config) SetCredentials(addr, apiKey string) error {
	if c == nil {
		return errors.New("config is nil")
	}

	c.NodePass.MasterAddr = strings.TrimSpace(addr)
	c.NodePass.APIKey = strings.TrimSpace(apiKey)
	return c.Save()
}

func (c *Config) HasValidCredentials() bool {
	if c == nil {
		return false
	}

	masterAddr := strings.TrimSpace(c.NodePass.MasterAddr)
	apiKey := strings.TrimSpace(c.NodePass.APIKey)
	if masterAddr == "" || apiKey == "" {
		return false
	}
	if !strings.HasPrefix(masterAddr, "http://") && !strings.HasPrefix(masterAddr, "https://") {
		return false
	}

	url := strings.TrimRight(masterAddr, "/") + "/api/v1/info"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-API-Key", apiKey)

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

func DefaultConfig(path string) *Config {
	cfg := &Config{
		path:  normalizePath(path),
		Agent: AgentSection{},
		NodePass: NodePassSection{
			MasterPort:   defaultMasterPort,
			StartTimeout: defaultStartTimeout,
		},
		Panel: PanelSection{
			HeartbeatInterval: defaultHeartbeatSeconds,
			CommandTimeout:    defaultCommandTimeout,
		},
	}
	cfg.sourceLines = defaultTemplateLines(cfg)
	return cfg
}

func (c *Config) applyDefaults() {
	if c.NodePass.MasterPort <= 0 {
		c.NodePass.MasterPort = defaultMasterPort
	}
	if c.NodePass.StartTimeout <= 0 {
		c.NodePass.StartTimeout = defaultStartTimeout
	}
	if c.Panel.HeartbeatInterval <= 0 {
		c.Panel.HeartbeatInterval = defaultHeartbeatSeconds
	}
	if c.Panel.CommandTimeout <= 0 {
		c.Panel.CommandTimeout = defaultCommandTimeout
	}
}

func parseLinesIntoConfig(lines []string, cfg *Config) {
	currentSection := ""

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}

		if matches := sectionLineRE.FindStringSubmatch(trimmed); len(matches) == 2 {
			currentSection = strings.ToLower(strings.TrimSpace(matches[1]))
			continue
		}

		_, key, _, rhs, ok := parseKeyValueLine(line)
		if !ok {
			continue
		}
		value, _ := splitValueAndComment(rhs)
		normalizedKey := strings.ToLower(strings.TrimSpace(key))

		switch currentSection {
		case "agent":
			switch normalizedKey {
			case "agent_id":
				cfg.Agent.AgentID = value
			case "panel_url":
				cfg.Agent.PanelURL = value
			case "deploy_token":
				cfg.Agent.DeployToken = value
			case "connect_addr":
				cfg.Agent.ConnectAddr = value
			case "egress_network":
				cfg.Agent.EgressNetwork = value
			}
		case "nodepass":
			switch normalizedKey {
			case "deploy_default_master_addr":
				cfg.NodePass.MasterAddr = value
			case "deploy_default_master_api_key":
				cfg.NodePass.APIKey = value
			case "master_port":
				if parsed, err := strconv.Atoi(value); err == nil {
					cfg.NodePass.MasterPort = parsed
				}
			case "start_timeout":
				if parsed, err := strconv.Atoi(value); err == nil {
					cfg.NodePass.StartTimeout = parsed
				}
			}
		case "panel":
			switch normalizedKey {
			case "heartbeat_interval":
				if parsed, err := strconv.Atoi(value); err == nil {
					cfg.Panel.HeartbeatInterval = parsed
				}
			case "command_timeout":
				if parsed, err := strconv.Atoi(value); err == nil {
					cfg.Panel.CommandTimeout = parsed
				}
			}
		}
	}
}

func upsertSectionKey(lines []string, section, key, value string) []string {
	sectionLower := strings.ToLower(strings.TrimSpace(section))
	insertLine := fmt.Sprintf("%s = %s", key, value)

	sectionStart := -1
	sectionEnd := len(lines)
	currentSection := ""

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if matches := sectionLineRE.FindStringSubmatch(trimmed); len(matches) == 2 {
			header := strings.ToLower(strings.TrimSpace(matches[1]))
			if header == sectionLower {
				sectionStart = i
				currentSection = header
				continue
			}

			if currentSection == sectionLower {
				sectionEnd = i
				break
			}
			currentSection = header
		}
	}

	if sectionStart == -1 {
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
			lines = append(lines, "")
		}
		lines = append(lines, fmt.Sprintf("[%s]", section), insertLine)
		return lines
	}

	for i := sectionStart + 1; i < sectionEnd; i++ {
		_, existingKey, sep, rhs, ok := parseKeyValueLine(lines[i])
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(existingKey), strings.TrimSpace(key)) {
			_, comment := splitValueAndComment(rhs)
			if comment == "" {
				lines[i] = strings.TrimSpace(existingKey) + sep + value
			} else {
				lines[i] = strings.TrimSpace(existingKey) + sep + value + comment
			}
			return lines
		}
	}

	before := append([]string(nil), lines[:sectionEnd]...)
	after := append([]string(nil), lines[sectionEnd:]...)
	before = append(before, insertLine)
	return append(before, after...)
}

func parseKeyValueLine(line string) (indent string, key string, sep string, rhs string, ok bool) {
	matches := keyValueLine.FindStringSubmatch(line)
	if len(matches) != 5 {
		return "", "", "", "", false
	}
	return matches[1], matches[2], matches[3], matches[4], true
}

func splitValueAndComment(raw string) (value string, comment string) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", ""
	}

	idx := strings.Index(raw, "#")
	if idx <= 0 {
		return strings.TrimSpace(raw), ""
	}

	before := raw[:idx]
	if len(before) == 0 {
		return strings.TrimSpace(raw), ""
	}
	last := before[len(before)-1]
	if last != ' ' && last != '\t' {
		return strings.TrimSpace(raw), ""
	}

	value = strings.TrimSpace(before)
	commentPart := strings.TrimSpace(raw[idx:])
	if commentPart == "" {
		return value, ""
	}
	return value, " " + commentPart
}

func splitLines(content string) []string {
	normalized := strings.ReplaceAll(content, "\r\n", "\n")
	parts := strings.Split(normalized, "\n")
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

func defaultTemplateLines(cfg *Config) []string {
	return []string{
		"# NodePass Agent 配置文件",
		"# 由 Agent 自动生成，请勿手动修改 [nodepass] 段",
		"# 其他段可手动修改",
		"",
		"[agent]",
		fmt.Sprintf("agent_id = %s", cfg.Agent.AgentID),
		fmt.Sprintf("panel_url = %s", cfg.Agent.PanelURL),
		fmt.Sprintf("deploy_token = %s", cfg.Agent.DeployToken),
		fmt.Sprintf("connect_addr = %s", cfg.Agent.ConnectAddr),
		fmt.Sprintf("egress_network = %s", cfg.Agent.EgressNetwork),
		"",
		"[nodepass]",
		"# ⚠ 以下两行由 Agent 自动填写，请勿手动修改",
		fmt.Sprintf("DEPLOY_DEFAULT_MASTER_ADDR = %s", cfg.NodePass.MasterAddr),
		fmt.Sprintf("DEPLOY_DEFAULT_MASTER_API_KEY = %s", cfg.NodePass.APIKey),
		fmt.Sprintf("master_port = %d", cfg.NodePass.MasterPort),
		fmt.Sprintf("start_timeout = %d", cfg.NodePass.StartTimeout),
		"",
		"[panel]",
		fmt.Sprintf("heartbeat_interval = %d", cfg.Panel.HeartbeatInterval),
		fmt.Sprintf("command_timeout = %d", cfg.Panel.CommandTimeout),
	}
}

func normalizePath(path string) string {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return defaultConfigPath
	}
	return cleanPath
}

func (c *Config) String() string {
	var b bytes.Buffer
	for i, line := range c.sourceLines {
		b.WriteString(line)
		if i < len(c.sourceLines)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}
