package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type AgentConf struct {
	MasterAddr string `json:"master_addr"`
	APIKey     string `json:"api_key"`
	UpdatedAt  int64  `json:"updated_at"`
}

func Load(workDir string) (*AgentConf, error) {
	path := confPath(workDir)
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &AgentConf{}, nil
		}
		return nil, err
	}

	content = bytes.TrimSpace(content)
	if len(content) == 0 {
		return &AgentConf{}, nil
	}

	if looksLikeLegacyConf(content) {
		return loadLegacy(content), nil
	}

	var conf AgentConf
	if err := json.Unmarshal(content, &conf); err != nil {
		return nil, fmt.Errorf("decode agent.conf: %w", err)
	}
	return &conf, nil
}

func Save(workDir string, conf *AgentConf) error {
	if conf == nil {
		return fmt.Errorf("agent.conf is nil")
	}
	path := confPath(workDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	conf.UpdatedAt = time.Now().Unix()

	existing, readErr := os.ReadFile(path)
	if readErr == nil && looksLikeLegacyConf(bytes.TrimSpace(existing)) {
		return saveLegacy(path, conf, string(existing))
	}
	if readErr != nil && !os.IsNotExist(readErr) {
		return readErr
	}

	payload, err := json.MarshalIndent(conf, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func Validate(workDir, masterAddr, apiKey string) (bool, error) {
	_ = workDir
	cleanAddr := normalizeMasterAddr(masterAddr)
	cleanKey := strings.TrimSpace(apiKey)
	if cleanAddr == "" || cleanKey == "" {
		return false, nil
	}

	url := strings.TrimRight(cleanAddr, "/") + "/api/v1/info"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+cleanKey)
	req.Header.Set("X-API-Key", cleanKey)

	cli := &http.Client{Timeout: 5 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	return false, nil
}

func confPath(workDir string) string {
	base := strings.TrimSpace(workDir)
	if base == "" {
		base = "/var/lib/nodepass-agent"
	}
	return filepath.Join(base, "agent.conf")
}

func normalizeMasterAddr(raw string) string {
	clean := strings.TrimSpace(raw)
	if clean == "" {
		return ""
	}
	if strings.HasPrefix(clean, "http://") || strings.HasPrefix(clean, "https://") {
		return clean
	}
	return "http://" + clean
}

var legacyKeyValueRE = regexp.MustCompile(`^(\s*)([A-Za-z0-9_.-]+)(\s*=\s*)(.*)$`)

func looksLikeLegacyConf(content []byte) bool {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 {
		return false
	}
	if trimmed[0] == '{' {
		return false
	}
	text := string(trimmed)
	return strings.Contains(text, "[agent]") ||
		strings.Contains(text, "[nodepass]") ||
		strings.Contains(text, "DEPLOY_DEFAULT_MASTER_ADDR") ||
		strings.Contains(text, "DEPLOY_DEFAULT_MASTER_API_KEY")
}

func loadLegacy(content []byte) *AgentConf {
	conf := &AgentConf{}
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		matches := legacyKeyValueRE.FindStringSubmatch(line)
		if len(matches) != 5 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(matches[2]))
		value := strings.TrimSpace(matches[4])
		value = trimQuotes(value)

		switch key {
		case "deploy_default_master_addr":
			conf.MasterAddr = value
		case "deploy_default_master_api_key":
			conf.APIKey = value
		}
	}
	return conf
}

func trimQuotes(value string) string {
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

func saveLegacy(path string, conf *AgentConf, existing string) error {
	lines := strings.Split(strings.ReplaceAll(existing, "\r\n", "\n"), "\n")
	lines = upsertLegacyKey(lines, "DEPLOY_DEFAULT_MASTER_ADDR", strings.TrimSpace(conf.MasterAddr))
	lines = upsertLegacyKey(lines, "DEPLOY_DEFAULT_MASTER_API_KEY", strings.TrimSpace(conf.APIKey))
	return atomicWrite(path, strings.Join(lines, "\n"))
}

func upsertLegacyKey(lines []string, key, value string) []string {
	found := false
	for idx, line := range lines {
		matches := legacyKeyValueRE.FindStringSubmatch(line)
		if len(matches) != 5 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(matches[2]), key) {
			lines[idx] = fmt.Sprintf("%s%s%s%s", matches[1], key, matches[3], value)
			found = true
			break
		}
	}
	if found {
		return lines
	}

	insertAt := len(lines)
	nodepassHeader := -1
	for idx, line := range lines {
		trimmed := strings.ToLower(strings.TrimSpace(line))
		if trimmed == "[nodepass]" {
			nodepassHeader = idx
			insertAt = idx + 1
			break
		}
	}

	if nodepassHeader == -1 {
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
			lines = append(lines, "")
		}
		lines = append(lines, "[nodepass]")
		insertAt = len(lines)
	}

	line := fmt.Sprintf("%s=%s", key, value)
	if insertAt >= len(lines) {
		return append(lines, line)
	}

	out := make([]string, 0, len(lines)+1)
	out = append(out, lines[:insertAt]...)
	out = append(out, line)
	out = append(out, lines[insertAt:]...)
	return out
}

func atomicWrite(path, content string) error {
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
