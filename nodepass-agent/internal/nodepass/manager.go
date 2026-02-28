package nodepass

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type TrafficData struct {
	RuleID    string    `json:"rule_id"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
	Timestamp time.Time `json:"timestamp"`
}

type Instance struct {
	RuleID       string
	Cmd          *exec.Cmd
	StdoutPipe   io.ReadCloser
	RestartCount int
	LastStart    time.Time

	nodepassURL    string
	target         string
	restartHistory []time.Time
	exitCh         chan struct{}
	stopRequested  bool
	mu             sync.Mutex
}

type HubClient interface {
	SendTrafficReport(records []TrafficData) error
}

type Manager struct {
	instances    sync.Map
	nodepassPath string
	trafficCh    chan TrafficData
	logger       *slog.Logger
	stopCh       chan struct{}
	reporterOnce sync.Once
}

func NewManager(nodepassPath string, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}

	return &Manager{
		nodepassPath: strings.TrimSpace(nodepassPath),
		trafficCh:    make(chan TrafficData, 4096),
		logger:       logger,
		stopCh:       make(chan struct{}),
	}
}

func (m *Manager) Start(ruleID, nodepassURL, target string) error {
	cleanRuleID := strings.TrimSpace(ruleID)
	cleanURL := strings.TrimSpace(nodepassURL)
	cleanTarget := strings.TrimSpace(target)
	if cleanRuleID == "" || cleanURL == "" || cleanTarget == "" {
		return errors.New("invalid start arguments")
	}
	if strings.TrimSpace(m.nodepassPath) == "" {
		return errors.New("nodepass path is empty")
	}

	if _, exists := m.loadInstance(cleanRuleID); exists {
		if err := m.Stop(cleanRuleID); err != nil {
			m.logger.Warn("stop existing instance before start failed", slog.String("rule_id", cleanRuleID), slog.Any("err", err))
		}
	}

	instance := &Instance{
		RuleID:      cleanRuleID,
		nodepassURL: cleanURL,
		target:      cleanTarget,
		exitCh:      make(chan struct{}),
	}

	if err := m.startProcess(instance); err != nil {
		return err
	}

	m.instances.Store(cleanRuleID, instance)
	return nil
}

func (m *Manager) Stop(ruleID string) error {
	instance, ok := m.loadInstance(strings.TrimSpace(ruleID))
	if !ok {
		return nil
	}

	instance.mu.Lock()
	instance.stopRequested = true
	cmd := instance.Cmd
	exitCh := instance.exitCh
	instance.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		m.instances.Delete(instance.RuleID)
		return nil
	}

	_ = cmd.Process.Signal(syscall.SIGTERM)

	select {
	case <-exitCh:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		select {
		case <-exitCh:
		case <-time.After(2 * time.Second):
		}
	}

	m.instances.Delete(instance.RuleID)
	return nil
}

func (m *Manager) Restart(ruleID string) error {
	instance, ok := m.loadInstance(strings.TrimSpace(ruleID))
	if !ok {
		return fmt.Errorf("instance not found: %s", ruleID)
	}

	instance.mu.Lock()
	nodepassURL := instance.nodepassURL
	target := instance.target
	instance.mu.Unlock()

	if err := m.Stop(instance.RuleID); err != nil {
		return err
	}
	return m.Start(instance.RuleID, nodepassURL, target)
}

func (m *Manager) Shutdown(ctx context.Context) {
	select {
	case <-m.stopCh:
	default:
		close(m.stopCh)
	}

	doneCh := make(chan struct{})
	go func() {
		m.instances.Range(func(key, _ any) bool {
			ruleID, _ := key.(string)
			_ = m.Stop(ruleID)
			return true
		})
		close(doneCh)
	}()

	select {
	case <-ctx.Done():
	case <-doneCh:
	}
}

func (m *Manager) StartTrafficReporter(hubClient HubClient) {
	if hubClient == nil {
		return
	}

	m.reporterOnce.Do(func() {
		go m.runTrafficReporter(hubClient)
	})
}

func (m *Manager) runTrafficReporter(hubClient HubClient) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	agg := make(map[string]TrafficData, 128)

	flush := func() {
		if len(agg) == 0 {
			return
		}

		records := make([]TrafficData, 0, len(agg))
		for _, item := range agg {
			records = append(records, item)
		}
		clear(agg)

		if err := hubClient.SendTrafficReport(records); err != nil {
			m.logger.Warn("send traffic report failed", slog.Any("err", err), slog.Int("records", len(records)))
		}
	}

	for {
		select {
		case <-m.stopCh:
			flush()
			return
		case item := <-m.trafficCh:
			existing, ok := agg[item.RuleID]
			if ok {
				existing.BytesIn += item.BytesIn
				existing.BytesOut += item.BytesOut
				existing.Timestamp = item.Timestamp
				agg[item.RuleID] = existing
				continue
			}
			agg[item.RuleID] = item
		case <-ticker.C:
			flush()
		}
	}
}

func (m *Manager) startProcess(instance *Instance) error {
	if instance == nil {
		return errors.New("instance is nil")
	}

	cmd := exec.Command(m.nodepassPath, instance.nodepassURL, instance.target)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	instance.mu.Lock()
	instance.Cmd = cmd
	instance.StdoutPipe = stdout
	instance.LastStart = time.Now().UTC()
	instance.exitCh = make(chan struct{})
	instance.stopRequested = false
	instance.mu.Unlock()

	go m.captureOutput(instance.RuleID, stdout)
	go m.captureOutput(instance.RuleID, stderr)
	go m.monitorProcess(instance)

	m.logger.Info("nodepass instance started", slog.String("rule_id", instance.RuleID), slog.Int("pid", cmd.Process.Pid))
	return nil
}

func (m *Manager) monitorProcess(instance *Instance) {
	instance.mu.Lock()
	cmd := instance.Cmd
	exitCh := instance.exitCh
	instance.mu.Unlock()

	if cmd == nil {
		close(exitCh)
		return
	}

	err := cmd.Wait()
	close(exitCh)

	instance.mu.Lock()
	stopped := instance.stopRequested
	instance.mu.Unlock()

	if stopped {
		return
	}

	if err == nil {
		return
	}

	if !m.allowRestart(instance) {
		m.logger.Warn("nodepass exited and reached restart limit", slog.String("rule_id", instance.RuleID), slog.Any("err", err))
		return
	}

	time.Sleep(1 * time.Second)
	if restartErr := m.startProcess(instance); restartErr != nil {
		m.logger.Error("nodepass restart failed", slog.String("rule_id", instance.RuleID), slog.Any("err", restartErr))
	}
}

func (m *Manager) allowRestart(instance *Instance) bool {
	if instance == nil {
		return false
	}

	now := time.Now().UTC()
	windowStart := now.Add(-1 * time.Minute)

	instance.mu.Lock()
	defer instance.mu.Unlock()

	filtered := instance.restartHistory[:0]
	for _, item := range instance.restartHistory {
		if item.After(windowStart) {
			filtered = append(filtered, item)
		}
	}
	instance.restartHistory = filtered
	if len(instance.restartHistory) >= 3 {
		instance.RestartCount = len(instance.restartHistory)
		return false
	}

	instance.restartHistory = append(instance.restartHistory, now)
	instance.RestartCount = len(instance.restartHistory)
	return true
}

func (m *Manager) captureOutput(ruleID string, reader io.ReadCloser) {
	if reader == nil {
		return
	}
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if data, ok := parseTrafficLine(ruleID, line); ok {
			select {
			case m.trafficCh <- data:
			default:
				m.logger.Warn("traffic channel full, dropping traffic sample", slog.String("rule_id", ruleID))
			}
		}
	}

	if err := scanner.Err(); err != nil {
		m.logger.Warn("read nodepass output failed", slog.String("rule_id", ruleID), slog.Any("err", err))
	}
}

func parseTrafficLine(ruleID, line string) (TrafficData, bool) {
	if !strings.Contains(line, "[TRAFFIC]") {
		return TrafficData{}, false
	}

	segment := line[strings.Index(line, "[TRAFFIC]")+len("[TRAFFIC]"):]
	segment = strings.TrimSpace(segment)
	if segment == "" {
		return TrafficData{}, false
	}

	bytesIn, inOK := parseKeyInt64(segment, "in", "bytes_in", "input")
	bytesOut, outOK := parseKeyInt64(segment, "out", "bytes_out", "output")
	if !inOK && !outOK {
		return TrafficData{}, false
	}

	ts := time.Now().UTC()
	if tsValue, ok := parseKeyString(segment, "ts", "timestamp", "time"); ok {
		if parsed, err := time.Parse(time.RFC3339, tsValue); err == nil {
			ts = parsed.UTC()
		}
	}

	return TrafficData{
		RuleID:    ruleID,
		BytesIn:   bytesIn,
		BytesOut:  bytesOut,
		Timestamp: ts,
	}, true
}

func parseKeyInt64(segment string, keys ...string) (int64, bool) {
	for _, key := range keys {
		value, ok := parseKeyString(segment, key)
		if !ok {
			continue
		}
		number, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			continue
		}
		return number, true
	}
	return 0, false
}

func parseKeyString(segment string, keys ...string) (string, bool) {
	parts := strings.Fields(segment)
	for _, part := range parts {
		if !strings.Contains(part, "=") {
			continue
		}
		chunks := strings.SplitN(part, "=", 2)
		if len(chunks) != 2 {
			continue
		}
		left := strings.ToLower(strings.TrimSpace(chunks[0]))
		right := strings.Trim(strings.TrimSpace(chunks[1]), "\"'")
		for _, key := range keys {
			if left == strings.ToLower(strings.TrimSpace(key)) {
				return right, true
			}
		}
	}
	return "", false
}

func (m *Manager) loadInstance(ruleID string) (*Instance, bool) {
	value, ok := m.instances.Load(ruleID)
	if !ok {
		return nil, false
	}
	instance, ok := value.(*Instance)
	if !ok || instance == nil {
		return nil, false
	}
	return instance, true
}
