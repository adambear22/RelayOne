package manager

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	reMasterAddr = regexp.MustCompile(`API endpoint:\s+(https?://\S+)`)
	reAPIKey     = regexp.MustCompile(`API Key:\s+(\S+)`)
)

var (
	ErrStartTimeout  = errors.New("nodepass start timeout")
	ErrProcessExited = errors.New("nodepass process exited before credentials ready")
)

const (
	defaultMasterPort   = 9090
	defaultStartTimeout = 30 * time.Second
	defaultLogLevel     = "info"
	maxRestartAttempts  = 5
)

type Credentials struct {
	MasterAddr string
	APIKey     string
}

type NodePassManager struct {
	BinPath      string
	MasterPort   int
	StartTimeout time.Duration
	LogLevel     string
	OnRenew      func(Credentials)

	mu            sync.RWMutex
	cmd           *exec.Cmd
	creds         Credentials
	waitCh        chan error
	runCtx        context.Context
	runCancel     context.CancelFunc
	stopRequested bool
}

func New(binPath string, masterPort int) *NodePassManager {
	return &NodePassManager{
		BinPath:    strings.TrimSpace(binPath),
		MasterPort: masterPort,
	}
}

func (m *NodePassManager) Start(ctx context.Context) (Credentials, error) {
	return m.start(ctx, true)
}

func (m *NodePassManager) StartManaged(ctx context.Context) error {
	_, err := m.start(ctx, false)
	return err
}

func (m *NodePassManager) start(ctx context.Context, waitForCreds bool) (Credentials, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	m.applyDefaults()

	m.mu.Lock()
	if m.runCancel != nil {
		if m.isProcessRunningLocked() {
			creds := m.creds
			m.mu.Unlock()
			if creds.MasterAddr != "" && creds.APIKey != "" {
				return creds, nil
			}
			return Credentials{}, errors.New("nodepass process is running but credentials are not ready yet")
		}
		m.mu.Unlock()
		return Credentials{}, errors.New("nodepass manager is already started")
	}

	runCtx, runCancel := context.WithCancel(ctx)
	m.runCtx = runCtx
	m.runCancel = runCancel
	m.stopRequested = false
	m.mu.Unlock()

	creds, waitCh, err := m.launchProcess(runCtx, waitForCreds)
	if err != nil {
		m.mu.Lock()
		m.clearRunStateLocked()
		m.mu.Unlock()
		runCancel()
		return Credentials{}, err
	}

	m.mu.Lock()
	m.waitCh = waitCh
	m.mu.Unlock()

	go m.startWatchdog(runCtx)
	return creds, nil
}

func (m *NodePassManager) Stop() error {
	m.mu.Lock()
	m.stopRequested = true
	cancel := m.runCancel
	cmd := m.cmd
	waitCh := m.waitCh
	m.clearRunStateLocked()
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	return terminateProcess(cmd, waitCh, 3*time.Second)
}

func (m *NodePassManager) Credentials() Credentials {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.creds
}

func (m *NodePassManager) SetCredentials(creds Credentials) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.creds = creds
}

func (m *NodePassManager) startWatchdog(ctx context.Context) {
	restartFailures := 0

	for {
		if ctx.Err() != nil || m.isStopping() {
			return
		}

		waitCh := m.currentWaitCh()
		if waitCh == nil {
			return
		}

		var waitErr error
		select {
		case <-ctx.Done():
			return
		case waitErr = <-waitCh:
		}

		if ctx.Err() != nil || m.isStopping() {
			return
		}

		restartFailures++
		if restartFailures > maxRestartAttempts {
			log.Printf("[watchdog] max restart attempts reached, giving up")
			return
		}

		delay := restartDelay(waitErr, restartFailures)
		log.Printf(
			"[watchdog] nodepass exited (code=%d), restarting in %s (attempt %d/%d)",
			exitCode(waitErr),
			delay,
			restartFailures,
			maxRestartAttempts,
		)

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}

		creds, newWaitCh, err := m.launchProcess(ctx, true)
		if err != nil {
			log.Printf("[watchdog] nodepass restart failed: %v", err)
			continue
		}

		restartFailures = 0
		m.mu.Lock()
		m.waitCh = newWaitCh
		m.mu.Unlock()

		if m.OnRenew != nil {
			m.OnRenew(creds)
		}
		log.Printf("[watchdog] nodepass restarted successfully, new creds obtained")
	}
}

func (m *NodePassManager) launchProcess(ctx context.Context, waitForCreds bool) (Credentials, chan error, error) {
	masterURL := fmt.Sprintf("master://0.0.0.0:%d?log=%s", m.MasterPort, m.LogLevel)
	cmd := exec.CommandContext(ctx, m.BinPath, masterURL)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Credentials{}, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return Credentials{}, nil, err
	}

	if err := cmd.Start(); err != nil {
		return Credentials{}, nil, err
	}

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
		close(waitCh)
	}()

	m.mu.Lock()
	m.cmd = cmd
	m.mu.Unlock()

	pr, pw := io.Pipe()
	var streamWG sync.WaitGroup
	streamWG.Add(2)
	go m.streamOutput(stdout, pw, &streamWG)
	go m.streamOutput(stderr, pw, &streamWG)
	go func() {
		streamWG.Wait()
		_ = pw.Close()
	}()

	if !waitForCreds {
		return m.Credentials(), waitCh, nil
	}

	credCh := make(chan Credentials, 1)
	parseErrCh := make(chan error, 1)
	go func() {
		parseErrCh <- ParseCredentials(pr, credCh, m.StartTimeout)
	}()

	for {
		select {
		case creds := <-credCh:
			m.mu.Lock()
			m.creds = creds
			m.mu.Unlock()
			return creds, waitCh, nil
		case parseErr := <-parseErrCh:
			if parseErr == nil {
				continue
			}
			_ = terminateProcess(cmd, waitCh, 3*time.Second)
			return Credentials{}, nil, parseErr
		case waitErr := <-waitCh:
			select {
			case creds := <-credCh:
				m.mu.Lock()
				m.creds = creds
				m.mu.Unlock()
				return creds, waitCh, nil
			default:
			}

			if waitErr == nil {
				return Credentials{}, nil, ErrProcessExited
			}
			return Credentials{}, nil, fmt.Errorf("%w: %v", ErrProcessExited, waitErr)
		case <-ctx.Done():
			_ = terminateProcess(cmd, waitCh, 3*time.Second)
			return Credentials{}, nil, ctx.Err()
		}
	}
}

func (m *NodePassManager) streamOutput(reader io.ReadCloser, writer io.Writer, wg *sync.WaitGroup) {
	defer wg.Done()
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		log.Printf("[nodepass] %s", line)
		_, _ = io.WriteString(writer, line+"\n")
	}
}

func ParseCredentials(reader io.Reader, credCh chan<- Credentials, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = defaultStartTimeout
	}

	lineCh := make(chan string, 32)
	scanErrCh := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			lineCh <- scanner.Text()
		}
		close(lineCh)
		scanErrCh <- scanner.Err()
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	creds := Credentials{}
	for {
		if creds.MasterAddr != "" && creds.APIKey != "" {
			if credCh != nil {
				select {
				case credCh <- creds:
				default:
				}
			}
			return nil
		}

		select {
		case <-timer.C:
			return ErrStartTimeout
		case line, ok := <-lineCh:
			if !ok {
				err := <-scanErrCh
				if err != nil {
					return err
				}
				return ErrProcessExited
			}

			if creds.MasterAddr == "" {
				if matches := reMasterAddr.FindStringSubmatch(line); len(matches) == 2 {
					creds.MasterAddr = strings.TrimSpace(matches[1])
				}
			}
			if creds.APIKey == "" {
				if matches := reAPIKey.FindStringSubmatch(line); len(matches) == 2 {
					creds.APIKey = strings.TrimSpace(matches[1])
				}
			}
		}
	}
}

func (m *NodePassManager) applyDefaults() {
	if m.MasterPort <= 0 {
		m.MasterPort = defaultMasterPort
	}
	if m.StartTimeout <= 0 {
		m.StartTimeout = defaultStartTimeout
	}
	m.LogLevel = strings.TrimSpace(m.LogLevel)
	if m.LogLevel == "" {
		m.LogLevel = defaultLogLevel
	}
}

func (m *NodePassManager) clearRunStateLocked() {
	m.cmd = nil
	m.waitCh = nil
	m.runCtx = nil
	m.runCancel = nil
}

func (m *NodePassManager) currentWaitCh() chan error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.waitCh
}

func (m *NodePassManager) isStopping() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stopRequested
}

func (m *NodePassManager) isProcessRunningLocked() bool {
	if m.cmd == nil || m.cmd.Process == nil {
		return false
	}
	if m.cmd.ProcessState == nil {
		return true
	}
	return !m.cmd.ProcessState.Exited()
}

func terminateProcess(cmd *exec.Cmd, waitCh <-chan error, timeout time.Duration) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	_ = cmd.Process.Signal(syscall.SIGTERM)
	if waitCh != nil {
		select {
		case <-waitCh:
			return nil
		case <-time.After(timeout):
		}
	}

	_ = cmd.Process.Kill()
	if waitCh != nil {
		select {
		case <-waitCh:
		case <-time.After(timeout):
		}
	}
	return nil
}

func restartDelay(waitErr error, attempt int) time.Duration {
	if waitErr == nil {
		return 3 * time.Second
	}

	delay := 5 * time.Second
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay >= 30*time.Second {
			return 30 * time.Second
		}
	}
	if delay > 30*time.Second {
		return 30 * time.Second
	}
	return delay
}

func exitCode(waitErr error) int {
	if waitErr == nil {
		return 0
	}

	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return exitErr.ExitCode()
	}

	if strings.Contains(waitErr.Error(), "killed") {
		return int(syscall.SIGKILL)
	}
	if strings.Contains(waitErr.Error(), "terminated") {
		return int(syscall.SIGTERM)
	}

	parts := strings.Fields(waitErr.Error())
	if len(parts) > 0 {
		if parsed, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
			return parsed
		}
	}

	return -1
}
