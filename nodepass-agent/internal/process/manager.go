package process

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	ErrCredentialsTimeout = errors.New("process: credentials timeout")
	ErrProcessExited      = errors.New("process: nodepass exited")
)

type Credentials struct {
	MasterAddr string
	APIKey     string
}

type ProcessManager struct {
	binPath string
	workDir string

	cmd    *exec.Cmd
	mu     sync.Mutex
	exitCh chan struct{}
	credCh chan Credentials

	parser CredentialParser
}

func NewProcessManager(binPath, workDir string) *ProcessManager {
	return &ProcessManager{
		binPath: strings.TrimSpace(binPath),
		workDir: strings.TrimSpace(workDir),
		exitCh:  make(chan struct{}),
		credCh:  make(chan Credentials, 1),
		parser:  NewDefaultCredentialParser(),
	}
}

func (m *ProcessManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd != nil && m.isRunningLocked() {
		return nil
	}

	cmd := exec.Command(
		m.binPath,
		"master",
		"--log-level", "debug",
		"--work-dir", m.workDir,
	)
	applyParentDeathSignal(cmd)

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

	m.cmd = cmd
	m.exitCh = make(chan struct{})
	m.credCh = make(chan Credentials, 1)

	reader, writer := io.Pipe()
	var copyWG sync.WaitGroup
	copyWG.Add(2)
	go func() {
		defer copyWG.Done()
		_, _ = io.Copy(writer, stdout)
	}()
	go func() {
		defer copyWG.Done()
		_, _ = io.Copy(writer, stderr)
	}()
	go func() {
		copyWG.Wait()
		_ = writer.Close()
	}()
	go m.parseCredentials(reader)

	go func(localCmd *exec.Cmd, localExit chan struct{}) {
		_ = localCmd.Wait()
		close(localExit)
	}(cmd, m.exitCh)

	return nil
}

func (m *ProcessManager) parseCredentials(r io.Reader) {
	scanner := bufio.NewScanner(r)
	addr := ""
	key := ""
	sent := false

	for scanner.Scan() {
		line := scanner.Text()
		if m.parser == nil {
			continue
		}
		parsedAddr, parsedKey, found := m.parser.Parse(line)
		if !found {
			continue
		}
		if parsedAddr != "" {
			addr = parsedAddr
		}
		if parsedKey != "" {
			key = parsedKey
		}
		if !sent && addr != "" && key != "" {
			select {
			case m.credCh <- Credentials{MasterAddr: addr, APIKey: key}:
				sent = true
			default:
				sent = true
			}
		}
	}
}

func (m *ProcessManager) WaitForCredentials(timeout time.Duration) (Credentials, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	m.mu.Lock()
	credCh := m.credCh
	exitCh := m.exitCh
	m.mu.Unlock()

	if credCh == nil {
		return Credentials{}, ErrCredentialsTimeout
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case creds := <-credCh:
		return creds, nil
	case <-exitCh:
		return Credentials{}, ErrProcessExited
	case <-timer.C:
		return Credentials{}, ErrCredentialsTimeout
	}
}

func (m *ProcessManager) Stop() error {
	m.mu.Lock()
	cmd := m.cmd
	exitCh := m.exitCh
	m.cmd = nil
	m.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		_ = cmd.Process.Kill()
		return err
	}

	select {
	case <-exitCh:
		return nil
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		select {
		case <-exitCh:
		case <-time.After(2 * time.Second):
		}
		return fmt.Errorf("process stop timeout")
	}
}

func (m *ProcessManager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.isRunningLocked()
}

func (m *ProcessManager) isRunningLocked() bool {
	if m.cmd == nil || m.cmd.Process == nil {
		return false
	}
	select {
	case <-m.exitCh:
		return false
	default:
		return true
	}
}

func (m *ProcessManager) ExitCh() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.exitCh == nil {
		m.exitCh = make(chan struct{})
	}
	return m.exitCh
}

func (m *ProcessManager) SetParser(parser CredentialParser) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.parser = parser
}
