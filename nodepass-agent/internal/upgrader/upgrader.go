package upgrader

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"nodepass-agent/internal/ws"
)

type UpgradePayload struct {
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	Checksum    string `json:"checksum"`
	Signature   string `json:"signature,omitempty"`
}

type Upgrader struct {
	workDir string

	currentVersionFn func() string
	executableFn     func() (string, error)
	execFn           func(path string, args []string, env []string) error
	httpClient       *http.Client
	preExec          func()

	mu      sync.Mutex
	pending *pendingUpgrade
}

type pendingUpgrade struct {
	execPath   string
	backupPath string
}

var ErrNoPendingUpgrade = errors.New("upgrader: no pending upgrade")

var errUpgradePending = errors.New("upgrader: pending upgrade exists")

func (u *Upgrader) HasPending() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.pending != nil
}

func New(workDir string, currentVersionFn func() string) *Upgrader {
	if strings.TrimSpace(workDir) == "" {
		workDir = "/var/lib/nodepass-agent"
	}
	if currentVersionFn == nil {
		currentVersionFn = func() string { return "dev" }
	}
	return &Upgrader{
		workDir:          workDir,
		currentVersionFn: currentVersionFn,
		executableFn:     os.Executable,
		execFn:           syscall.Exec,
		httpClient:       &http.Client{},
	}
}

func (u *Upgrader) HandleUpgrade(ctx context.Context, msg ws.HubMessage) error {
	var payload UpgradePayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return err
	}

	if payload.Version == "" {
		return fmt.Errorf("upgrade version is required")
	}
	if payload.DownloadURL == "" {
		return fmt.Errorf("download_url is required")
	}

	if payload.Version == u.currentVersionFn() {
		return nil
	}
	if u.HasPending() {
		return errUpgradePending
	}

	newBinaryPath := filepath.Join(u.workDir, "agent.new")
	if err := os.MkdirAll(u.workDir, 0o755); err != nil {
		return err
	}

	if err := u.downloadBinary(ctx, payload.DownloadURL, payload.Checksum, newBinaryPath); err != nil {
		return err
	}
	if err := os.Chmod(newBinaryPath, 0o755); err != nil {
		_ = os.Remove(newBinaryPath)
		return err
	}

	execPath, err := u.executableFn()
	if err != nil {
		_ = os.Remove(newBinaryPath)
		return err
	}

	backupPath := execPath + ".bak"
	_ = os.Remove(backupPath)
	if err := os.Rename(execPath, backupPath); err != nil {
		_ = os.Remove(newBinaryPath)
		return err
	}
	rollback := true
	defer func() {
		if rollback {
			_ = os.Rename(backupPath, execPath)
		}
	}()

	if err := os.Rename(newBinaryPath, execPath); err != nil {
		return err
	}

	u.mu.Lock()
	u.pending = &pendingUpgrade{
		execPath:   execPath,
		backupPath: backupPath,
	}
	u.mu.Unlock()

	rollback = false
	return nil
}

func (u *Upgrader) ExecPending() error {
	u.mu.Lock()
	pending := u.pending
	if pending == nil {
		u.mu.Unlock()
		return ErrNoPendingUpgrade
	}
	u.mu.Unlock()

	if u.preExec != nil {
		u.preExec()
	}

	if err := u.execFn(pending.execPath, os.Args, os.Environ()); err != nil {
		_ = os.Rename(pending.backupPath, pending.execPath)
		u.mu.Lock()
		u.pending = nil
		u.mu.Unlock()
		return err
	}

	u.mu.Lock()
	u.pending = nil
	u.mu.Unlock()
	_ = os.Remove(pending.backupPath)
	return nil
}

func (u *Upgrader) downloadBinary(ctx context.Context, downloadURL, expectedChecksum, dstPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return err
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	tmp := dstPath + ".tmp"
	file, err := os.Create(tmp)
	if err != nil {
		return err
	}

	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(file, hasher), resp.Body); err != nil {
		file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	sum := hex.EncodeToString(hasher.Sum(nil))
	if expected := strings.TrimSpace(strings.ToLower(expectedChecksum)); expected != "" && sum != expected {
		_ = os.Remove(tmp)
		return fmt.Errorf("checksum mismatch")
	}

	if err := os.Rename(tmp, dstPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
