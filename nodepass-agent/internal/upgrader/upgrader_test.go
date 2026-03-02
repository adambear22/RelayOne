package upgrader

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"nodepass-agent/internal/ws"
)

func TestUpgradeChecksumMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("new-binary"))
	}))
	defer srv.Close()

	u := New(t.TempDir(), func() string { return "v1.0.0" })
	msgPayload, _ := json.Marshal(UpgradePayload{
		Version:     "v1.1.0",
		DownloadURL: srv.URL,
		Checksum:    "deadbeef",
	})

	err := u.HandleUpgrade(context.Background(), ws.HubMessage{Type: "upgrade", Payload: msgPayload})
	if err == nil {
		t.Fatalf("expected checksum mismatch error")
	}
}

func TestHandleUpgradeStagesPendingWithoutExec(t *testing.T) {
	newBinary := []byte("new-binary")
	sum := sha256.Sum256(newBinary)
	checksum := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(newBinary)
	}))
	defer srv.Close()

	workDir := t.TempDir()
	execPath := filepath.Join(workDir, "agent")
	if err := os.WriteFile(execPath, []byte("old-binary"), 0o755); err != nil {
		t.Fatalf("write old binary: %v", err)
	}

	u := New(workDir, func() string { return "v1.0.0" })
	u.executableFn = func() (string, error) { return execPath, nil }

	msgPayload, _ := json.Marshal(UpgradePayload{
		Version:     "v1.1.0",
		DownloadURL: srv.URL,
		Checksum:    checksum,
	})

	if err := u.HandleUpgrade(context.Background(), ws.HubMessage{Type: "upgrade", Payload: msgPayload}); err != nil {
		t.Fatalf("handle upgrade: %v", err)
	}

	if !u.HasPending() {
		t.Fatalf("expected pending upgrade")
	}

	content, readErr := os.ReadFile(execPath)
	if readErr != nil {
		t.Fatalf("read exec path: %v", readErr)
	}
	if string(content) != "new-binary" {
		t.Fatalf("expected staged new binary, got %q", string(content))
	}
}

func TestUpgradeRollbackWhenExecFails(t *testing.T) {
	newBinary := []byte("new-binary")
	sum := sha256.Sum256(newBinary)
	checksum := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(newBinary)
	}))
	defer srv.Close()

	workDir := t.TempDir()
	execPath := filepath.Join(workDir, "agent")
	if err := os.WriteFile(execPath, []byte("old-binary"), 0o755); err != nil {
		t.Fatalf("write old binary: %v", err)
	}

	u := New(workDir, func() string { return "v1.0.0" })
	u.executableFn = func() (string, error) { return execPath, nil }
	u.execFn = func(path string, args []string, env []string) error {
		_ = path
		_ = args
		_ = env
		return os.ErrInvalid
	}

	msgPayload, _ := json.Marshal(UpgradePayload{
		Version:     "v1.1.0",
		DownloadURL: srv.URL,
		Checksum:    checksum,
	})

	if err := u.HandleUpgrade(context.Background(), ws.HubMessage{Type: "upgrade", Payload: msgPayload}); err != nil {
		t.Fatalf("handle upgrade: %v", err)
	}
	if err := u.ExecPending(); err == nil {
		t.Fatalf("expected exec failure")
	}

	content, readErr := os.ReadFile(execPath)
	if readErr != nil {
		t.Fatalf("read exec path: %v", readErr)
	}
	if string(content) != "old-binary" {
		t.Fatalf("expected rollback to old binary, got %q", string(content))
	}
	if u.HasPending() {
		t.Fatalf("expected pending cleared after failed exec")
	}
}

func TestExecPendingNoopWhenNone(t *testing.T) {
	u := New(t.TempDir(), func() string { return "v1.0.0" })
	err := u.ExecPending()
	if !errors.Is(err, ErrNoPendingUpgrade) {
		t.Fatalf("expected ErrNoPendingUpgrade, got %v", err)
	}
}

func TestRejectNewUpgradeWhenPendingExists(t *testing.T) {
	newBinary := []byte("new-binary")
	sum := sha256.Sum256(newBinary)
	checksum := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(newBinary)
	}))
	defer srv.Close()

	workDir := t.TempDir()
	execPath := filepath.Join(workDir, "agent")
	if err := os.WriteFile(execPath, []byte("old-binary"), 0o755); err != nil {
		t.Fatalf("write old binary: %v", err)
	}

	u := New(workDir, func() string { return "v1.0.0" })
	u.executableFn = func() (string, error) { return execPath, nil }

	msgPayload, _ := json.Marshal(UpgradePayload{
		Version:     "v1.1.0",
		DownloadURL: srv.URL,
		Checksum:    checksum,
	})

	if err := u.HandleUpgrade(context.Background(), ws.HubMessage{Type: "upgrade", Payload: msgPayload}); err != nil {
		t.Fatalf("first handle upgrade: %v", err)
	}

	err := u.HandleUpgrade(context.Background(), ws.HubMessage{Type: "upgrade", Payload: msgPayload})
	if err == nil {
		t.Fatalf("expected pending upgrade error")
	}
}
