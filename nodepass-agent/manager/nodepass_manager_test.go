package manager

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParseCredentialsSuccess(t *testing.T) {
	input := strings.NewReader(strings.Join([]string{
		"2025/01/15 10:23:01 [INFO] NodePass master starting...",
		"2025/01/15 10:23:01 [INFO] API endpoint: http://127.0.0.1:9090",
		"2025/01/15 10:23:01 [INFO] API Key: npk_test_key",
	}, "\n"))

	credCh := make(chan Credentials, 1)
	err := ParseCredentials(input, credCh, time.Second)
	if err != nil {
		t.Fatalf("ParseCredentials returned error: %v", err)
	}

	select {
	case creds := <-credCh:
		if creds.MasterAddr != "http://127.0.0.1:9090" {
			t.Fatalf("unexpected MasterAddr: %q", creds.MasterAddr)
		}
		if creds.APIKey != "npk_test_key" {
			t.Fatalf("unexpected APIKey: %q", creds.APIKey)
		}
	default:
		t.Fatalf("expected credentials on channel")
	}
}

func TestParseCredentialsTimeout(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()

	credCh := make(chan Credentials, 1)
	err := ParseCredentials(reader, credCh, 150*time.Millisecond)
	if !errors.Is(err, ErrStartTimeout) {
		t.Fatalf("expected ErrStartTimeout, got %v", err)
	}
}

func TestStartTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script test is unix-only")
	}

	scriptPath := writeExecutableScript(t, `#!/bin/sh
set -eu
echo "NodePass master starting..."
sleep 5
`)

	m := &NodePassManager{
		BinPath:      scriptPath,
		MasterPort:   19090,
		StartTimeout: 200 * time.Millisecond,
		LogLevel:     "info",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := m.Start(ctx)
	if !errors.Is(err, ErrStartTimeout) {
		t.Fatalf("expected ErrStartTimeout, got %v", err)
	}
}

func TestWatchdogRestartTriggersOnRenew(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script test is unix-only")
	}

	counterFile := filepath.Join(t.TempDir(), "counter.txt")
	scriptPath := writeExecutableScript(t, `#!/bin/sh
set -eu
counter_file="${NODEPASS_TEST_COUNTER_FILE}"
count=0
if [ -f "${counter_file}" ]; then
  count=$(cat "${counter_file}")
fi
count=$((count+1))
printf '%s' "${count}" > "${counter_file}"
echo "API endpoint: http://127.0.0.1:9090"
echo "API Key: npk_watchdog_${count}"
sleep 0.1
exit 1
`)
	if err := os.Setenv("NODEPASS_TEST_COUNTER_FILE", counterFile); err != nil {
		t.Fatalf("Setenv failed: %v", err)
	}
	defer os.Unsetenv("NODEPASS_TEST_COUNTER_FILE")

	renewCh := make(chan Credentials, 2)
	m := &NodePassManager{
		BinPath:      scriptPath,
		MasterPort:   19090,
		StartTimeout: 2 * time.Second,
		LogLevel:     "info",
		OnRenew: func(creds Credentials) {
			renewCh <- creds
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer m.Stop()

	firstCreds, err := m.Start(ctx)
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	if firstCreds.APIKey == "" {
		t.Fatalf("expected initial api key")
	}

	select {
	case renewed := <-renewCh:
		if renewed.APIKey == "" {
			t.Fatalf("expected renewed api key")
		}
		if renewed.APIKey == firstCreds.APIKey {
			t.Fatalf("expected renewed api key to change, first=%q renewed=%q", firstCreds.APIKey, renewed.APIKey)
		}
	case <-time.After(9 * time.Second):
		t.Fatalf("timeout waiting for watchdog renewal")
	}
}

func writeExecutableScript(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "nodepass-mock.sh")
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatalf("Chmod failed: %v", err)
	}
	return path
}
