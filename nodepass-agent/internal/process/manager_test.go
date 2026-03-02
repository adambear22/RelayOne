package process

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestDefaultParserExtractsCredentials(t *testing.T) {
	parser := NewDefaultCredentialParser()
	addr, key, found := parser.Parse("MASTER_ADDR=127.0.0.1:19090")
	if !found || addr == "" || key != "" {
		t.Fatalf("expected address, got addr=%q key=%q found=%v", addr, key, found)
	}
	if addr != "http://127.0.0.1:19090" {
		t.Fatalf("unexpected addr: %q", addr)
	}

	addr, key, found = parser.Parse("API_KEY=test-key")
	if !found || key != "test-key" || addr != "" {
		t.Fatalf("expected api key, got addr=%q key=%q found=%v", addr, key, found)
	}
}

func TestProcessManagerStartAndWaitForCredentials(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script helper is unix-only")
	}

	workDir := t.TempDir()
	binPath := filepath.Join(workDir, "nodepass")
	script := "#!/bin/sh\n" +
		"echo 'MASTER_ADDR=127.0.0.1:19090'\n" +
		"echo 'API_KEY=test-key-123'\n" +
		"while true; do sleep 1; done\n"
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	mgr := NewProcessManager(binPath, workDir)
	if err := mgr.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	creds, err := mgr.WaitForCredentials(3 * time.Second)
	if err != nil {
		t.Fatalf("wait creds: %v", err)
	}
	if creds.MasterAddr != "http://127.0.0.1:19090" {
		t.Fatalf("unexpected master addr: %q", creds.MasterAddr)
	}
	if creds.APIKey != "test-key-123" {
		t.Fatalf("unexpected api key: %q", creds.APIKey)
	}

	if !mgr.IsRunning() {
		t.Fatalf("expected process running")
	}

	_ = mgr.Stop()
}
