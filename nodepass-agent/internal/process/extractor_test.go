package process

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestExtract_SkipsWhenVersionMatches(t *testing.T) {
	origBinaryProvider := binaryProvider
	origVersionProvider := versionProvider
	origVerify := verifyCommand
	t.Cleanup(func() {
		binaryProvider = origBinaryProvider
		versionProvider = origVersionProvider
		verifyCommand = origVerify
	})

	binaryProvider = func() []byte { return []byte("new-binary") }
	versionProvider = func() string { return "1.2.3" }
	verifyCommand = func(context.Context, string) error { return nil }

	workDir := t.TempDir()
	ex := NewExtractor(workDir)

	if err := os.MkdirAll(filepath.Dir(ex.BinPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(ex.BinPath, []byte("old-binary"), 0o755); err != nil {
		t.Fatalf("write bin: %v", err)
	}
	if err := os.WriteFile(ex.versionPath(), []byte("1.2.3\n"), 0o600); err != nil {
		t.Fatalf("write version: %v", err)
	}

	before, err := os.ReadFile(ex.BinPath)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}

	if err := ex.Extract(); err != nil {
		t.Fatalf("extract: %v", err)
	}

	after, err := os.ReadFile(ex.BinPath)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("expected existing binary unchanged")
	}
}

func TestExtract_UpdatesWhenVersionDiffers(t *testing.T) {
	origBinaryProvider := binaryProvider
	origVersionProvider := versionProvider
	origVerify := verifyCommand
	t.Cleanup(func() {
		binaryProvider = origBinaryProvider
		versionProvider = origVersionProvider
		verifyCommand = origVerify
	})

	binaryProvider = func() []byte { return []byte("new-binary") }
	versionProvider = func() string { return "2.0.0" }
	verifyCommand = func(context.Context, string) error { return nil }

	workDir := t.TempDir()
	ex := NewExtractor(workDir)

	if err := os.MkdirAll(filepath.Dir(ex.BinPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(ex.BinPath, []byte("old-binary"), 0o755); err != nil {
		t.Fatalf("write bin: %v", err)
	}
	if err := os.WriteFile(ex.versionPath(), []byte("1.0.0\n"), 0o600); err != nil {
		t.Fatalf("write version: %v", err)
	}

	if err := ex.Extract(); err != nil {
		t.Fatalf("extract: %v", err)
	}

	updated, err := os.ReadFile(ex.BinPath)
	if err != nil {
		t.Fatalf("read updated: %v", err)
	}
	if string(updated) != "new-binary" {
		t.Fatalf("unexpected binary content: %q", string(updated))
	}

	versionContent, err := os.ReadFile(ex.versionPath())
	if err != nil {
		t.Fatalf("read version: %v", err)
	}
	if string(bytes.TrimSpace(versionContent)) != "2.0.0" {
		t.Fatalf("unexpected version: %q", string(versionContent))
	}
}
