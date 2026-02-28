package extractor

import (
	"embed"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nodepass-agent/embedfs"
)

func TestExtractCreatesBinary(t *testing.T) {
	ex := New(t.TempDir())

	if err := ex.Extract(embedfs.NodepassFiles); err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}

	info, err := os.Stat(ex.BinPath)
	if err != nil {
		t.Fatalf("Stat returned error: %v", err)
	}
	if info.IsDir() {
		t.Fatalf("expected file, got directory")
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("expected executable permissions, got %o", info.Mode().Perm())
	}

	installedVersion, err := ex.InstalledVersion()
	if err != nil {
		t.Fatalf("InstalledVersion returned error: %v", err)
	}

	embeddedVersion, err := ex.EmbeddedVersion(embedfs.NodepassFiles)
	if err != nil {
		t.Fatalf("EmbeddedVersion returned error: %v", err)
	}

	if installedVersion != embeddedVersion {
		t.Fatalf("installed version %q does not match embedded version %q", installedVersion, embeddedVersion)
	}
}

func TestExtractSkipsWhenUpToDate(t *testing.T) {
	ex := New(t.TempDir())

	if err := ex.Extract(embedfs.NodepassFiles); err != nil {
		t.Fatalf("initial Extract returned error: %v", err)
	}

	before, err := os.Stat(ex.BinPath)
	if err != nil {
		t.Fatalf("Stat before second extract failed: %v", err)
	}

	time.Sleep(1100 * time.Millisecond)

	if err := ex.Extract(embedfs.NodepassFiles); err != nil {
		t.Fatalf("second Extract returned error: %v", err)
	}

	after, err := os.Stat(ex.BinPath)
	if err != nil {
		t.Fatalf("Stat after second extract failed: %v", err)
	}

	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("expected mtime unchanged, before=%s after=%s", before.ModTime(), after.ModTime())
	}
}

func TestExtractFixesPermission(t *testing.T) {
	ex := New(t.TempDir())

	if err := ex.Extract(embedfs.NodepassFiles); err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}

	if err := os.Chmod(ex.BinPath, 0o644); err != nil {
		t.Fatalf("Chmod returned error: %v", err)
	}

	if err := ex.Extract(embedfs.NodepassFiles); err != nil {
		t.Fatalf("Extract with existing binary returned error: %v", err)
	}

	info, err := os.Stat(ex.BinPath)
	if err != nil {
		t.Fatalf("Stat returned error: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("expected executable permissions after extract, got %o", info.Mode().Perm())
	}
}

func TestExtractReturnsErrorWhenEmbeddedFileMissing(t *testing.T) {
	workDir := t.TempDir()
	ex := &Extractor{WorkDir: workDir, BinPath: filepath.Join(workDir, "bin", "nodepass")}

	var emptyFS embed.FS
	if err := ex.Extract(emptyFS); err == nil {
		t.Fatalf("expected error when embedded file is missing")
	}
}
