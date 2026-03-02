package process

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	agentembed "nodepass-agent/embed"
)

type Extractor struct {
	WorkDir string
	BinPath string
}

var (
	binaryProvider  = agentembed.GetBinary
	versionProvider = agentembed.Version
	verifyTimeout   = 3 * time.Second
	verifyCommand   = func(ctx context.Context, binPath string) error {
		cmd := exec.CommandContext(ctx, binPath, "version")
		return cmd.Run()
	}
)

func NewExtractor(workDir string) *Extractor {
	cleanWorkDir := strings.TrimSpace(workDir)
	if cleanWorkDir == "" {
		cleanWorkDir = "/var/lib/nodepass-agent"
	}
	return &Extractor{
		WorkDir: cleanWorkDir,
		BinPath: filepath.Join(cleanWorkDir, "bin", "nodepass"),
	}
}

func (e *Extractor) Extract() error {
	if e == nil {
		return errors.New("extractor is nil")
	}
	if strings.TrimSpace(e.BinPath) == "" {
		e.BinPath = filepath.Join(e.WorkDir, "bin", "nodepass")
	}

	embeddedVersion := strings.TrimSpace(versionProvider())
	if embeddedVersion == "" {
		embeddedVersion = fileChecksum(binaryProvider())
	}

	if _, err := os.Stat(e.BinPath); err == nil {
		installedVersion, vErr := e.installedVersion()
		if vErr == nil && installedVersion == embeddedVersion {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(e.BinPath), 0o755); err != nil {
		return err
	}

	tmp := e.BinPath + ".tmp"
	if err := os.WriteFile(tmp, binaryProvider(), 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, e.BinPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	if err := os.WriteFile(e.versionPath(), []byte(embeddedVersion+"\n"), 0o600); err != nil {
		return err
	}

	return e.verifyExecutable()
}

func (e *Extractor) NeedsUpdate(newVersion string) bool {
	installedVersion, err := e.installedVersion()
	if err != nil {
		return true
	}
	return strings.TrimSpace(installedVersion) != strings.TrimSpace(newVersion)
}

func (e *Extractor) installedVersion() (string, error) {
	content, err := os.ReadFile(e.versionPath())
	if err == nil {
		return strings.TrimSpace(string(content)), nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}

	binContent, readErr := os.ReadFile(e.BinPath)
	if readErr != nil {
		return "", readErr
	}
	return fileChecksum(binContent), nil
}

func (e *Extractor) versionPath() string {
	return e.BinPath + ".version"
}

func (e *Extractor) verifyExecutable() error {
	fi, err := os.Stat(e.BinPath)
	if err != nil {
		return err
	}
	if fi.Size() < 1024 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), verifyTimeout)
	defer cancel()

	if err := verifyCommand(ctx, e.BinPath); err != nil {
		return fmt.Errorf("verify nodepass binary: %w", err)
	}
	return nil
}

func fileChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
