package extractor

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nodepass-agent/embedfs"
)

const defaultWorkDir = "/opt/nodepass-agent"

type Extractor struct {
	WorkDir string
	BinPath string
}

func New(workDir string) *Extractor {
	e := &Extractor{WorkDir: strings.TrimSpace(workDir)}
	e.normalizePaths()
	return e
}

func (e *Extractor) Extract(files embed.FS) error {
	e.normalizePaths()

	embeddedBinary, embeddedVersion, err := e.embeddedBinaryAndVersion(files)
	if err != nil {
		return err
	}

	installedVersion, err := e.InstalledVersion()
	if err == nil && installedVersion == embeddedVersion {
		return os.Chmod(e.BinPath, 0o755)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(e.BinPath), 0o755); err != nil {
		return err
	}

	tmpPath := e.BinPath + ".tmp-" + fmt.Sprintf("%d", time.Now().UnixNano())
	if err := os.WriteFile(tmpPath, embeddedBinary, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, e.BinPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	return nil
}

func (e *Extractor) EmbeddedVersion(files embed.FS) (string, error) {
	_, version, err := e.embeddedBinaryAndVersion(files)
	return version, err
}

func (e *Extractor) InstalledVersion() (string, error) {
	e.normalizePaths()

	content, err := os.ReadFile(e.BinPath)
	if err != nil {
		return "", err
	}

	return checksum(content), nil
}

func (e *Extractor) embeddedBinaryAndVersion(files embed.FS) ([]byte, string, error) {
	embedPath, err := embedfs.EmbedPath()
	if err != nil {
		return nil, "", err
	}

	content, err := files.ReadFile(embedPath)
	if err != nil {
		return nil, "", err
	}
	if len(content) == 0 {
		return nil, "", fmt.Errorf("embedded binary is empty: %s", embedPath)
	}

	return content, checksum(content), nil
}

func checksum(data []byte) string {
	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func (e *Extractor) normalizePaths() {
	e.WorkDir = strings.TrimSpace(e.WorkDir)
	if e.WorkDir == "" {
		e.WorkDir = defaultWorkDir
	}

	e.BinPath = strings.TrimSpace(e.BinPath)
	if e.BinPath == "" {
		e.BinPath = filepath.Join(e.WorkDir, "bin", "nodepass")
	}
}
