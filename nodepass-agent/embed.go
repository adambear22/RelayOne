package agent

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed assets/nodepass-linux-amd64
var nodepassAmd64 []byte

//go:embed assets/nodepass-linux-arm64
var nodepassArm64 []byte

//go:embed assets/nodepass-linux-armv7
var nodepassArmv7 []byte

var expectedNodePassSHA256 = map[string]string{
	"amd64": "35aa8ce4e82911a5bb41c9a0d53f53ffc5f4ff0c3417c9f09e34c84527d6c1ec",
	"arm64": "736af36dbd231abc7bb64c9e35206f2db2936874236e0335cebfd740ba66b2cb",
	"arm":   "594bf3fdb6184ba17d3336132a99d9d270b026fa07b3ea9529bfc9a3e4e725b4",
	"armv7": "594bf3fdb6184ba17d3336132a99d9d270b026fa07b3ea9529bfc9a3e4e725b4",
}

func ExtractNodePass(arch, version string) (string, error) {
	binary, expectedHash, err := embeddedBinaryForArch(arch)
	if err != nil {
		return "", err
	}

	cleanVersion := sanitizeVersion(version)
	cleanArch := strings.TrimSpace(strings.ToLower(arch))
	targetPath := filepath.Join(os.TempDir(), fmt.Sprintf(".nodepass-%s-%s", cleanVersion, cleanArch))

	if hash, ok, err := fileSHA256(targetPath); err == nil && ok && strings.EqualFold(hash, expectedHash) {
		if err := ensureExecutable(targetPath); err == nil {
			return targetPath, nil
		}
	}

	if err := os.WriteFile(targetPath, binary, 0o755); err != nil {
		return "", err
	}
	if err := os.Chmod(targetPath, 0o755); err != nil {
		return "", err
	}

	hash, ok, err := fileSHA256(targetPath)
	if err != nil {
		return "", err
	}
	if !ok || !strings.EqualFold(hash, expectedHash) {
		return "", errors.New("nodepass binary hash mismatch")
	}

	if err := ensureExecutable(targetPath); err != nil {
		return "", err
	}

	return targetPath, nil
}

func embeddedBinaryForArch(arch string) ([]byte, string, error) {
	cleanArch := strings.TrimSpace(strings.ToLower(arch))
	expectedHash, ok := expectedNodePassSHA256[cleanArch]
	if !ok {
		return nil, "", fmt.Errorf("unsupported arch: %s", arch)
	}

	switch cleanArch {
	case "amd64":
		return nodepassAmd64, expectedHash, nil
	case "arm64":
		return nodepassArm64, expectedHash, nil
	case "arm", "armv7":
		return nodepassArmv7, expectedHash, nil
	default:
		return nil, "", fmt.Errorf("unsupported arch: %s", arch)
	}
}

func fileSHA256(path string) (string, bool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}

	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]), true, nil
}

func ensureExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s is not executable", path)
	}
	return nil
}

func sanitizeVersion(version string) string {
	clean := strings.TrimSpace(version)
	if clean == "" {
		return "dev"
	}

	replacer := strings.NewReplacer("/", "-", "\\", "-", " ", "-")
	clean = replacer.Replace(clean)
	if clean == "" {
		return "dev"
	}
	return clean
}
