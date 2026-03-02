package embedfs

import (
	"embed"
	"fmt"
	"runtime"
	"strings"
)

//go:embed nodepass_linux_amd64 nodepass_linux_arm64 nodepass_linux_armv7 nodepass_darwin_amd64 nodepass_darwin_arm64
var NodepassFiles embed.FS

func EmbedPath() (string, error) {
	return EmbedPathFor(runtime.GOOS, runtime.GOARCH)
}

func EmbedPathFor(goos, goarch string) (string, error) {
	osName := strings.ToLower(strings.TrimSpace(goos))
	archName := strings.ToLower(strings.TrimSpace(goarch))

	switch osName {
	case "linux":
		switch archName {
		case "amd64", "x86_64":
			return "nodepass_linux_amd64", nil
		case "arm64", "aarch64":
			return "nodepass_linux_arm64", nil
		case "arm", "armv7", "armv7l":
			return "nodepass_linux_armv7", nil
		}
	case "darwin":
		switch archName {
		case "amd64", "x86_64":
			return "nodepass_darwin_amd64", nil
		case "arm64", "aarch64":
			return "nodepass_darwin_arm64", nil
		}
	}

	return "", fmt.Errorf("unsupported platform: %s/%s", osName, archName)
}
