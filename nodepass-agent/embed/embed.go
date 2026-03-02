package embed

import (
	_ "embed"
	"runtime"
	"strings"
)

//go:embed nodepass_linux_amd64
var NodepassLinuxAmd64 []byte

//go:embed nodepass_linux_arm64
var NodepassLinuxArm64 []byte

//go:embed nodepass_linux_386
var NodepassLinux386 []byte

//go:embed VERSION
var EmbeddedVersion string

func GetBinary() []byte {
	switch runtime.GOARCH {
	case "amd64":
		return NodepassLinuxAmd64
	case "arm64":
		return NodepassLinuxArm64
	case "386":
		return NodepassLinux386
	default:
		panic("unsupported arch: " + runtime.GOARCH)
	}
}

func Version() string {
	return strings.TrimSpace(EmbeddedVersion)
}
