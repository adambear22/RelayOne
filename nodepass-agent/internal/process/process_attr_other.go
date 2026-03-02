//go:build !linux

package process

import "os/exec"

func applyParentDeathSignal(cmd *exec.Cmd) {
	_ = cmd
}
