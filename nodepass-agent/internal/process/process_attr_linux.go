//go:build linux

package process

import (
	"os/exec"
	"syscall"
)

func applyParentDeathSignal(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}
