//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

func detachPurgeCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
