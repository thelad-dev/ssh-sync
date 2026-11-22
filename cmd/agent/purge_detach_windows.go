//go:build windows

package main

import "os/exec"

func detachPurgeCmd(cmd *exec.Cmd) {}
