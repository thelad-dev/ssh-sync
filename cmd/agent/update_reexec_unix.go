//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/thelad-dev/ssh-sync/internal/selfupdate"
)

const updateReexecEnv = "SSH_SYNC_UPDATE_REEXEC"

// reexecUpdateFromTemp startet update aus einer Temp-Kopie, damit das Zielbinary
// nicht „text file busy“ ist, während die Zieldatei ersetzt wird.
func reexecUpdateFromTemp(destFlag string, updateArgs []string) (ran bool, exitCode int, err error) {
	if os.Getenv(updateReexecEnv) == "1" {
		return false, 0, nil
	}

	exe, err := os.Executable()
	if err != nil {
		return false, 0, err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return false, 0, err
	}

	var dest string
	if destFlag != "" {
		dest, err = filepath.EvalSymlinks(destFlag)
	} else {
		dest, err = selfupdate.ResolveDestPath("")
	}
	if err != nil {
		return false, 0, err
	}

	if filepath.Clean(exe) != filepath.Clean(dest) {
		return false, 0, nil
	}

	data, err := os.ReadFile(exe)
	if err != nil {
		return false, 0, err
	}
	dir, err := os.MkdirTemp("", "ssh-sync-update-*")
	if err != nil {
		return false, 0, err
	}
	defer os.RemoveAll(dir)
	tmp, err := os.OpenFile(filepath.Join(dir, "ssh-sync-update-runner"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return false, 0, err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return false, 0, err
	}
	if err := tmp.Close(); err != nil {
		return false, 0, err
	}

	cmd := exec.Command(tmpPath, updateArgs...)
	cmd.Env = append(os.Environ(), updateReexecEnv+"=1")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return true, ee.ExitCode(), nil
		}
		return false, 0, err
	}
	return true, 0, nil
}

func maybeReexecUpdate(destFlag string, updateArgs []string) {
	ran, code, err := reexecUpdateFromTemp(destFlag, updateArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Update-Reexec fehlgeschlagen: %v\n", err)
		return
	}
	if ran {
		os.Exit(code)
	}
}
