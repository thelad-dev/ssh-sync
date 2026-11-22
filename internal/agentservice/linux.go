//go:build linux

package agentservice

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const systemdUnit = "ssh-sync.service"

func stopPlatform() (Result, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		if killed := pkillDaemon(); killed {
			return Result{Method: "Prozess-Signal", Changed: true}, nil
		}
		return Result{}, nil
	}

	state := systemdActiveState()
	switch state {
	case "inactive", "failed", "":
		if killed := pkillDaemon(); killed {
			return Result{Method: "Prozess-Signal", Changed: true}, nil
		}
		return Result{Method: "systemd user", Changed: false}, nil
	}

	if err := exec.Command("systemctl", "--user", "stop", systemdUnit).Run(); err != nil {
		return Result{}, fmt.Errorf("systemctl --user stop %s: %w", systemdUnit, err)
	}
	if err := waitSystemdState("inactive", "failed"); err != nil {
		return Result{}, err
	}
	return Result{Method: "systemd user (" + systemdUnit + ")", Changed: true}, nil
}

func startPlatform() (Result, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return Result{}, nil
	}
	if err := exec.Command("systemctl", "--user", "restart", systemdUnit).Run(); err != nil {
		return Result{}, fmt.Errorf("systemctl --user restart %s: %w", systemdUnit, err)
	}
	return Result{Method: "systemd user (" + systemdUnit + ")", Changed: true}, nil
}

func systemdActiveState() string {
	out, err := exec.Command("systemctl", "--user", "is-active", systemdUnit).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func waitSystemdState(want ...string) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		state := systemdActiveState()
		for _, w := range want {
			if state == w {
				return nil
			}
		}
		if state == "unknown" {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("systemd-Dienst %s stoppt nicht rechtzeitig (Zustand: %s)", systemdUnit, systemdActiveState())
}

func pkillDaemon() bool {
	if _, err := exec.LookPath("pkill"); err != nil {
		return false
	}
	return exec.Command("pkill", "-f", "[s]sh-sync daemon").Run() == nil
}

func uninstallPlatform() error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}
	_ = exec.Command("systemctl", "--user", "disable", "--now", systemdUnit).Run()
	_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	unitPath := filepath.Join(home, ".config", "systemd", "user", systemdUnit)
	_ = os.Remove(unitPath)
	return nil
}
