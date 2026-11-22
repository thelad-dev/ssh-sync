//go:build windows

package agentservice

import (
	"fmt"
	"os/exec"
)

const windowsServiceName = "ssh-sync"

// windowsLegacyServiceNames: alte Dienst-/Task-Namen fuer Stop und Uninstall bei Migration.
var windowsLegacyServiceNames = []string{"ssh-profile-syncer"}

func stopPlatform() (Result, error) {
	stopped := false
	method := ""

	for _, name := range append([]string{windowsServiceName}, windowsLegacyServiceNames...) {
		if err := exec.Command("sc", "stop", name).Run(); err == nil {
			stopped = true
			method = "Windows-Dienst (" + name + ")"
		}
		if err := exec.Command("schtasks", "/End", "/TN", name).Run(); err == nil {
			stopped = true
			if method == "" {
				method = "Scheduled Task (" + name + ")"
			}
		}
	}

	if !stopped {
		return Result{Method: "sc/schtasks", Changed: false}, nil
	}
	return Result{Method: method, Changed: true}, nil
}

func startPlatform() (Result, error) {
	if err := exec.Command("sc", "start", windowsServiceName).Run(); err == nil {
		return Result{Method: "Windows-Dienst (" + windowsServiceName + ")", Changed: true}, nil
	}
	if err := exec.Command("schtasks", "/Run", "/TN", windowsServiceName).Run(); err == nil {
		return Result{Method: "Scheduled Task (" + windowsServiceName + ")", Changed: true}, nil
	}
	return Result{}, fmt.Errorf("Dienst %s nicht gestartet (ssh-sync service start)", windowsServiceName)
}

func uninstallPlatform() error {
	for _, name := range append([]string{windowsServiceName}, windowsLegacyServiceNames...) {
		_ = exec.Command("sc", "stop", name).Run()
		_ = exec.Command("sc", "delete", name).Run()
		_ = exec.Command("schtasks", "/End", "/TN", name).Run()
		_ = exec.Command("schtasks", "/Delete", "/TN", name, "/F").Run()
	}
	return nil
}
