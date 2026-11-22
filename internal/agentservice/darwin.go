//go:build darwin

package agentservice

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// launchdLabels: neues Label zuerst; alte Labels bleiben fuer Migration (Stop/Uninstall).
var launchdLabels = []string{
	"com.ssh-sync.ssh-sync",
	"com.ssh-profile-syncer.ssh-sync",
	"com.legacy.ssh-sync",
	"ssh-sync",
}

const launchdPlistName = "com.ssh-sync.ssh-sync.plist"

func stopPlatform() (Result, error) {
	stopped := false
	method := ""

	if _, err := exec.LookPath("launchctl"); err == nil {
		uid := os.Getuid()
		gui := "gui/" + strconv.Itoa(uid)
		for _, label := range launchdLabels {
			target := gui + "/" + label
			if err := exec.Command("launchctl", "bootout", target).Run(); err == nil {
				stopped = true
				method = "launchctl bootout"
			}
			if err := exec.Command("launchctl", "stop", label).Run(); err == nil {
				stopped = true
				if method == "" {
					method = "launchctl stop"
				}
			}
		}
	}

	if pkillDaemon() {
		stopped = true
		if method == "" {
			method = "Prozess-Signal"
		}
	}

	if !stopped {
		return Result{Method: "launchctl/pkill", Changed: false}, nil
	}
	time.Sleep(400 * time.Millisecond)
	return Result{Method: method, Changed: true}, nil
}

func startPlatform() (Result, error) {
	if _, err := exec.LookPath("launchctl"); err != nil {
		return Result{}, nil
	}
	uid := os.Getuid()
	gui := "gui/" + strconv.Itoa(uid)
	home, err := os.UserHomeDir()
	if err != nil {
		return Result{}, err
	}
	plist := filepath.Join(home, "Library", "LaunchAgents", launchdPlistName)
	if err := exec.Command("launchctl", "bootstrap", gui, plist).Run(); err == nil {
		return Result{Method: "launchctl bootstrap", Changed: true}, nil
	}
	for _, label := range launchdLabels {
		if err := exec.Command("launchctl", "kickstart", "-k", gui+"/"+label).Run(); err == nil {
			return Result{Method: "launchctl kickstart", Changed: true}, nil
		}
	}
	return Result{}, fmt.Errorf("kein launchd-Agent für ssh-sync gefunden")
}

func pkillDaemon() bool {
	if _, err := exec.LookPath("pkill"); err != nil {
		return false
	}
	return exec.Command("pkill", "-f", "[s]sh-sync daemon").Run() == nil
}

func uninstallPlatform() error {
	if _, err := exec.LookPath("launchctl"); err != nil {
		return nil
	}
	uid := os.Getuid()
	gui := "gui/" + strconv.Itoa(uid)
	for _, label := range launchdLabels {
		target := gui + "/" + label
		_ = exec.Command("launchctl", "bootout", target).Run()
		_ = exec.Command("launchctl", "remove", label).Run()
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	for _, name := range []string{
		launchdPlistName,
		"com.legacy.ssh-sync.plist",
	} {
		_ = os.Remove(filepath.Join(home, "Library", "LaunchAgents", name))
	}
	return nil
}
