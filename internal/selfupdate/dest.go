package selfupdate

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ResolveDestPath bestimmt das zu aktualisierende Binary.
// Läuft der Update aus /tmp, wird die Installation unter ~/.local/bin bevorzugt.
func ResolveDestPath(destFlag string) (string, error) {
	if strings.TrimSpace(destFlag) != "" {
		return filepath.EvalSymlinks(destFlag)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	if !isEphemeralRunner(exe) {
		return exe, nil
	}
	if install := findInstalledBinary(exe); install != "" {
		return install, nil
	}
	return exe, nil
}

func isEphemeralRunner(path string) bool {
	path = filepath.Clean(path)
	base := filepath.Base(path)
	if base == "ssh-sync-update-runner" {
		return true
	}
	dir := filepath.Dir(path)
	if dir == os.TempDir() || strings.HasPrefix(dir, "/tmp") || strings.Contains(dir, "/Temp/") {
		return true
	}
	return false
}

func findInstalledBinary(currentExe string) string {
	currentExe = filepath.Clean(currentExe)
	if p, err := exec.LookPath("ssh-sync"); err == nil {
		if p, err = filepath.EvalSymlinks(p); err == nil && filepath.Clean(p) != currentExe && !isEphemeralRunner(p) {
			if isExecutableFile(p) {
				return p
			}
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	for _, c := range []string{
		filepath.Join(home, ".local", "bin", "ssh-sync"),
		"/usr/local/bin/ssh-sync",
	} {
		if c == currentExe {
			continue
		}
		if p, err := filepath.EvalSymlinks(c); err == nil && isExecutableFile(p) {
			return p
		}
	}
	return ""
}

func isExecutableFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir() && st.Mode()&0o111 != 0
}
