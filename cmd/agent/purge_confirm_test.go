package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPurgeWithoutConfirmationDeletesNothing(t *testing.T) {
	bin := buildTestAgent(t)
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	configDir := filepath.Join(home, ".config", "ssh-sync")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(sshDir, "keep-me")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(configDir, "config.json")
	if err := os.WriteFile(cfgPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "purge", "--config", cfgPath)
	cmd.Env = append(os.Environ(), "HOME="+home)
	cmd.Stdin = nil
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("purge ohne Bestätigung soll fehlschlagen: %s", out)
	}

	if _, err := os.Stat(secret); err != nil {
		t.Fatal("datei wurde trotzdem gelöscht")
	}
}

func buildTestAgent(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "ssh-sync")
	repoRoot := findRepoRoot(t)
	build := exec.Command("go", "build", "-o", out, "./cmd/agent")
	build.Dir = repoRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build agent: %v\n%s", err, b)
	}
	return out
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod nicht gefunden")
		}
		dir = parent
	}
}
