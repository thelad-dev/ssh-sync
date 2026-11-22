package selfupdate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveDestPathFromTmpRunner(t *testing.T) {
	dir := t.TempDir()
	installDir := filepath.Join(dir, ".local", "bin")
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		t.Fatal(err)
	}
	install := filepath.Join(installDir, "ssh-sync")
	if err := os.WriteFile(install, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", dir)
	defer os.Setenv("HOME", oldHome)

	// LookPath("ssh-sync") darf kein fremdes Installationsbinary finden.
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", t.TempDir())
	defer os.Setenv("PATH", oldPath)

	got, err := ResolveDestPath("")
	// ohne echtes Executable aus /tmp: nutzt HOME/.local/bin
	if err != nil {
		t.Fatal(err)
	}
	if got != install {
		t.Fatalf("got %q want %q", got, install)
	}
}
