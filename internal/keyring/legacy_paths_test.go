package keyring

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGetMasterPasswordReadsLegacyFileAndKeepsIt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}
	t.Setenv(masterPasswordEnv, "")
	t.Setenv("SSH_SYNC_KEYRING", "file")
	t.Setenv("SSH_TTY", "")

	legacyDir := filepath.Join(home, ".config", "ssh-profile-syncer")
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacyPath := LegacyMasterFilePath(home)
	if err := os.WriteFile(legacyPath, []byte("legacy-master-fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	pw, err := GetMasterPassword()
	if err != nil {
		t.Fatal(err)
	}
	if pw != "legacy-master-fixture" {
		t.Fatalf("pw=%q", pw)
	}
	if _, err := os.Stat(legacyPath); err != nil {
		t.Fatalf("legacy master file must remain: %v", err)
	}
	newPath, err := masterFilePath()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(newPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "legacy-master-fixture" {
		t.Fatalf("new master file=%q", data)
	}
}

func TestLegacyMasterFilePathShape(t *testing.T) {
	home := filepath.Join("Users", "fixture")
	got := LegacyMasterFilePath(home)
	want := filepath.Join(home, ".config", "ssh-profile-syncer", masterFileName)
	if got != want {
		t.Fatalf("got %q want %q (GOOS=%s)", got, want, runtime.GOOS)
	}
}
