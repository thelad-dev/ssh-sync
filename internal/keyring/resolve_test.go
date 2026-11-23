package keyring

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResolveMasterPasswordUsesStoredWithoutTTY(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}
	t.Setenv(masterPasswordEnv, "")
	t.Setenv("SSH_SYNC_KEYRING", "file")
	t.Setenv("SSH_TTY", "")

	cfgDir := filepath.Join(home, ".config", "ssh-sync")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, masterFileName), []byte("stored-master\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	prompted := false
	pw, err := ResolveMasterPassword(false, func(label string) (string, error) {
		prompted = true
		return "should-not-run", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if pw != "stored-master" {
		t.Fatalf("pw=%q", pw)
	}
	if prompted {
		t.Fatal("ohne TTY und mit gespeichertem Passwort darf nicht gepromptet werden")
	}
}

func TestResolveMasterPasswordWithoutStoredNeedsUnlock(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}
	t.Setenv(masterPasswordEnv, "")
	t.Setenv("SSH_SYNC_KEYRING", "file")
	t.Setenv("SSH_TTY", "")

	pw, err := ResolveMasterPassword(false, func(label string) (string, error) {
		return "nope", nil
	})
	if err == nil {
		t.Fatalf("erwartet Fehler, got pw=%q", pw)
	}
	if !strings.Contains(err.Error(), "ssh-sync unlock") {
		t.Fatalf("Hinweis auf unlock fehlt: %v", err)
	}
}

func TestResolveMasterPasswordPromptsOnTTY(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}
	t.Setenv(masterPasswordEnv, "")
	t.Setenv("SSH_SYNC_KEYRING", "file")
	t.Setenv("SSH_TTY", "")

	pw, err := ResolveMasterPassword(true, func(label string) (string, error) {
		if label != "Master-Passwort:" {
			t.Fatalf("label=%q", label)
		}
		return "typed-master", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if pw != "typed-master" {
		t.Fatalf("pw=%q", pw)
	}
}

func TestResolveMasterPasswordPromptError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}
	t.Setenv(masterPasswordEnv, "")
	t.Setenv("SSH_SYNC_KEYRING", "file")
	t.Setenv("SSH_TTY", "")

	_, err := ResolveMasterPassword(true, func(label string) (string, error) {
		return "", errors.New("inappropriate ioctl for device")
	})
	if err == nil {
		t.Fatal("erwartet Fehler")
	}
	if !strings.Contains(err.Error(), "Passwort lesen fehlgeschlagen") {
		t.Fatalf("err=%v", err)
	}
}
