package agentconfig

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDefaultPathMigratesLegacyConfigAndKeepsBackup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}

	legacyDir := filepath.Join(home, ".config", "ssh-profile-syncer")
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(legacyDir, "config.json")
	legacyBody := []byte(`{
  "server_url": "https://example.test",
  "device_id": "0123456789abcdef0123456789abcdef",
  "jwt": "legacy-jwt-fixture"
}`)
	if err := os.WriteFile(legacyPath, legacyBody, 0o600); err != nil {
		t.Fatal(err)
	}

	path, err := DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	wantNew := filepath.Join(home, ".config", "ssh-sync", "config.json")
	if path != wantNew {
		t.Fatalf("path=%q want %q", path, wantNew)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(legacyBody) {
		t.Fatalf("migrated body mismatch")
	}
	if _, err := os.Stat(legacyPath); err != nil {
		t.Fatalf("legacy config must remain: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DeviceID != "0123456789abcdef0123456789abcdef" || cfg.JWT != "legacy-jwt-fixture" {
		t.Fatalf("unexpected cfg: %+v", cfg)
	}

	// Second call is idempotent and does not require legacy file.
	path2, err := DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if path2 != path {
		t.Fatalf("second path=%q", path2)
	}
}

func TestLegacyConfigPathUsesDotConfigOnAllPlatforms(t *testing.T) {
	home := filepath.Join("Users", "fixture")
	got := LegacyConfigPath(home)
	want := filepath.Join(home, ".config", "ssh-profile-syncer", "config.json")
	if got != want {
		t.Fatalf("got %q want %q (GOOS=%s)", got, want, runtime.GOOS)
	}
}

func TestDefaultPathWithoutLegacy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}
	path, err := DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".config", "ssh-sync", "config.json")
	if path != want {
		t.Fatalf("path=%q want %q", path, want)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("new config should not exist yet, err=%v", err)
	}
}
