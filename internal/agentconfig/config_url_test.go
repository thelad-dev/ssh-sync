package agentconfig

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMigrateLegacyConfigRejectsInsecureHTTP(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}

	legacyDir := filepath.Join(home, ".config", "ssh-profile-syncer")
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacyBody := []byte(`{
  "server_url": "http://evil.test",
  "device_id": "0123456789abcdef0123456789abcdef",
  "jwt": "legacy-jwt-fixture"
}`)
	if err := os.WriteFile(filepath.Join(legacyDir, "config.json"), legacyBody, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := DefaultPath()
	if err == nil {
		t.Fatal("expected rejection of http://evil.test on legacy migrate")
	}
	if !strings.Contains(err.Error(), "http://") && !strings.Contains(err.Error(), "Loopback") && !strings.Contains(err.Error(), "insecure") {
		t.Fatalf("unexpected error: %v", err)
	}
	newPath := filepath.Join(home, ".config", "ssh-sync", "config.json")
	if _, err := os.Stat(newPath); !os.IsNotExist(err) {
		t.Fatal("insecure legacy config must not be copied")
	}
}
