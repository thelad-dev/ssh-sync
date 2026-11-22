package agentpurge

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/thelad-dev/ssh-sync/internal/sshconfig"
)

func TestPortalStyleFullWipeLeavesNoManagedBackup(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	configDir := filepath.Join(home, ".config", "ssh-sync")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(configDir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"server_url":"https://example.test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	managed := sshconfig.ManagedBegin + "\nHost h\n  HostName x\n  IdentityFile id_ed25519\n" + sshconfig.ManagedEnd + "\n"
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(managed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), []byte("managed-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "foreign_key"), []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Portalweg: Wipe vor completed, kein managed-only, kein backupManaged.
	if err := WipeSSHDir(sshDir); err != nil {
		t.Fatal(err)
	}
	if err := Execute(Options{
		ManagedOnly: false,
		ConfigPath:  cfgPath,
		SSHDir:      sshDir,
		SkipBinary:  true,
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(sshDir, "id_ed25519")); !os.IsNotExist(err) {
		t.Fatal("managed key must be gone")
	}
	if _, err := os.Stat(filepath.Join(sshDir, "foreign_key")); !os.IsNotExist(err) {
		t.Fatal("foreign key must be wiped on portal full purge")
	}
	if _, err := os.Stat(filepath.Join(sshDir, "authorized_keys")); err != nil {
		t.Fatalf("authorized_keys must remain: %v", err)
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if len(e.Name()) >= len(".ssh-sync-purge-backup-") && e.Name()[:len(".ssh-sync-purge-backup-")] == ".ssh-sync-purge-backup-" {
			t.Fatalf("portal wipe must not create backup dir %s", e.Name())
		}
	}
}
