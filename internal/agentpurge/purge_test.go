package agentpurge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thelad-dev/ssh-sync/internal/sshconfig"
)

func TestPurgeRequiresConfirmationViaCLI(t *testing.T) {
	// Ohne Bestaetigung loescht Execute nichts; CLI-Bestaetigung in cmd/agent/purge_confirm_test.go.
	// Hier: Execute mit SkipBinary und leerem Temp-HOME.
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
	if err := os.WriteFile(cfgPath, []byte(`{"server_url":"http://x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(sshDir, "manual_key")
	if err := os.WriteFile(extra, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	managed := sshconfig.ManagedBegin + "\nHost h\n  HostName x\n  IdentityFile id_ed25519\n" + sshconfig.ManagedEnd + "\n"
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(managed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, ".master-key"), []byte("pw"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Execute(Options{
		ManagedOnly: true,
		ConfigPath:  cfgPath,
		SSHDir:      sshDir,
		SkipBinary:  true,
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(extra); err != nil {
		t.Fatalf("unmanaged extra soll bleiben: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sshDir, "id_ed25519")); !os.IsNotExist(err) {
		t.Fatal("managed key soll weg sein")
	}
	if _, err := os.Stat(configDir); !os.IsNotExist(err) {
		t.Fatal("config dir soll weg sein")
	}
}

func TestPurgeFullWipesSSHButKeepsProtected(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	configDir := filepath.Join(home, ".config", "ssh-sync")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(configDir, "config.json")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"config", "id_rsa", "known_hosts", "authorized_keys"} {
		if err := os.WriteFile(filepath.Join(sshDir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := Execute(Options{ConfigPath: cfgPath, SSHDir: sshDir, SkipBinary: true}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(sshDir, "id_rsa")); !os.IsNotExist(err) {
		t.Fatal("id_rsa soll weg sein")
	}
	if _, err := os.Stat(filepath.Join(sshDir, "known_hosts")); err != nil {
		t.Fatalf("known_hosts soll bleiben: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sshDir, "authorized_keys")); err != nil {
		t.Fatalf("authorized_keys soll bleiben: %v", err)
	}
	if _, err := os.Stat(configDir); !os.IsNotExist(err) {
		t.Fatal("config dir soll weg sein")
	}
}

func TestPostAckManagedPurgeLeavesForeignAndProtected(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	configDir := filepath.Join(home, ".config", "ssh-sync")
	backupDir := filepath.Join(home, "purge-backup")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(configDir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"server_url":"http://x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(sshDir, "id_ed25519_foreign")
	if err := os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte("keep-me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte("kh"), 0o600); err != nil {
		t.Fatal(err)
	}
	managed := sshconfig.ManagedBegin + "\nHost h\n  HostName x\n  IdentityFile id_ed25519\n" + sshconfig.ManagedEnd + "\n"
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(managed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), []byte("managed"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Execute(Options{
		ManagedOnly: true,
		ConfigPath:  cfgPath,
		SSHDir:      sshDir,
		BackupDir:   backupDir,
		SkipBinary:  true,
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("fremder Key soll bleiben: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sshDir, "authorized_keys")); err != nil {
		t.Fatalf("authorized_keys soll bleiben: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sshDir, "known_hosts")); err != nil {
		t.Fatalf("known_hosts soll bleiben: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sshDir, "id_ed25519")); !os.IsNotExist(err) {
		t.Fatal("managed key soll weg sein")
	}
	if _, err := os.Stat(filepath.Join(backupDir, "id_ed25519")); err != nil {
		t.Fatalf("backup soll managed key enthalten: %v", err)
	}
}

func TestManagedIdentityFiles(t *testing.T) {
	content := sshconfig.ManagedBegin + "\nHost a\n  IdentityFile ~/.ssh/sync_key\n  IdentityFile rel_key\n" + sshconfig.ManagedEnd
	files := sshconfig.ManagedIdentityFiles(content)
	if len(files) != 2 || !strings.Contains(files[0], "sync_key") {
		t.Fatalf("unexpected files: %v", files)
	}
}
