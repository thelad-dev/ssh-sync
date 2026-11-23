package sshconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thelad-dev/ssh-sync/internal/keygen"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

// TestDisposableHomeScenario simuliert ein Wegwerf-Home mit eigener config und
// eigenem id_ed25519 gleichen Namens wie der Server-Schluessel.
func TestDisposableHomeScenario(t *testing.T) {
	dir := t.TempDir()
	local, err := keygen.Generate(keygen.TypeEd25519, "verify-local")
	if err != nil {
		t.Fatal(err)
	}
	server, err := keygen.Generate(keygen.TypeEd25519, "verify-server")
	if err != nil {
		t.Fatal(err)
	}
	configBefore := "Host local\n  HostName localhost\n  User me\n# lokale zeile behalten\n"
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(configBefore), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519"), local.PrivatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519.pub"), []byte(local.PublicLine), 0o644); err != nil {
		t.Fatal(err)
	}

	localFP, _ := PrivateKeyFingerprint(local.PrivatePEM)
	serverFP, _ := PrivateKeyFingerprint(server.PrivatePEM)
	pubFP, _ := PublicKeyFingerprint([]byte(local.PublicLine))
	t.Logf("VORHER config lines=%d", lineCount(configBefore))
	t.Logf("VORHER id_ed25519 fp=%s", localFP)
	t.Logf("VORHER id_ed25519.pub fp=%s", pubFP)

	id := "id-server"
	bundle := &store.SyncBundle{
		Identities: []store.Identity{{ID: id, Name: "id_ed25519"}},
		Hosts:      []store.Host{{ID: "h1", Alias: "srv", HostName: "example.test", User: "u", IdentityID: &id}},
	}

	dry, err := Apply(dir, bundle, map[string][]byte{id: server.PrivatePEM}, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !dry.DryRun || !dry.NeedsConfirm {
		t.Fatal("erster Lauf muss Trockenlauf sein")
	}
	if _, err := os.Stat(filepath.Join(dir, "id_ed25519.ssh-sync")); !os.IsNotExist(err) {
		t.Fatal("DryRun darf Ausweichdatei nicht anlegen")
	}
	cfgAfterDry, _ := os.ReadFile(filepath.Join(dir, "config"))
	if string(cfgAfterDry) != configBefore {
		t.Fatal("DryRun aenderte config")
	}

	res, err := Apply(dir, bundle, map[string][]byte{id: server.PrivatePEM}, ApplyOptions{AllowFirstWrite: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.DryRun {
		t.Fatal("AllowFirstWrite muss schreiben")
	}

	gotLocal, _ := os.ReadFile(filepath.Join(dir, "id_ed25519"))
	if PrivateKeyMustFP(t, gotLocal) != localFP {
		t.Fatal("lokaler Key ueberschrieben")
	}
	gotAlt, err := os.ReadFile(filepath.Join(dir, "id_ed25519.ssh-sync"))
	if err != nil {
		t.Fatal(err)
	}
	if PrivateKeyMustFP(t, gotAlt) != serverFP {
		t.Fatal("Ausweichdatei falsch")
	}
	cfg, _ := os.ReadFile(filepath.Join(dir, "config"))
	t.Logf("NACHHER config lines=%d", lineCount(string(cfg)))
	t.Logf("NACHHER id_ed25519 fp=%s", PrivateKeyMustFP(t, gotLocal))
	t.Logf("NACHHER id_ed25519.ssh-sync fp=%s", PrivateKeyMustFP(t, gotAlt))
	t.Logf("NACHHER backup=%s", res.BackupPath)
	if !strings.Contains(string(cfg), "Host local") {
		t.Fatal("Host local fehlt")
	}
	if !strings.Contains(string(cfg), managedBegin) {
		t.Fatal("managed Block fehlt")
	}
	if res.BackupPath == "" {
		t.Fatal("Backup erwartet")
	}
	fmt.Fprintf(os.Stderr, "DISPOSABLE_HOME_OK local=%s server=%s\n", localFP, serverFP)
}

func lineCount(s string) int {
	if s == "" {
		return 0
	}
	n := strings.Count(s, "\n")
	if !strings.HasSuffix(s, "\n") {
		n++
	}
	return n
}
