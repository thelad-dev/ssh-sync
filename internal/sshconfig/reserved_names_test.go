package sshconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thelad-dev/ssh-sync/internal/store"
)

func TestApplyRejectsReservedIdentityNames(t *testing.T) {
	sshDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte("keep-me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	idRef := "id1"
	bundle := &store.SyncBundle{
		Identities: []store.Identity{{ID: "id1", Name: "authorized_keys"}},
		Hosts:      []store.Host{{ID: "h1", Alias: "h", HostName: "x", IdentityID: &idRef}},
	}
	_, err := Apply(sshDir, bundle, map[string][]byte{"id1": []byte("PRIVATE")})
	if err == nil {
		t.Fatal("expected reserved name rejection")
	}
	if !strings.Contains(err.Error(), "reservierten") && !strings.Contains(err.Error(), "authorized_keys") {
		t.Fatalf("unexpected error: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(sshDir, "authorized_keys"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep-me\n" {
		t.Fatalf("authorized_keys was overwritten: %q", got)
	}
}

func TestValidateKeyBasenameRejectsSuffixVariants(t *testing.T) {
	for _, name := range []string{"known_hosts", "known_hosts.pem", "config--bak", "rc", "environment", "authorized_keys2"} {
		if err := ValidateKeyBasename(name); err == nil {
			t.Fatalf("expected reject for %q", name)
		}
	}
	if err := ValidateKeyBasename("id_ed25519"); err != nil {
		t.Fatal(err)
	}
}
