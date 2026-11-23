package sshconfig

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/thelad-dev/ssh-sync/internal/keygen"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

func passphrasePEM(t *testing.T, comment, pass string) (pemBytes []byte, pubLine string, fp string) {
	t.Helper()
	kp, err := keygen.Generate(keygen.TypeEd25519, comment)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ssh.ParseRawPrivateKey(kp.PrivatePEM)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(raw, comment, []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes = pem.EncodeToMemory(block)
	fp, protected, err := inspectPrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !protected {
		t.Fatal("erwartet passphrase-geschuetzten Key")
	}
	return pemBytes, kp.PublicLine, fp
}

func TestApplySkipsPassphraseIdentityContinuesRest(t *testing.T) {
	dir := t.TempDir()
	passPEM, _, _ := passphrasePEM(t, "git", "secret-pass")
	okKey, err := keygen.Generate(keygen.TypeEd25519, "ok")
	if err != nil {
		t.Fatal(err)
	}
	localOther, err := keygen.Generate(keygen.TypeEd25519, "local-git")
	if err != nil {
		t.Fatal(err)
	}
	localPath := filepath.Join(dir, "id_ed25519-git")
	if err := os.WriteFile(localPath, localOther.PrivatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(managedBegin+"\n"+managedEnd+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	idPass := "id-pass"
	idOK := "id-ok"
	bundle := &store.SyncBundle{
		Identities: []store.Identity{
			{ID: idPass, Name: "id_ed25519-git"},
			{ID: idOK, Name: "id_ed25519"},
		},
		Hosts: []store.Host{
			{ID: "h1", Alias: "git", HostName: "git.example", IdentityID: &idPass},
			{ID: "h2", Alias: "srv", HostName: "srv.example", IdentityID: &idOK},
		},
	}
	keys := map[string][]byte{
		idPass: passPEM,
		idOK:   okKey.PrivatePEM,
	}

	res, err := Apply(dir, bundle, keys, ApplyOptions{AllowFirstWrite: true})
	if err != nil {
		t.Fatalf("Apply darf bei Passphrase-Identity nicht abbrechen: %v", err)
	}
	after, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("lokaler id_ed25519-git wurde veraendert")
	}
	if _, err := os.Stat(localPath + keyConflictSuffix); !os.IsNotExist(err) {
		t.Fatal("Passphrase-Identity darf keine Ausweichdatei anlegen")
	}
	okPath := filepath.Join(dir, "id_ed25519")
	gotOK, err := os.ReadFile(okPath)
	if err != nil {
		t.Fatal("normale Identity muss geschrieben werden")
	}
	if PrivateKeyMustFP(t, gotOK) != PrivateKeyMustFP(t, okKey.PrivatePEM) {
		t.Fatal("normale Identity falsch")
	}
	if len(res.SkippedIdentities) != 1 || !strings.Contains(res.SkippedIdentities[0], "id_ed25519-git") {
		t.Fatalf("SkippedIdentities=%v", res.SkippedIdentities)
	}
	if !strings.Contains(res.SkippedIdentities[0], "Passphrase") {
		t.Fatalf("SkipReason fehlt: %v", res.SkippedIdentities)
	}
	summary := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "1 Identity uebersprungen") && strings.Contains(w, "id_ed25519-git (Passphrase)") {
			summary = true
		}
	}
	if !summary {
		t.Fatalf("Zusammenfassung fehlt in Warnings: %v", res.Warnings)
	}
	cfg, _ := os.ReadFile(filepath.Join(dir, "config"))
	if !strings.Contains(string(cfg), "Host srv") {
		t.Fatal("Host der normalen Identity fehlt")
	}
	if strings.Contains(string(cfg), "IdentityFile") && strings.Contains(string(cfg), "id_ed25519-git") {
		t.Fatalf("IdentityFile fuer uebersprungene Passphrase-Identity unerwartet:\n%s", cfg)
	}
}

func TestApplyPassphraseIdentityMatchesLocalUsesPath(t *testing.T) {
	dir := t.TempDir()
	passPEM, pubLine, passFP := passphrasePEM(t, "same", "secret-pass")
	// Lokaler Key ohne Passphrase, gleicher Fingerabdruck: aus dem Klartext-Key vor Verschluesselung.
	// passPEM ist verschluesselt; wir brauchen denselben Key unverschluesselt lokal.
	// Erzeuge lokal aus Public-Vergleich: parse raw from a fresh pair is wrong.
	// Stattdessen: unverschluesselte Kopie mit gleichem Pub erzeugen indem wir
	// den Passphrase-Key nur fuer Server nutzen und lokal denselben Pub-Fingerprint
	// aus einem neu erzeugten Key... nein, Fingerabdruecke muessen matchen.
	// Loesung: unverschluesselte PEM aus demselben raw key speichern.
	raw, err := ssh.ParseRawPrivateKeyWithPassphrase(passPEM, []byte("secret-pass"))
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(raw, "same")
	if err != nil {
		t.Fatal(err)
	}
	localPEM := pem.EncodeToMemory(block)
	primary := filepath.Join(dir, "id_ed25519-git")
	if err := os.WriteFile(primary, localPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(primary+".pub", []byte(pubLine), 0o644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(primary)
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(managedBegin+"\n"+managedEnd+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id := "id-pass"
	bundle := &store.SyncBundle{
		Identities: []store.Identity{{ID: id, Name: "id_ed25519-git"}},
		Hosts:      []store.Host{{ID: "h1", Alias: "git", HostName: "git.example", IdentityID: &id}},
	}
	res, err := Apply(dir, bundle, map[string][]byte{id: passPEM}, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(primary)
	if string(after) != string(before) {
		t.Fatal("lokaler Key darf nicht veraendert werden")
	}
	if len(res.SkippedIdentities) != 0 {
		t.Fatalf("gleicher Fingerabdruck darf nicht als uebersprungen zaehlen: %v", res.SkippedIdentities)
	}
	if len(res.KeyPaths) != 1 {
		t.Fatalf("KeyPaths=%v", res.KeyPaths)
	}
	cfg, _ := os.ReadFile(filepath.Join(dir, "config"))
	if !strings.Contains(string(cfg), filepath.ToSlash(primary)) && !strings.Contains(string(cfg), primary) {
		t.Fatalf("IdentityFile auf lokalen Key erwartet:\n%s", cfg)
	}
	if PrivateKeyMustFP(t, localPEM) != passFP {
		t.Fatal("Testdaten: Fingerabdruecke passen nicht")
	}
}

func TestPrivateKeyFingerprintFromPassphraseKey(t *testing.T) {
	pemBytes, pubLine, _ := passphrasePEM(t, "fp", "x")
	fp, err := PrivateKeyFingerprint(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	pubFP, err := PublicKeyFingerprint([]byte(pubLine))
	if err != nil {
		t.Fatal(err)
	}
	if fp != pubFP {
		t.Fatalf("fp=%s pub=%s", fp, pubFP)
	}
}
