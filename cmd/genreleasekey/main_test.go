package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteAndReadSeedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh-sync-release.seed")
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	if err := writeSeedFile(path, seed); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("seed file mode too open: %v", info.Mode())
	}
	got, err := readSeedFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(seed) {
		t.Fatal("seed mismatch")
	}
	priv := ed25519.NewKeyFromSeed(got)
	pubHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	if len(pubHex) != 64 {
		t.Fatalf("public hex length %d", len(pubHex))
	}
	if strings.Contains(pubHex, "\n") {
		t.Fatal("unexpected newline in pub hex")
	}
}

func TestReadSeedRejectsWrongLength(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.seed")
	if err := os.WriteFile(path, []byte("abcd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSeedFile(path); err == nil {
		t.Fatal("expected length error")
	}
}

// TestOpenSSLPublicKeyMatchesGo prueft, dass derselbe Seed denselben Public Key
// ergibt wie Go ed25519.NewKeyFromSeed und der OpenSSL-PKCS#8-Weg in
// scripts/gen-release-key.sh (Praefix 302e020100300506032b657004220420).
func TestOpenSSLPublicKeyMatchesGo(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl nicht installiert")
	}
	out, err := exec.Command("openssl", "version").CombinedOutput()
	if err != nil {
		t.Skipf("openssl version: %v", err)
	}
	// "OpenSSL 3.0.22 ..."
	fields := strings.Fields(string(out))
	if len(fields) < 2 || !strings.HasPrefix(fields[1], "3") {
		t.Skipf("openssl >= 3 erforderlich, got %q", strings.TrimSpace(string(out)))
	}

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	wantPub := hex.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))

	const pkcs8Prefix = "302e020100300506032b657004220420"
	derPath := filepath.Join(t.TempDir(), "seed.pkcs8.der")
	der, err := hex.DecodeString(pkcs8Prefix + hex.EncodeToString(seed))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(derPath, der, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("openssl", "pkey", "-inform", "DER", "-in", derPath, "-pubout", "-outform", "DER")
	pubDER, err := cmd.Output()
	if err != nil {
		t.Fatalf("openssl pkey: %v", err)
	}
	if len(pubDER) < 32 {
		t.Fatalf("pub DER too short: %d", len(pubDER))
	}
	gotPub := hex.EncodeToString(pubDER[len(pubDER)-32:])
	if gotPub != wantPub {
		t.Fatalf("public key mismatch\n go:      %s\n openssl: %s", wantPub, gotPub)
	}

	// Zweiter bekannter Seed: Roundtrip ueber Seed-Datei und Go-Ableitung.
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "test.seed")
	if err := writeSeedFile(seedPath, seed); err != nil {
		t.Fatal(err)
	}
	gotSeed, err := readSeedFile(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotSeed, seed) {
		t.Fatal("seed file roundtrip mismatch")
	}
	fromFile := hex.EncodeToString(ed25519.NewKeyFromSeed(gotSeed).Public().(ed25519.PublicKey))
	if fromFile != wantPub {
		t.Fatalf("seed-file derived pub mismatch: %s vs %s", fromFile, wantPub)
	}
}
