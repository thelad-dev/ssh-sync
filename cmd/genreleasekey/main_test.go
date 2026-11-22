package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
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
