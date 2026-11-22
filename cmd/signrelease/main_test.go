package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/thelad-dev/ssh-sync/internal/releaseverify"
)

func TestLoadPrivateKeySeedAndFull(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seedPath := filepath.Join(dir, "seed")
	fullPath := filepath.Join(dir, "full")
	if err := os.WriteFile(seedPath, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte(hex.EncodeToString(priv)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gotSeed, err := loadPrivateKey(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	gotFull, err := loadPrivateKey(fullPath)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(gotSeed.Public().(ed25519.PublicKey)) {
		t.Fatal("seed-derived public key mismatch")
	}
	if !pub.Equal(gotFull.Public().(ed25519.PublicKey)) {
		t.Fatal("full private key public mismatch")
	}
}

func TestSignVerifyDirRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := releaseverify.PublicKey
	releaseverify.PublicKey = pub
	t.Cleanup(func() { releaseverify.PublicKey = old })

	dir := t.TempDir()
	asset := filepath.Join(dir, "ssh-sync-linux-amd64")
	if err := os.WriteFile(asset, []byte("agent-binary-payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "key.seed")
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
		t.Fatal(err)
	}

	gotPriv, err := loadPrivateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := releaseverify.FileSHA256(asset)
	if err != nil {
		t.Fatal(err)
	}
	m := releaseverify.Manifest{
		Version: "9.9.9",
		Assets:  map[string]string{"ssh-sync-linux-amd64": hash},
	}
	canon, sig, err := releaseverify.SignManifest(m, gotPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, releaseverify.ManifestName), canon, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, releaseverify.SigName), sig, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyDir(dir); err != nil {
		t.Fatal(err)
	}

	// Tamper asset -> verify must fail.
	if err := os.WriteFile(asset, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyDir(dir); err == nil {
		t.Fatal("expected hash failure after tamper")
	}
}

func TestVerifyDirRejectsBadSig(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := releaseverify.PublicKey
	releaseverify.PublicKey = pub
	t.Cleanup(func() { releaseverify.PublicKey = old })

	dir := t.TempDir()
	asset := filepath.Join(dir, "a.bin")
	if err := os.WriteFile(asset, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	hash, err := releaseverify.FileSHA256(asset)
	if err != nil {
		t.Fatal(err)
	}
	m := releaseverify.Manifest{Version: "0.0.1", Assets: map[string]string{"a.bin": hash}}
	canon, sig, err := releaseverify.SignManifest(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0xff
	if err := os.WriteFile(filepath.Join(dir, releaseverify.ManifestName), canon, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, releaseverify.SigName), sig, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyDir(dir); err == nil {
		t.Fatal("expected signature failure")
	}
}
