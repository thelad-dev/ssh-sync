package selfupdate

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thelad-dev/ssh-sync/internal/releaseverify"
)

func TestApplyRejectsHTTPWithoutInsecure(t *testing.T) {
	_, err := Apply(Options{
		ServerURL:      "http://evil.example:8080",
		CurrentVersion: "0.1.0",
	})
	if err == nil || !strings.Contains(err.Error(), "http://") {
		t.Fatalf("expected http rejection, got %v", err)
	}
}

func TestApplyRejectsBadSignatureWrongHashAndStaleVersion(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := releaseverify.PublicKey
	releaseverify.PublicKey = pub
	t.Cleanup(func() { releaseverify.PublicKey = old })

	assetName := "ssh-sync-linux-amd64"
	if n, err := AssetName(); err == nil {
		assetName = n
	}

	goodPayload := make([]byte, 2048)
	for i := range goodPayload {
		goodPayload[i] = 'A'
	}
	sum := sha256.Sum256(goodPayload)
	hashHex := hex.EncodeToString(sum[:])

	manifest := releaseverify.Manifest{
		Version: "2.0.0",
		Assets:  map[string]string{assetName: hashHex},
	}
	canon, sig, err := releaseverify.SignManifest(manifest, priv)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/downloads/"+releaseverify.ManifestName, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(canon)
	})
	mux.HandleFunc("/downloads/"+releaseverify.SigName, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(sig)
	})
	mux.HandleFunc("/downloads/"+assetName, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(goodPayload)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	dir := t.TempDir()
	dest := filepath.Join(dir, "ssh-sync")
	if err := os.WriteFile(dest, []byte("#!/bin/sh\necho old\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Stale / equal version
	_, err = Apply(Options{
		ServerURL:      ts.URL,
		DestPath:       dest,
		CurrentVersion: "2.0.0",
		Insecure:       true,
	})
	if err == nil || !strings.Contains(err.Error(), "kein neueres") {
		t.Fatalf("stale version: %v", err)
	}

	// Bad signature
	badSig := append([]byte{}, sig...)
	badSig[3] ^= 0xaa
	muxBad := http.NewServeMux()
	muxBad.HandleFunc("/downloads/"+releaseverify.ManifestName, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(canon)
	})
	muxBad.HandleFunc("/downloads/"+releaseverify.SigName, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(badSig)
	})
	muxBad.HandleFunc("/downloads/"+assetName, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(goodPayload)
	})
	tsBad := httptest.NewServer(muxBad)
	t.Cleanup(tsBad.Close)
	_, err = Apply(Options{
		ServerURL:      tsBad.URL,
		DestPath:       dest,
		CurrentVersion: "1.0.0",
		Insecure:       true,
	})
	if err == nil || !strings.Contains(err.Error(), "Signatur") {
		t.Fatalf("bad sig: %v", err)
	}

	// Wrong hash (payload swapped)
	evil := make([]byte, 2048)
	for i := range evil {
		evil[i] = 'X'
	}
	muxHash := http.NewServeMux()
	muxHash.HandleFunc("/downloads/"+releaseverify.ManifestName, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(canon)
	})
	muxHash.HandleFunc("/downloads/"+releaseverify.SigName, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(sig)
	})
	muxHash.HandleFunc("/downloads/"+assetName, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(evil)
	})
	tsHash := httptest.NewServer(muxHash)
	t.Cleanup(tsHash.Close)
	_, err = Apply(Options{
		ServerURL:      tsHash.URL,
		DestPath:       dest,
		CurrentVersion: "1.0.0",
		Insecure:       true,
	})
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("wrong hash: %v", err)
	}

	// Happy path
	res, err := Apply(Options{
		ServerURL:      ts.URL,
		DestPath:       dest,
		CurrentVersion: "1.0.0",
		Insecure:       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Version != "2.0.0" {
		t.Fatalf("version %s", res.Version)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(goodPayload) {
		t.Fatal("binary not replaced")
	}
}
