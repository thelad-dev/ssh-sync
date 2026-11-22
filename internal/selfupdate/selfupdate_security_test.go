package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

func TestApplyRejectsBadBundleWrongHashAndStaleVersion(t *testing.T) {
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
		Assets: []releaseverify.ManifestAsset{{
			Platform: "test",
			Filename: assetName,
			SHA256:   hashHex,
			Size:     int64(len(goodPayload)),
		}},
	}
	canon, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	goodBundle := []byte(`{"good":true}`)

	verifyOK := func(manifestBytes, bundleBytes []byte, currentVersion string, allowDowngrade bool) (*releaseverify.Manifest, error) {
		if string(bundleBytes) != string(goodBundle) {
			return nil, fmt.Errorf("Signatur ungueltig")
		}
		m, err := releaseverify.ParseManifest(manifestBytes)
		if err != nil {
			return nil, err
		}
		if err := releaseverify.CheckUpgrade(m, currentVersion, allowDowngrade); err != nil {
			return nil, err
		}
		return m, nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/downloads/"+releaseverify.ManifestName, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(canon)
	})
	mux.HandleFunc("/downloads/"+releaseverify.BundleName, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(goodBundle)
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

	_, err = Apply(Options{
		ServerURL:      ts.URL,
		DestPath:       dest,
		CurrentVersion: "2.0.0",
		Insecure:       true,
		VerifyManifest: verifyOK,
	})
	if err == nil || !strings.Contains(err.Error(), "kein neueres") {
		t.Fatalf("stale version: %v", err)
	}

	muxBad := http.NewServeMux()
	muxBad.HandleFunc("/downloads/"+releaseverify.ManifestName, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(canon)
	})
	muxBad.HandleFunc("/downloads/"+releaseverify.BundleName, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"bad":true}`))
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
		VerifyManifest: verifyOK,
	})
	if err == nil || !strings.Contains(err.Error(), "Signatur") {
		t.Fatalf("bad bundle: %v", err)
	}

	evil := make([]byte, 2048)
	for i := range evil {
		evil[i] = 'X'
	}
	muxHash := http.NewServeMux()
	muxHash.HandleFunc("/downloads/"+releaseverify.ManifestName, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(canon)
	})
	muxHash.HandleFunc("/downloads/"+releaseverify.BundleName, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(goodBundle)
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
		VerifyManifest: verifyOK,
	})
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("wrong hash: %v", err)
	}

	res, err := Apply(Options{
		ServerURL:      ts.URL,
		DestPath:       dest,
		CurrentVersion: "1.0.0",
		Insecure:       true,
		VerifyManifest: verifyOK,
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

func TestApplyMissingBundleFailClosed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/downloads/"+releaseverify.ManifestName, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":"2.0.0","assets":[{"filename":"x","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1}]}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	dir := t.TempDir()
	dest := filepath.Join(dir, "ssh-sync")
	if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Apply(Options{
		ServerURL:      ts.URL,
		DestPath:       dest,
		CurrentVersion: "1.0.0",
		Insecure:       true,
	})
	if err == nil {
		t.Fatal("expected missing bundle failure")
	}
}
