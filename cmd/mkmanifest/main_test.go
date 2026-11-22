package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPlatformFromFilename(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"ssh-sync-linux-amd64", "linux-amd64"},
		{"ssh-sync-linux-arm64", "linux-arm64"},
		{"ssh-sync-darwin-amd64", "darwin-amd64"},
		{"ssh-sync-darwin-arm64", "darwin-arm64"},
		{"ssh-sync-windows-amd64.exe", "windows-amd64"},
	}
	for _, tc := range cases {
		got, err := platformFromFilename(tc.name)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
	if _, err := platformFromFilename("SHA256SUMS"); err == nil {
		t.Fatal("expected error for SHA256SUMS")
	}
	if _, err := platformFromFilename("ssh-sync-windows-amd64.zip"); err == nil {
		t.Fatal("expected error for zip")
	}
}

func TestWriteManifest(t *testing.T) {
	dir := t.TempDir()
	body := []byte("fake-binary-content")
	name := "ssh-sync-linux-amd64"
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ssh-sync-windows-amd64.zip"), []byte("z"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writeManifest(dir, "1.2.3", "1.0.0", "2026-11-22T12:00:00Z"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		t.Fatal(err)
	}
	var got manifest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != "1.2.3" || got.MinVersion != "1.0.0" || got.Timestamp != "2026-11-22T12:00:00Z" {
		t.Fatalf("meta: %+v", got)
	}
	if len(got.Artifacts) != 1 {
		t.Fatalf("artifacts: %d", len(got.Artifacts))
	}
	sum := sha256.Sum256(body)
	wantHash := hex.EncodeToString(sum[:])
	a := got.Artifacts[0]
	if a.Platform != "linux-amd64" || a.Filename != name || a.SHA256 != wantHash || a.Size != int64(len(body)) {
		t.Fatalf("artifact: %+v", a)
	}
}

func TestWriteManifestRequiresBinaries(t *testing.T) {
	dir := t.TempDir()
	if err := writeManifest(dir, "1.0.0", "", "2026-11-22T12:00:00Z"); err == nil {
		t.Fatal("expected error without binaries")
	}
}
