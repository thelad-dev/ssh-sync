package releaseverify

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.1", -1},
		{"1.2.0", "1.1.9", 1},
		{"0.1.0-dev", "0.1.0", -1},
		{"2.0.0", "2.0.0", 0},
	}
	for _, tc := range cases {
		got, err := CompareVersions(tc.a, tc.b)
		if err != nil {
			t.Fatalf("%s vs %s: %v", tc.a, tc.b, err)
		}
		if got != tc.want {
			t.Fatalf("%s vs %s: got %d want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCheckServerURL(t *testing.T) {
	if err := CheckServerURL("https://portal.example", false); err != nil {
		t.Fatal(err)
	}
	if err := CheckServerURL("http://127.0.0.1:8080", false); err != nil {
		t.Fatal(err)
	}
	if err := CheckServerURL("http://portal.example", false); err == nil {
		t.Fatal("expected http rejection")
	}
	if err := CheckServerURL("http://portal.example", true); err != nil {
		t.Fatal(err)
	}
}

func TestSanitizeInstallBaseURL(t *testing.T) {
	got, err := SanitizeInstallBaseURL("https", "portal.example")
	if err != nil || got != "https://portal.example" {
		t.Fatalf("got %q %v", got, err)
	}
	if _, err := SanitizeInstallBaseURL("https", "x$(id)"); err == nil {
		t.Fatal("expected reject")
	}
	if _, err := SanitizeInstallBaseURL("ftp", "x"); err == nil {
		t.Fatal("expected reject scheme")
	}
}

func TestParseManifestAndAssetHash(t *testing.T) {
	dir := t.TempDir()
	asset := filepath.Join(dir, "ssh-sync-linux-amd64")
	payload := make([]byte, 2048)
	for i := range payload {
		payload[i] = byte(i)
	}
	if err := os.WriteFile(asset, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	raw := sampleManifest("1.2.3", "ssh-sync-linux-amd64", hex.EncodeToString(sum[:]), int64(len(payload)))
	m, err := ParseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAssetHash(m, "ssh-sync-linux-amd64", asset); err != nil {
		t.Fatal(err)
	}
}

func TestPublicKeyPEMRemoved(t *testing.T) {
	if _, err := PublicKeyPEM(); err == nil {
		t.Fatal("expected error without Ed25519 key")
	}
}
