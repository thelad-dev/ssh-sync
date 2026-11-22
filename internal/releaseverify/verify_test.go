package releaseverify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

func testIdentity(t *testing.T, issuer, sanRegex string, withRepoExt bool) verify.CertificateIdentity {
	t.Helper()
	san, err := verify.NewSANMatcher("", sanRegex)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := verify.NewIssuerMatcher(issuer, "")
	if err != nil {
		t.Fatal(err)
	}
	ext := certificate.Extensions{}
	if withRepoExt {
		ext.SourceRepositoryURI = SourceRepositoryURI
		ext.SourceRepositoryOwnerURI = SourceRepositoryOwnerURI
	}
	id, err := verify.NewCertificateIdentity(san, iss, ext)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func goodSAN(version string) string {
	return "https://github.com/thelad-dev/ssh-sync/.github/workflows/release.yml@refs/tags/v" + version
}

func sampleManifest(version, filename, hash string, size int64) []byte {
	m := Manifest{
		Version:    version,
		MinVersion: "1.0.0",
		Timestamp:  "2026-11-22T12:00:00Z",
		Assets: []ManifestAsset{{
			Platform: "linux/amd64",
			Filename: filename,
			SHA256:   hash,
			Size:     size,
		}},
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

func TestProductionCertificateIdentity(t *testing.T) {
	id, err := ProductionCertificateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if got := id.Issuer.Issuer; got != TrustedOIDCIssuer {
		t.Fatalf("issuer %q", got)
	}
	if id.SourceRepositoryURI != SourceRepositoryURI {
		t.Fatalf("repo uri %q", id.SourceRepositoryURI)
	}
	if id.SourceRepositoryOwnerURI != SourceRepositoryOwnerURI {
		t.Fatalf("owner uri %q", id.SourceRepositoryOwnerURI)
	}
}

func TestVerifySignedEntityValid(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 2048)
	for i := range payload {
		payload[i] = byte(i)
	}
	sum := sha256.Sum256(payload)
	manifestBytes := sampleManifest("1.2.3", "ssh-sync-linux-amd64", hex.EncodeToString(sum[:]), int64(len(payload)))

	identity := goodSAN("1.2.3")
	entity, err := vs.Sign(identity, TrustedOIDCIssuer, manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	certID := testIdentity(t, TrustedOIDCIssuer, SubjectSANRegex, false)
	got, err := VerifySignedEntity(manifestBytes, entity, VerifyOpts{
		CurrentVersion:      "1.0.0",
		TrustedMaterial:     vs,
		CertificateIdentity: &certID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "1.2.3" {
		t.Fatalf("version %s", got.Version)
	}
	dir := t.TempDir()
	asset := filepath.Join(dir, "ssh-sync-linux-amd64")
	if err := os.WriteFile(asset, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAssetHash(got, "ssh-sync-linux-amd64", asset); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySignedEntityWrongIdentity(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("x"))
	manifestBytes := sampleManifest("1.2.3", "a.bin", hex.EncodeToString(sum[:]), 1)
	entity, err := vs.Sign("https://github.com/evil/other/.github/workflows/release.yml@refs/tags/v1.2.3", TrustedOIDCIssuer, manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	certID := testIdentity(t, TrustedOIDCIssuer, SubjectSANRegex, false)
	if _, err := VerifySignedEntity(manifestBytes, entity, VerifyOpts{
		TrustedMaterial:     vs,
		CertificateIdentity: &certID,
	}); err == nil {
		t.Fatal("expected identity rejection")
	}
}

func TestVerifySignedEntityWrongIssuer(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("x"))
	manifestBytes := sampleManifest("1.2.3", "a.bin", hex.EncodeToString(sum[:]), 1)
	entity, err := vs.Sign(goodSAN("1.2.3"), "https://evil.example/oidc", manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	certID := testIdentity(t, TrustedOIDCIssuer, SubjectSANRegex, false)
	if _, err := VerifySignedEntity(manifestBytes, entity, VerifyOpts{
		TrustedMaterial:     vs,
		CertificateIdentity: &certID,
	}); err == nil {
		t.Fatal("expected issuer rejection")
	}
}

func TestVerifySignedEntityManipulatedManifest(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("x"))
	manifestBytes := sampleManifest("1.2.3", "a.bin", hex.EncodeToString(sum[:]), 1)
	entity, err := vs.Sign(goodSAN("1.2.3"), TrustedOIDCIssuer, manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	tampered := sampleManifest("9.9.9", "a.bin", hex.EncodeToString(sum[:]), 1)
	certID := testIdentity(t, TrustedOIDCIssuer, SubjectSANRegex, false)
	if _, err := VerifySignedEntity(tampered, entity, VerifyOpts{
		TrustedMaterial:     vs,
		CertificateIdentity: &certID,
	}); err == nil {
		t.Fatal("expected manipulated manifest rejection")
	}
}

func TestVerifySignedEntityExpired(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("x"))
	manifestBytes := sampleManifest("1.2.3", "a.bin", hex.EncodeToString(sum[:]), 1)
	// Leaf cert from VirtualSigstore is valid for ~10 minutes from Now;
	// integrate far in the future so the observer timestamp is outside NotAfter.
	entity, err := vs.SignAtTime(goodSAN("1.2.3"), TrustedOIDCIssuer, manifestBytes, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	certID := testIdentity(t, TrustedOIDCIssuer, SubjectSANRegex, false)
	if _, err := VerifySignedEntity(manifestBytes, entity, VerifyOpts{
		TrustedMaterial:     vs,
		CertificateIdentity: &certID,
	}); err == nil {
		t.Fatal("expected expired certificate rejection")
	}
}

func TestVerifySignedEntityDowngrade(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("x"))
	manifestBytes := sampleManifest("1.2.3", "a.bin", hex.EncodeToString(sum[:]), 1)
	entity, err := vs.Sign(goodSAN("1.2.3"), TrustedOIDCIssuer, manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	certID := testIdentity(t, TrustedOIDCIssuer, SubjectSANRegex, false)
	if _, err := VerifySignedEntity(manifestBytes, entity, VerifyOpts{
		CurrentVersion:      "2.0.0",
		TrustedMaterial:     vs,
		CertificateIdentity: &certID,
	}); err == nil || !strings.Contains(err.Error(), "kein neueres") {
		t.Fatalf("expected downgrade rejection, got %v", err)
	}
	if _, err := VerifySignedEntity(manifestBytes, entity, VerifyOpts{
		CurrentVersion:      "2.0.0",
		AllowDowngrade:      true,
		TrustedMaterial:     vs,
		CertificateIdentity: &certID,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyManifestBundleMissing(t *testing.T) {
	if _, err := VerifyManifestBundle([]byte(`{"version":"1.0.0","assets":[]}`), nil, VerifyOpts{}); err == nil {
		t.Fatal("expected missing bundle")
	}
	if _, err := VerifyManifestBundle(nil, []byte(`{}`), VerifyOpts{}); err == nil {
		t.Fatal("expected missing manifest")
	}
}

func TestEmbeddedTrustedRoot(t *testing.T) {
	tr, err := EmbeddedTrustedRoot()
	if err != nil {
		t.Fatal(err)
	}
	if tr == nil {
		t.Fatal("nil trusted root")
	}
}
