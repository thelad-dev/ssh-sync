package releaseverify

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// VerifyOpts controls downgrade protection for release verification.
// Identity and trusted root cannot be overridden from outside this package;
// test code in package releaseverify may set the unexported fields.
type VerifyOpts struct {
	// CurrentVersion is the installed agent version. Empty skips the upgrade check.
	CurrentVersion string
	// AllowDowngrade permits installing a version that is not strictly newer.
	AllowDowngrade bool

	// trustedMaterial overrides the embedded public-good root (tests in this package only).
	trustedMaterial root.TrustedMaterial
	// certificateIdentity overrides the production GitHub Actions identity (tests only).
	certificateIdentity *verify.CertificateIdentity
}

// ProductionCertificateIdentity builds the Fulcio identity policy for ssh-sync releases.
func ProductionCertificateIdentity() (verify.CertificateIdentity, error) {
	return verify.NewCertificateIdentity(
		mustSANRegex(SubjectSANRegex),
		mustIssuer(TrustedOIDCIssuer),
		certificate.Extensions{
			SourceRepositoryURI:      SourceRepositoryURI,
			SourceRepositoryOwnerURI: SourceRepositoryOwnerURI,
		},
	)
}

func mustSANRegex(re string) verify.SubjectAlternativeNameMatcher {
	m, err := verify.NewSANMatcher("", re)
	if err != nil {
		panic(err)
	}
	return m
}

func mustIssuer(issuer string) verify.IssuerMatcher {
	m, err := verify.NewIssuerMatcher(issuer, "")
	if err != nil {
		panic(err)
	}
	return m
}

// VerifyManifestBundle verifies manifest.json against a Sigstore protobuf bundle (JSON).
// Fail-closed: any verification error rejects the release.
func VerifyManifestBundle(manifestBytes, bundleBytes []byte, opts VerifyOpts) (*Manifest, error) {
	if len(manifestBytes) == 0 {
		return nil, fmt.Errorf("manifest fehlt")
	}
	if len(bundleBytes) == 0 {
		return nil, fmt.Errorf("Sigstore-Bundle fehlt")
	}

	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleBytes); err != nil {
		return nil, fmt.Errorf("Sigstore-Bundle: %w", err)
	}
	if !b.MinVersion("0.3") {
		return nil, fmt.Errorf("Sigstore-Bundle: Version unter 0.3")
	}
	return verifySignedEntity(manifestBytes, &b, opts)
}

// verifySignedEntity verifies a signed entity (bundle or test entity) over manifest bytes.
func verifySignedEntity(manifestBytes []byte, entity verify.SignedEntity, opts VerifyOpts) (*Manifest, error) {
	material := opts.trustedMaterial
	if material == nil {
		tr, err := EmbeddedTrustedRoot()
		if err != nil {
			return nil, err
		}
		material = tr
	}

	identity := opts.certificateIdentity
	if identity == nil {
		id, err := ProductionCertificateIdentity()
		if err != nil {
			return nil, err
		}
		identity = &id
	}

	verifier, err := verify.NewVerifier(
		material,
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("Sigstore-Verifier: %w", err)
	}

	policy := verify.NewPolicy(
		verify.WithArtifact(bytes.NewReader(manifestBytes)),
		verify.WithCertificateIdentity(*identity),
	)
	if _, err := verifier.Verify(entity, policy); err != nil {
		return nil, fmt.Errorf("Sigstore-Verifikation fehlgeschlagen: %w", err)
	}

	m, err := ParseManifest(manifestBytes)
	if err != nil {
		return nil, err
	}
	if err := CheckUpgrade(m, opts.CurrentVersion, opts.AllowDowngrade); err != nil {
		return nil, err
	}
	return m, nil
}

// CheckUpgrade enforces downgrade protection against the installed version.
func CheckUpgrade(m *Manifest, currentVersion string, allowDowngrade bool) error {
	if m == nil {
		return fmt.Errorf("manifest fehlt")
	}
	if strings.TrimSpace(m.MinVersion) != "" {
		cmpMin, err := CompareVersions(m.Version, m.MinVersion)
		if err != nil {
			return err
		}
		if cmpMin < 0 {
			return fmt.Errorf("manifest version %s unter min_version %s", m.Version, m.MinVersion)
		}
	}
	if strings.TrimSpace(currentVersion) == "" {
		return nil
	}
	cmp, err := CompareVersions(m.Version, currentVersion)
	if err != nil {
		return err
	}
	if allowDowngrade {
		return nil
	}
	if cmp <= 0 {
		return fmt.Errorf("kein neueres Release (manifest %s, lokal %s)", m.Version, currentVersion)
	}
	return nil
}
