package releaseverify_test

import (
	"reflect"
	"testing"

	"github.com/thelad-dev/ssh-sync/internal/releaseverify"
	"github.com/thelad-dev/ssh-sync/internal/selfupdate"
)

// TestVerifyOptsExposesNoTrustOverrides ensures production callers cannot set
// CertificateIdentity or TrustedMaterial: those fields are unexported and only
// reachable from tests in package releaseverify.
func TestVerifyOptsExposesNoTrustOverrides(t *testing.T) {
	typ := reflect.TypeOf(releaseverify.VerifyOpts{})
	allowed := map[string]bool{
		"CurrentVersion": true,
		"AllowDowngrade": true,
	}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		if !allowed[f.Name] {
			t.Fatalf("exportiertes VerifyOpts-Feld %q darf Trust nicht ueberschreibbar machen", f.Name)
		}
		switch f.Type.String() {
		case "root.TrustedMaterial", "*verify.CertificateIdentity", "verify.CertificateIdentity":
			t.Fatalf("exportiertes Feld %q hat Trust-Typ %s", f.Name, f.Type.String())
		}
	}
	if _, ok := typ.FieldByName("TrustedMaterial"); ok {
		t.Fatal("TrustedMaterial darf nicht exportiert sein")
	}
	if _, ok := typ.FieldByName("CertificateIdentity"); ok {
		t.Fatal("CertificateIdentity darf nicht exportiert sein")
	}
	if f, ok := typ.FieldByName("trustedMaterial"); !ok || f.IsExported() {
		t.Fatal("trustedMaterial muss unexportiert existieren")
	}
	if f, ok := typ.FieldByName("certificateIdentity"); !ok || f.IsExported() {
		t.Fatal("certificateIdentity muss unexportiert existieren")
	}
}

// TestSelfUpdateOptionsExposesNoVerifyOverride keeps the verification hook
// unexported so production cannot swap out Sigstore checks.
func TestSelfUpdateOptionsExposesNoVerifyOverride(t *testing.T) {
	typ := reflect.TypeOf(selfupdate.Options{})
	if _, ok := typ.FieldByName("VerifyManifest"); ok {
		t.Fatal("VerifyManifest darf nicht exportiert sein")
	}
	if f, ok := typ.FieldByName("verifyManifest"); !ok || f.IsExported() {
		t.Fatal("verifyManifest muss unexportiert existieren")
	}
}
