package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestValidateJWTSecretRejectsWeakValues(t *testing.T) {
	cases := []string{
		"",
		"short",
		"change-me-in-production",
		"bitte-durch-ein-langes-zufaelliges-secret-ersetzen",
	}
	for _, c := range cases {
		if err := ValidateJWTSecret(c); err == nil {
			t.Fatalf("expected reject for %q", c)
		}
	}
	ok := strings.Repeat("a", 32)
	if err := ValidateJWTSecret(ok); err != nil {
		t.Fatal(err)
	}
}

func TestJWTSecretEnvWeakFails(t *testing.T) {
	t.Setenv("SSH_SYNC_JWT_SECRET", "change-me-in-production")
	if _, err := JWTSecret(t.TempDir()); err == nil {
		t.Fatal("expected weak env secret to fail")
	}
}

func TestJWTSecretPersistsWithoutLoggingValue(t *testing.T) {
	t.Setenv("SSH_SYNC_JWT_SECRET", "")
	_ = os.Unsetenv("SSH_SYNC_JWT_SECRET")
	dir := t.TempDir()
	secret, err := JWTSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) < MinJWTSecretLen {
		t.Fatalf("secret too short: %d", len(secret))
	}
	path := filepath.Join(dir, "jwt.secret")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != string(secret) {
		t.Fatal("persisted secret mismatch")
	}
	again, err := JWTSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(secret) {
		t.Fatal("reload mismatch")
	}
}

func TestParseTokenRequiresExp(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		Scope: ScopeUser,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	})
	signed, err := tok.SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseToken(secret, signed); err == nil {
		t.Fatal("token without exp must be rejected")
	}
}
