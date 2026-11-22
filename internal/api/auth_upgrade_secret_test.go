package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/auth"
	"github.com/thelad-dev/ssh-sync/internal/crypto"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

// Fingerabdruck auth.upgrade.legacy-verifier-without-current-secret:
// Ohne aktuelles Legacy-Passwort (oder Setup-Token) darf Scheme/Hash nicht wechseln.
func TestUpgradeRejectsWithoutCurrentSecret(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/upgrade-secret.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	salt := bytes.Repeat([]byte{0x22}, crypto.SaltLen)
	legacyPW := "legacy-master-12"
	hash, err := auth.HashPassword(legacyPW)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUserWithScheme(hash, salt, store.AuthSchemeLegacy); err != nil {
		t.Fatal(err)
	}

	secret := []byte("test-secret-for-jwt-signing-ok")
	srv := NewServer(st, secret)
	token, err := auth.IssueUserToken(secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	attackerKey := bytes.Repeat([]byte{0x22}, crypto.KeyLen)
	upBody, _ := json.Marshal(map[string]any{
		"auth_key":   hex.EncodeToString(attackerKey),
		"identities": []any{},
	})
	upReq := httptest.NewRequest(http.MethodPost, "/api/auth/upgrade", bytes.NewReader(upBody))
	upReq.Header.Set("Authorization", "Bearer "+token)
	upRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(upRec, upReq)
	if upRec.Code == http.StatusOK {
		t.Fatalf("upgrade ohne Geheimnisnachweis darf nicht 200 sein, got %d %s", upRec.Code, upRec.Body.String())
	}

	user, err := st.GetUser()
	if err != nil {
		t.Fatal(err)
	}
	if user.AuthScheme != store.AuthSchemeLegacy {
		t.Fatalf("scheme unveraendert erwartet, got %q", user.AuthScheme)
	}
	if !auth.CheckPassword(user.PasswordHash, legacyPW) {
		t.Fatal("Legacy-Passwort-Hash darf nicht getauscht werden")
	}
	if auth.CheckPassword(user.PasswordHash, hex.EncodeToString(attackerKey)) {
		t.Fatal("Angreifer-auth_key darf nicht als Login gelten")
	}
}

func TestUpgradeWithCurrentPasswordSucceeds(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/upgrade-ok.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	salt := bytes.Repeat([]byte{0x33}, crypto.SaltLen)
	legacyPW := "legacy-master-12"
	hash, err := auth.HashPassword(legacyPW)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUserWithScheme(hash, salt, store.AuthSchemeLegacy); err != nil {
		t.Fatal(err)
	}
	keys := crypto.DeriveKeys(legacyPW, salt)

	secret := []byte("test-secret-for-jwt-signing-ok")
	srv := NewServer(st, secret)
	token, err := auth.IssueUserToken(secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	upBody, _ := json.Marshal(map[string]any{
		"auth_key":   hex.EncodeToString(keys.AuthKey),
		"password":   legacyPW,
		"identities": []any{},
	})
	upReq := httptest.NewRequest(http.MethodPost, "/api/auth/upgrade", bytes.NewReader(upBody))
	upReq.Header.Set("Authorization", "Bearer "+token)
	upRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(upRec, upReq)
	if upRec.Code != http.StatusOK {
		t.Fatalf("upgrade mit Passwort: %d %s", upRec.Code, upRec.Body.String())
	}
	user, err := st.GetUser()
	if err != nil {
		t.Fatal(err)
	}
	if user.AuthScheme != store.AuthSchemeV1 {
		t.Fatalf("scheme=%q", user.AuthScheme)
	}
	if !auth.CheckPassword(user.PasswordHash, hex.EncodeToString(keys.AuthKey)) {
		t.Fatal("nach Upgrade muss auth_key gelten")
	}
}
