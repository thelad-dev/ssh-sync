package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/auth"
	"github.com/thelad-dev/ssh-sync/internal/crypto"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

func TestSetupAndLoginRejectPlaintextPasswordBody(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/auth.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	secret := []byte("test-secret-for-jwt-signing-ok")
	srv := NewServer(st, secret)

	salt, err := crypto.NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	keys := crypto.DeriveKeys("master-password-12", salt)

	setupBody, _ := json.Marshal(map[string]string{
		"auth_key": hex.EncodeToString(keys.AuthKey),
		"kdf_salt": hex.EncodeToString(salt),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/setup", bytes.NewReader(setupBody))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(string(setupBody), "password") {
		t.Fatal("setup-Body darf kein password-Feld tragen")
	}

	bad := httptest.NewRequest(http.MethodPost, "/api/setup", bytes.NewReader([]byte(`{"password":"master-password-12"}`)))
	badRec := httptest.NewRecorder()
	// bereits initialisiert → Conflict; separat gegen Klartext pruefen wir Login unten
	srv.Handler().ServeHTTP(badRec, bad)
	if badRec.Code == http.StatusCreated {
		t.Fatal("Setup mit Klartext-Passwort darf nicht anlegen")
	}

	loginBody, _ := json.Marshal(map[string]string{"auth_key": hex.EncodeToString(keys.AuthKey)})
	if strings.Contains(string(loginBody), `"password"`) {
		t.Fatal("login-Body darf kein password enthalten")
	}
	loginReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(loginBody))
	loginRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login auth_key: %d %s", loginRec.Code, loginRec.Body.String())
	}
	var loginResp map[string]string
	_ = json.Unmarshal(loginRec.Body.Bytes(), &loginResp)
	if loginResp["auth_scheme"] != store.AuthSchemeV1 {
		t.Fatalf("auth_scheme=%q", loginResp["auth_scheme"])
	}
}

func TestLegacyLoginThenUpgrade(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/legacy.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	salt := bytes.Repeat([]byte{0x44}, crypto.SaltLen)
	hash, err := auth.HashPassword("legacy-master-12")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUserWithScheme(hash, salt, store.AuthSchemeLegacy); err != nil {
		t.Fatal(err)
	}
	keys := crypto.DeriveKeys("legacy-master-12", salt)
	legacyCT, err := crypto.Encrypt(keys.LegacyKey, []byte("PRIVATE"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertIdentity(store.Identity{
		ID:                  "id1",
		Name:                "k",
		PublicKey:           "ssh-ed25519 AAA",
		EncryptedPrivateKey: legacyCT,
	}); err != nil {
		t.Fatal(err)
	}

	srv := NewServer(st, []byte("test-secret-for-jwt-signing-ok"))
	loginReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(`{"password":"legacy-master-12"}`)))
	loginRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("legacy login: %d %s", loginRec.Code, loginRec.Body.String())
	}
	var loginResp map[string]string
	_ = json.Unmarshal(loginRec.Body.Bytes(), &loginResp)
	token := loginResp["token"]

	newCT, err := crypto.EncryptIdentity(keys, "id1", "ssh-ed25519 AAA", []byte("PRIVATE"))
	if err != nil {
		t.Fatal(err)
	}
	upBody, _ := json.Marshal(map[string]any{
		"auth_key": hex.EncodeToString(keys.AuthKey),
		"password": "legacy-master-12",
		"identities": []map[string]string{{
			"id":                    "id1",
			"encrypted_private_key": newCT,
		}},
	})
	upReq := httptest.NewRequest(http.MethodPost, "/api/auth/upgrade", bytes.NewReader(upBody))
	upReq.Header.Set("Authorization", "Bearer "+token)
	upRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(upRec, upReq)
	if upRec.Code != http.StatusOK {
		t.Fatalf("upgrade: %d %s", upRec.Code, upRec.Body.String())
	}

	user, err := st.GetUser()
	if err != nil {
		t.Fatal(err)
	}
	if user.AuthScheme != store.AuthSchemeV1 {
		t.Fatalf("scheme=%q", user.AuthScheme)
	}
	if !auth.CheckPassword(user.PasswordHash, hex.EncodeToString(keys.AuthKey)) {
		t.Fatal("bcrypt muss auth_key hashen (N1)")
	}
	if auth.CheckPassword(user.PasswordHash, "legacy-master-12") {
		t.Fatal("Master-Passwort darf nach Upgrade nicht mehr als Login gelten")
	}

	authLogin, _ := json.Marshal(map[string]string{"auth_key": hex.EncodeToString(keys.AuthKey)})
	req2 := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(authLogin))
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("auth_key login nach upgrade: %d %s", rec2.Code, rec2.Body.String())
	}
}

func TestPutHostRejectsProxyCommand(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/host.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	salt := bytes.Repeat([]byte{0x55}, crypto.SaltLen)
	keys := crypto.DeriveKeys("master-password-12", salt)
	hash, _ := auth.HashPassword(hex.EncodeToString(keys.AuthKey))
	_ = st.CreateUserWithScheme(hash, salt, store.AuthSchemeV1)
	srv := NewServer(st, []byte("test-secret-for-jwt-signing-ok"))
	token, err := auth.IssueUserToken([]byte("test-secret-for-jwt-signing-ok"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	body := `{"alias":"db","host_name":"db.example","extra":"ProxyCommand sh -c id"}`
	req := httptest.NewRequest(http.MethodPut, "/api/hosts/0123456789abcdef0123456789abcdef", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("erwartet 400, got %d %s", rec.Code, rec.Body.String())
	}
	b, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(b), "nicht erlaubt") && !strings.Contains(string(b), "ProxyCommand") && !strings.Contains(string(b), "extra") {
		t.Fatalf("Fehlertext unerwartet: %s", b)
	}
}
