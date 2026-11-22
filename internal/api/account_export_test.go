package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/accountexport"
	"github.com/thelad-dev/ssh-sync/internal/auth"
	"github.com/thelad-dev/ssh-sync/internal/crypto"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

func TestAccountExportImportRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	salt := bytes.Repeat([]byte{0x7a}, crypto.SaltLen)
	keys := crypto.DeriveKeys("master-password-12", salt)
	hash, _ := auth.HashPassword(hex.EncodeToString(keys.AuthKey))
	if err := st.CreateUserWithScheme(hash, salt, store.AuthSchemeV1); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	id := "cccccccccccccccccccccccccccccccc"
	enc, _ := crypto.EncryptIdentity(keys, id, "ssh-ed25519 AAAA", []byte("SECRETKEY"))
	_ = st.UpsertIdentity(store.Identity{
		ID: id, Name: "k1", PublicKey: "ssh-ed25519 AAAA", EncryptedPrivateKey: enc,
		CreatedAt: now, UpdatedAt: now,
	})
	_ = st.UpsertHost(store.Host{
		ID: "dddddddddddddddddddddddddddddddd", Alias: "srv", HostName: "srv.example",
		User: "root", Port: 22, IdentityID: &id, CreatedAt: now, UpdatedAt: now,
	})

	secret := []byte("0123456789abcdef0123456789abcdef")
	srv := NewServer(st, secret)
	token, err := auth.IssueUserToken(secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/account/export", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("export %d %s", rec.Code, rec.Body.String())
	}
	var payload accountexport.Payload
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Identities) != 1 || payload.Identities[0].EncryptedPrivateKey != enc {
		t.Fatalf("export payload: %+v", payload)
	}

	// Frisches Zielkonto mit gleichem Salt.
	st2, err := store.Open(filepath.Join(dir, "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	hash2, _ := auth.HashPassword(hex.EncodeToString(keys.AuthKey))
	_ = st2.CreateUserWithScheme(hash2, salt, store.AuthSchemeV1)
	srv2 := NewServer(st2, secret)
	token2, _ := auth.IssueUserToken(secret, time.Hour)

	body, _ := json.Marshal(map[string]any{
		"payload": payload,
		"mode":    "replace",
		"dry_run": false,
	})
	req2 := httptest.NewRequest(http.MethodPost, "/api/account/import", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer "+token2)
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	srv2.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("import %d %s", rec2.Code, rec2.Body.String())
	}
	ids, _ := st2.ListIdentities()
	hosts, _ := st2.ListHosts()
	if len(ids) != 1 || len(hosts) != 1 {
		t.Fatalf("after import ids=%d hosts=%d", len(ids), len(hosts))
	}
	plain, err := crypto.DecryptIdentity(keys, ids[0].ID, ids[0].PublicKey, ids[0].EncryptedPrivateKey)
	if err != nil || string(plain) != "SECRETKEY" {
		t.Fatalf("decrypt %v %q", err, plain)
	}
}

func TestAccountExportRequiresAuth(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/x.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := NewServer(st, []byte("0123456789abcdef0123456789abcdef"))
	req := httptest.NewRequest(http.MethodGet, "/api/account/export", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rec.Code)
	}
}
