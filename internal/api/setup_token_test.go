package api

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/thelad-dev/ssh-sync/internal/crypto"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

func TestSetupRequiresTokenWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	srv := NewServer(st, []byte("0123456789abcdef0123456789abcdef"))

	t.Setenv("SSH_SYNC_SETUP_TOKEN", "setup-secret-token")
	salt := bytes.Repeat([]byte{0x11}, crypto.SaltLen)
	keys := crypto.DeriveKeys("twelvechars!!", salt)
	body := []byte(`{"auth_key":"` + hex.EncodeToString(keys.AuthKey) + `","kdf_salt":"` + hex.EncodeToString(salt) + `"}`)

	req := httptest.NewRequest(http.MethodPost, "/api/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("without token: status %d body %s", rr.Code, rr.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/setup", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Setup-Token", "setup-secret-token")
	rr2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusCreated {
		t.Fatalf("with token: status %d body %s", rr2.Code, rr2.Body.String())
	}
}
