package clientauth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/thelad-dev/ssh-sync/internal/api"
	"github.com/thelad-dev/ssh-sync/internal/auth"
	"github.com/thelad-dev/ssh-sync/internal/client"
	"github.com/thelad-dev/ssh-sync/internal/crypto"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

func TestPortalLoginDoesNotSendPasswordOnAuthV1Failure(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/authv1.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	master := "wrong-master-password-xx"
	other := crypto.DeriveKeys("other-master-password-yy", salt)
	hash, err := auth.HashPassword(hex.EncodeToString(other.AuthKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUserWithScheme(hash, salt, store.AuthSchemeV1); err != nil {
		t.Fatal(err)
	}

	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	secretHex := []byte(hex.EncodeToString(secret))
	srv := api.NewServer(st, secretHex)

	var passwordBodies atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/login" && r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			var payload map[string]string
			_ = json.Unmarshal(body, &payload)
			if _, ok := payload["password"]; ok {
				passwordBodies.Add(1)
			}
			r.Body = io.NopCloser(strings.NewReader(string(body)))
		}
		srv.Handler().ServeHTTP(w, r)
	}))
	defer ts.Close()

	apiClient := client.New(ts.URL, "")
	_, err = PortalLogin(apiClient, master)
	if err == nil {
		t.Fatal("expected login failure")
	}
	if passwordBodies.Load() != 0 {
		t.Fatalf("master password must not be sent on auth_v1 failure, got %d password bodies", passwordBodies.Load())
	}
}

func TestPortalLoginSendsPasswordOnlyWhenLegacy(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/legacy.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	master := "legacy-master-12chars"
	hash, err := auth.HashPassword(master)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUserWithScheme(hash, salt, store.AuthSchemeLegacy); err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	srv := api.NewServer(st, []byte(hex.EncodeToString(secret)))

	var sawPassword atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/login" && r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), `"password"`) {
				sawPassword.Add(1)
			}
			r.Body = io.NopCloser(strings.NewReader(string(body)))
		}
		srv.Handler().ServeHTTP(w, r)
	}))
	defer ts.Close()

	apiClient := client.New(ts.URL, "")
	_, err = PortalLogin(apiClient, master)
	if err != nil {
		t.Fatal(err)
	}
	if sawPassword.Load() == 0 {
		t.Fatal("legacy login must send password after server marks legacy")
	}
}
