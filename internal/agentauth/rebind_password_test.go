package agentauth

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/agentconfig"
	"github.com/thelad-dev/ssh-sync/internal/api"
	"github.com/thelad-dev/ssh-sync/internal/auth"
	"github.com/thelad-dev/ssh-sync/internal/crypto"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

func TestEnsureDeviceJWTDoesNotSendPasswordOnAuthV1Unauthorized(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}
	t.Setenv("SSH_SYNC_KEYRING", "file")
	t.Setenv("SSH_TTY", "")

	st, err := store.Open(t.TempDir() + "/rebind-v1.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	secret := testSecret(t)
	master := "fixture-master-" + hex.EncodeToString(mustRand(t, 8))
	salt := mustRand(t, 16)
	keys := crypto.DeriveKeys(master, salt)
	hash, err := auth.HashPassword(hex.EncodeToString(keys.AuthKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUserWithScheme(hash, salt, store.AuthSchemeV1); err != nil {
		t.Fatal(err)
	}

	deviceID := hex.EncodeToString(mustRand(t, 16))
	staleJWT, err := auth.IssueDeviceToken(secret, deviceID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateDevice(store.Device{
		ID:        deviceID,
		Name:      "v1-host",
		TokenHash: auth.HashToken("not-matching"),
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	keyDir := filepath.Join(home, ".config", "ssh-sync")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, ".master-key"), []byte(master), 0o600); err != nil {
		t.Fatal(err)
	}

	inner := api.NewServer(st, secret)
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
		inner.Handler().ServeHTTP(w, r)
	}))
	defer ts.Close()

	cfgPath := filepath.Join(t.TempDir(), "config.json")
	cfg := &agentconfig.Config{ServerURL: ts.URL, DeviceID: deviceID, JWT: staleJWT}
	if err := agentconfig.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDeviceJWT(cfgPath, cfg); err != nil {
		t.Fatalf("auth_v1 rebind via auth_key should succeed: %v", err)
	}
	if passwordBodies.Load() != 0 {
		t.Fatalf("password must not be sent for auth_v1, got %d", passwordBodies.Load())
	}
	if cfg.JWT == "" || cfg.JWT == staleJWT {
		t.Fatal("expected rotated jwt via auth_key")
	}
}

func TestEnsureDeviceJWTRejectsInsecureServerURL(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	cfg := &agentconfig.Config{
		ServerURL: "http://evil.test",
		DeviceID:  "0123456789abcdef0123456789abcdef",
		JWT:       "stale",
	}
	if err := agentconfig.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	err := EnsureDeviceJWT(cfgPath, cfg)
	if err == nil {
		t.Fatal("expected CheckServerURL rejection")
	}
	if !strings.Contains(err.Error(), "http://") && !strings.Contains(err.Error(), "insecure") && !strings.Contains(err.Error(), "Loopback") {
		t.Fatalf("unexpected error: %v", err)
	}
}
