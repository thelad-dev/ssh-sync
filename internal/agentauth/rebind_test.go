package agentauth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/agentconfig"
	"github.com/thelad-dev/ssh-sync/internal/api"
	"github.com/thelad-dev/ssh-sync/internal/auth"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

func testSecret(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return []byte(hex.EncodeToString(buf))
}

func TestEnsureDeviceJWTIdempotentWhenAlreadyValid(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/ok.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	secret := testSecret(t)
	srv := api.NewServer(st, secret)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	deviceID := hex.EncodeToString(mustRand(t, 16))
	jwtTok, err := auth.IssueDeviceToken(secret, deviceID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateDevice(store.Device{
		ID:        deviceID,
		Name:      "ok",
		TokenHash: auth.HashToken(jwtTok),
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(t.TempDir(), "config.json")
	cfg := &agentconfig.Config{ServerURL: ts.URL, DeviceID: deviceID, JWT: jwtTok}
	if err := agentconfig.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDeviceJWT(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.JWT != jwtTok {
		t.Fatal("jwt should stay unchanged when ping succeeds")
	}
}

func TestEnsureDeviceJWTRebindFromLegacyAgentFixture(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}
	t.Setenv("SSH_SYNC_KEYRING", "file")
	t.Setenv("SSH_TTY", "")

	st, err := store.Open(t.TempDir() + "/rebind.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	secret := testSecret(t)
	srv := api.NewServer(st, secret)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	master := "fixture-master-" + hex.EncodeToString(mustRand(t, 8))
	hash, err := auth.HashPassword(master)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUserWithScheme(hash, mustRand(t, 16), store.AuthSchemeLegacy); err != nil {
		t.Fatal(err)
	}

	deviceID := hex.EncodeToString(mustRand(t, 16))
	// Old agent format: JWT in config, but DB hash is sha256(opaque device_token).
	opaque := hex.EncodeToString(mustRand(t, 32))
	oldHash := auth.HashToken(opaque)
	staleJWT, err := auth.IssueDeviceToken(secret, deviceID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateDevice(store.Device{
		ID:        deviceID,
		Name:      "legacy-host",
		TokenHash: oldHash,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	legacyDir := filepath.Join(home, ".config", "ssh-profile-syncer")
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacyCfg := map[string]any{
		"server_url": ts.URL,
		"device_id":  deviceID,
		"jwt":        staleJWT,
	}
	raw, _ := json.MarshalIndent(legacyCfg, "", "  ")
	if err := os.WriteFile(filepath.Join(legacyDir, "config.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, ".master-key"), []byte(master), 0o600); err != nil {
		t.Fatal(err)
	}

	cfgPath, err := agentconfig.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := agentconfig.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureDeviceJWT(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.JWT == "" || cfg.JWT == staleJWT {
		t.Fatal("expected rotated jwt")
	}
	saved, err := agentconfig.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.JWT != cfg.JWT {
		t.Fatal("config not persisted")
	}
	if _, err := os.Stat(filepath.Join(legacyDir, "config.json")); err != nil {
		t.Fatalf("legacy config must remain: %v", err)
	}

	// Idempotent second call.
	prev := cfg.JWT
	if err := EnsureDeviceJWT(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.JWT != prev {
		t.Fatal("second ensure should be no-op")
	}
}

func TestEnsureDeviceJWTFailsWithoutMaster(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}
	t.Setenv("SSH_SYNC_MASTER_PASSWORD", "")
	t.Setenv("SSH_SYNC_KEYRING", "file")
	t.Setenv("SSH_TTY", "")

	st, err := store.Open(t.TempDir() + "/nomaster.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	secret := testSecret(t)
	srv := api.NewServer(st, secret)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	deviceID := hex.EncodeToString(mustRand(t, 16))
	if err := st.CreateDevice(store.Device{
		ID:        deviceID,
		Name:      "x",
		TokenHash: auth.HashToken("not-a-match"),
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	staleJWT, err := auth.IssueDeviceToken(secret, deviceID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	cfg := &agentconfig.Config{ServerURL: ts.URL, DeviceID: deviceID, JWT: staleJWT}
	if err := agentconfig.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	err = EnsureDeviceJWT(cfgPath, cfg)
	if err == nil {
		t.Fatal("expected error without master password")
	}
}

func mustRand(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
