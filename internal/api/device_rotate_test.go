package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/auth"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

func randomJWTSecret(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return []byte(hex.EncodeToString(buf))
}

func randomDeviceID(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buf)
}

func TestRotateDeviceIssuesNewJWTAndUpdatesHash(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/rot.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	secret := randomJWTSecret(t)
	srv := NewServer(st, secret)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	deviceID := randomDeviceID(t)
	oldJWT, err := auth.IssueDeviceToken(secret, deviceID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateDevice(store.Device{
		ID:        deviceID,
		Name:      "lab",
		TokenHash: auth.HashToken(oldJWT),
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	userTok, err := auth.IssueUserToken(secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/devices/"+deviceID+"/rotate", nil)
	req.Header.Set("Authorization", "Bearer "+userTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("rotate status=%d body=%s", resp.StatusCode, body)
	}
	var out map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	newJWT := out["jwt"]
	if newJWT == "" || newJWT == oldJWT {
		t.Fatal("expected fresh jwt")
	}

	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/sync", nil)
	req2.Header.Set("Authorization", "Bearer "+oldJWT)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old jwt want 401 got %d", resp2.StatusCode)
	}

	req3, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/sync", nil)
	req3.Header.Set("Authorization", "Bearer "+newJWT)
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("new jwt want 200 got %d", resp3.StatusCode)
	}
}

func TestRotateDeviceRejectsDeviceJWT(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/rot-dev.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	secret := randomJWTSecret(t)
	srv := NewServer(st, secret)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	deviceID := randomDeviceID(t)
	devJWT, err := auth.IssueDeviceToken(secret, deviceID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateDevice(store.Device{
		ID:        deviceID,
		Name:      "lab",
		TokenHash: auth.HashToken(devJWT),
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/devices/"+deviceID+"/rotate", nil)
	req.Header.Set("Authorization", "Bearer "+devJWT)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("device jwt rotate want 401 got %d", resp.StatusCode)
	}
}

func TestRotateDeviceUnknownID(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/rot-miss.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	secret := randomJWTSecret(t)
	srv := NewServer(st, secret)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	userTok, err := auth.IssueUserToken(secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	missing := randomDeviceID(t)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/devices/"+missing+"/rotate", nil)
	req.Header.Set("Authorization", "Bearer "+userTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 got %d", resp.StatusCode)
	}
}

func TestRotateDeviceIdempotentSecondCall(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/rot-idem.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	secret := randomJWTSecret(t)
	srv := NewServer(st, secret)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	deviceID := randomDeviceID(t)
	jwt1, err := auth.IssueDeviceToken(secret, deviceID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateDevice(store.Device{
		ID:        deviceID,
		Name:      "lab",
		TokenHash: auth.HashToken(jwt1),
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	userTok, err := auth.IssueUserToken(secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	doRotate := func() string {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/devices/"+deviceID+"/rotate", nil)
		req.Header.Set("Authorization", "Bearer "+userTok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("rotate status=%d", resp.StatusCode)
		}
		var out map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out["jwt"]
	}
	a := doRotate()
	// IssuedAt is second-granular; wait so the second token differs.
	time.Sleep(1100 * time.Millisecond)
	b := doRotate()
	if a == "" || b == "" || a == b {
		t.Fatalf("expected two distinct jwts")
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/sync", nil)
	req.Header.Set("Authorization", "Bearer "+b)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("latest jwt want 200 got %d", resp.StatusCode)
	}
}

func TestRotateDeviceRateLimit(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/rot-rl.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	secret := randomJWTSecret(t)
	srv := NewServer(st, secret)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	prev := rotateMax
	rotateMax = 2
	t.Cleanup(func() { rotateMax = prev })

	deviceID := randomDeviceID(t)
	jwtTok, err := auth.IssueDeviceToken(secret, deviceID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateDevice(store.Device{
		ID:        deviceID,
		Name:      "lab",
		TokenHash: auth.HashToken(jwtTok),
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	userTok, err := auth.IssueUserToken(secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/devices/"+deviceID+"/rotate", nil)
		req.Header.Set("Authorization", "Bearer "+userTok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("rotate %d status=%d", i, resp.StatusCode)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/devices/"+deviceID+"/rotate", nil)
	req.Header.Set("Authorization", "Bearer "+userTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("want 429 got %d", resp.StatusCode)
	}
}

func TestOldDeviceTokenHashRejectedUntilRotate(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/rot-oldhash.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	secret := randomJWTSecret(t)
	srv := NewServer(st, secret)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	deviceID := randomDeviceID(t)
	opaque := make([]byte, 32)
	if _, err := rand.Read(opaque); err != nil {
		t.Fatal(err)
	}
	opaqueToken := hex.EncodeToString(opaque)
	sum := sha256.Sum256([]byte(opaqueToken))
	oldStyleHash := hex.EncodeToString(sum[:])

	jwtTok, err := auth.IssueDeviceToken(secret, deviceID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateDevice(store.Device{
		ID:        deviceID,
		Name:      "migrated",
		TokenHash: oldStyleHash,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/sync", nil)
	req.Header.Set("Authorization", "Bearer "+jwtTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old hash form want 401 got %d", resp.StatusCode)
	}

	userTok, err := auth.IssueUserToken(secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rotReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/devices/"+deviceID+"/rotate", nil)
	rotReq.Header.Set("Authorization", "Bearer "+userTok)
	rotResp, err := http.DefaultClient.Do(rotReq)
	if err != nil {
		t.Fatal(err)
	}
	defer rotResp.Body.Close()
	if rotResp.StatusCode != http.StatusOK {
		t.Fatalf("rotate status=%d", rotResp.StatusCode)
	}
	var out map[string]string
	if err := json.NewDecoder(rotResp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/sync", nil)
	req2.Header.Set("Authorization", "Bearer "+out["jwt"])
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("after rotate want 200 got %d", resp2.StatusCode)
	}
}
