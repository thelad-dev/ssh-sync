package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/auth"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

func TestDeletedDeviceTokenRejectedOnSync(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	secret := []byte("test-secret-device-revoke-32b!!")
	srv := NewServer(st, secret)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	deviceID := "0123456789abcdef0123456789abcdef"
	jwtToken, err := auth.IssueDeviceToken(secret, deviceID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateDevice(store.Device{
		ID:        deviceID,
		Name:      "laptop",
		TokenHash: auth.HashToken(jwtToken),
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/sync", nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("before delete status=%d", resp.StatusCode)
	}

	if err := st.DeleteDevice(deviceID); err != nil {
		t.Fatal(err)
	}

	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/sync", nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after delete want 401, got %d body=%s", resp.StatusCode, body)
	}
}

func TestPutHostRejectsNonHexID(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	secret := []byte("test-secret-id-validation-32b!!")
	srv := NewServer(st, secret)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	userToken, err := auth.IssueUserToken(secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"alias":"x","host_name":"example.test"}`
	req, _ := http.NewRequest(http.MethodPut, ts.URL+`/api/hosts/not-a-hex-id`, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+userToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		got, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 400, got %d body=%s", resp.StatusCode, got)
	}
}
