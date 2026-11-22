package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/auth"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

func TestTriggerPurgePortalFlow(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	secret := []byte("test-secret-purge-flow")
	srv := NewServer(st, secret)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	deviceID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	now := time.Now()
	userToken, err := auth.IssueUserToken(secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	deviceToken, err := auth.IssueDeviceToken(secret, deviceID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateDevice(store.Device{
		ID:        deviceID,
		Name:      "Test-Rechner",
		TokenHash: auth.HashToken(deviceToken),
		CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.TouchDevice(deviceID); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/devices/"+deviceID+"/trigger-purge", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("trigger-purge status=%d body=%s", resp.StatusCode, body)
	}
	var queued map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&queued); err != nil {
		t.Fatal(err)
	}
	if queued["status"] != "queued" {
		t.Fatalf("unexpected queue response: %v", queued)
	}

	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/agent/commands", nil)
	req.Header.Set("Authorization", "Bearer "+deviceToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("poll status=%d body=%s", resp.StatusCode, body)
	}
	var cmd map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&cmd); err != nil {
		t.Fatal(err)
	}
	if cmd["command"] != store.CommandPurge {
		t.Fatalf("expected purge command, got %v", cmd)
	}
	cmdID, _ := cmd["id"].(string)
	if cmdID == "" {
		t.Fatal("missing command id")
	}

	completeBody := bytes.NewBufferString(`{"status":"completed","message":"ok"}`)
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/agent/commands/"+cmdID+"/complete", completeBody)
	req.Header.Set("Authorization", "Bearer "+deviceToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("complete status=%d body=%s", resp.StatusCode, body)
	}

	devices, err := st.ListDevices()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devices {
		if d.ID == deviceID {
			t.Fatal("device should be removed from portal after purge complete")
		}
	}
}
