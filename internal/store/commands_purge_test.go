package store

import (
	"testing"
	"time"
)

func TestEnqueuePurgeCommand(t *testing.T) {
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	deviceID := "dev-purge-test"
	if err := st.CreateDevice(Device{ID: deviceID, Name: "test", TokenHash: "x", CreatedAt: mustTime()}); err != nil {
		t.Fatal(err)
	}

	cmd, err := st.EnqueueCommand(deviceID, CommandPurge)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Command != CommandPurge {
		t.Fatalf("command=%q", cmd.Command)
	}
	if cmd.Status != StatusPending {
		t.Fatalf("status=%q", cmd.Status)
	}

	claimed, err := st.ClaimNextCommand(deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if claimed == nil || claimed.Command != CommandPurge {
		t.Fatalf("claimed=%v", claimed)
	}
}

func mustTime() time.Time {
	return time.Now()
}
