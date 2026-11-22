package keyring

import (
	"testing"
)

func TestPreferFileStorage(t *testing.T) {
	t.Setenv("SSH_SYNC_KEYRING", "")
	t.Setenv("SSH_TTY", "")

	if preferFileStorage() {
		t.Fatal("expected false without SSH_TTY")
	}

	t.Setenv("SSH_TTY", "/dev/pts/0")
	if !preferFileStorage() {
		t.Fatal("expected true with SSH_TTY")
	}

	t.Setenv("SSH_TTY", "")
	t.Setenv("SSH_SYNC_KEYRING", "file")
	if !preferFileStorage() {
		t.Fatal("expected true with SSH_SYNC_KEYRING=file")
	}

	t.Setenv("SSH_SYNC_KEYRING", "keyring")
	if preferFileStorage() {
		t.Fatal("expected false with SSH_SYNC_KEYRING=keyring")
	}
}
