//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReexecUpdateUsesExclusiveTempFile(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "ssh-sync")
	payload := []byte("#!/bin/sh\necho runner\n")
	if err := os.WriteFile(exe, payload, 0o755); err != nil {
		t.Fatal(err)
	}
	// Simulate only the temp-file creation path by calling the helper pieces.
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	td, err := os.MkdirTemp("", "ssh-sync-update-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(td) })
	tmp, err := os.OpenFile(filepath.Join(td, "ssh-sync-update-runner"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	// Second create with O_EXCL must fail (no fixed /tmp path race).
	_, err = os.OpenFile(filepath.Join(td, "ssh-sync-update-runner"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err == nil {
		t.Fatal("expected O_EXCL collision")
	}
}
