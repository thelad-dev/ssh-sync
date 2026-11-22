package selfupdate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceUnix(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "ssh-sync")
	oldContent := []byte("#!/bin/sh\necho old\n")
	newContent := []byte("#!/bin/sh\necho new\n")

	if err := os.WriteFile(dest, oldContent, 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, ".ssh-sync-update-1")
	if err := os.WriteFile(src, newContent, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := replaceUnix(dest, src); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newContent) {
		t.Fatalf("inhalt: %q", got)
	}
}
