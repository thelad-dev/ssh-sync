package importlocal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublicKeyPaths(t *testing.T) {
	paths := publicKeyPaths("/home/user/.ssh/id_rsa.pem")
	if len(paths) < 2 {
		t.Fatalf("expected at least 2 paths, got %v", paths)
	}
	if paths[0] != "/home/user/.ssh/id_rsa.pem.pub" {
		t.Errorf("unexpected first path: %s", paths[0])
	}
	if paths[1] != "/home/user/.ssh/id_rsa.pub" {
		t.Errorf("unexpected second path: %s", paths[1])
	}
}

func TestReadPublicKeyPemPair(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "id_rsa.pem")
	pub := filepath.Join(dir, "id_rsa.pub")
	if err := os.WriteFile(priv, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pubText := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC test"
	if err := os.WriteFile(pub, []byte(pubText+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := readPublicKey(priv)
	if got != pubText {
		t.Errorf("readPublicKey() = %q, want %q", got, pubText)
	}
}
