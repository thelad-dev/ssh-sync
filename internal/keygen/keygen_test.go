package keygen

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerateEd25519OpenSSH(t *testing.T) {
	kp, err := Generate(TypeEd25519, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ssh.ParsePrivateKey(kp.PrivatePEM); err != nil {
		t.Fatalf("private key not parseable: %v", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(kp.PublicLine))
	if err != nil {
		t.Fatalf("public key not parseable: %v", err)
	}
	if pub.Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("unexpected type %s", pub.Type())
	}
}

func TestGenerateEd25519LongCommentSSHKeygen(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not in PATH")
	}
	comment := "Hetzner Cloudserver mit Meilisearch"
	kp, err := Generate(TypeEd25519, comment)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ssh.ParsePrivateKey(kp.PrivatePEM); err != nil {
		t.Fatalf("private key not parseable: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "long_comment_id")
	if err := os.WriteFile(path, kp.PrivatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("ssh-keygen", "-y", "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -y failed: %v\n%s", err, out)
	}
}

func TestGenerateRSA(t *testing.T) {
	kp, err := Generate(TypeRSA, "rsa-test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ssh.ParsePrivateKey(kp.PrivatePEM); err != nil {
		t.Fatalf("rsa private key not parseable: %v", err)
	}
}
