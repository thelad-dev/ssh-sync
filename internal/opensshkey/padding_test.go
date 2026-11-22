package opensshkey

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestFixPaddingIdempotentGoodKey(t *testing.T) {
	pem := mustSSHKeygen(t, "good comment")
	fixed, changed, err := FixPadding(pem)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("expected no change for good key")
	}
	if _, err := ssh.ParsePrivateKey(fixed); err != nil {
		t.Fatal(err)
	}
}

func TestFixPaddingDoublePadLongComment(t *testing.T) {
	pem := mustSSHKeygen(t, "Hetzner Cloudserver mit Meilisearch")
	broken := corruptWithDoublePadding(t, pem)
	if _, err := ssh.ParsePrivateKey(broken); err == nil {
		t.Fatal("expected broken key to be unparseable")
	}
	fixed, changed, err := FixPadding(broken)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected change")
	}
	if _, err := ssh.ParsePrivateKey(fixed); err != nil {
		t.Fatalf("fixed key not parseable: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	if err := os.WriteFile(path, fixed, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("ssh-keygen", "-y", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -y: %v\n%s", err, out)
	}
	_, changed2, err := FixPadding(fixed)
	if err != nil || changed2 {
		t.Fatalf("second fix should be no-op: changed=%v err=%v", changed2, err)
	}
}

func mustSSHKeygen(t *testing.T, comment string) []byte {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen missing")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "id")
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-C", comment, "-f", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return pem
}

func corruptWithDoublePadding(t *testing.T, pem []byte) []byte {
	t.Helper()
	body, ok := extractPEMBody(pem)
	if !ok {
		t.Fatal("pem")
	}
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatal(err)
	}
	rest := raw[len(magic):]
	cipherName, rest, err := readString(rest)
	if err != nil {
		t.Fatal(err)
	}
	kdfName, rest, err := readString(rest)
	if err != nil {
		t.Fatal(err)
	}
	kdfOpts, rest, err := readString(rest)
	if err != nil {
		t.Fatal(err)
	}
	rest = rest[4:]
	pubWire, rest, err := readString(rest)
	if err != nil {
		t.Fatal(err)
	}
	priv, _, err := readString(rest)
	if err != nil {
		t.Fatal(err)
	}
	brokenPriv := doublePadPriv(t, priv)

	var buf bytes.Buffer
	buf.WriteString(magic)
	writeString(&buf, cipherName)
	writeString(&buf, kdfName)
	writeString(&buf, kdfOpts)
	_ = binary.Write(&buf, binary.BigEndian, uint32(1))
	writeString(&buf, pubWire)
	writeString(&buf, brokenPriv)
	return wrapPEM(buf.Bytes())
}

func doublePadPriv(t *testing.T, priv []byte) []byte {
	t.Helper()
	rest := priv[8:]
	keyType, rest, err := readString(rest)
	if err != nil {
		t.Fatal(err)
	}
	if string(keyType) != "ssh-ed25519" {
		t.Fatalf("want ed25519 got %s", keyType)
	}
	pub, rest, err := readString(rest)
	if err != nil {
		t.Fatal(err)
	}
	sk, rest, err := readString(rest)
	if err != nil {
		t.Fatal(err)
	}
	comment, _, err := readString(rest)
	if err != nil {
		t.Fatal(err)
	}
	ed := concatSSH(pub, sk, comment)
	ed = openSSHPad(ed)
	pk1 := concatBytes(priv[0:8], sshStr(keyType), ed)
	return openSSHPad(pk1)
}

func openSSHPad(b []byte) []byte {
	n := (8 - (len(b) % 8)) % 8
	out := make([]byte, len(b)+n)
	copy(out, b)
	for i := 0; i < n; i++ {
		out[len(b)+i] = byte(i + 1)
	}
	return out
}

func sshStr(s []byte) []byte {
	out := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(out, uint32(len(s)))
	copy(out[4:], s)
	return out
}

func concatSSH(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, sshStr(p)...)
	}
	return b
}

func concatBytes(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}
