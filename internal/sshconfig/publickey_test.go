package sshconfig

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestPublicKeysEqualIgnoresComment(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	canon := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	a := canon + " user@devbox"
	b := canon + " user@laptop"
	if !PublicKeysEqual(a, b) {
		t.Fatal("expected same key with different comments to match")
	}
	if PublicKeysEqual(a, canon+" x") == false && !PublicKeysEqual(a, b) {
		// different keys should not match - generate another key
	}
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	signer2, _ := ssh.NewSignerFromKey(priv2)
	other := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer2.PublicKey())))
	if PublicKeysEqual(a, other) {
		t.Fatal("different keys should not match")
	}
}
