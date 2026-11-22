package sshconfig

import (
	"strings"

	"golang.org/x/crypto/ssh"
)

// PublicKeysEqual vergleicht OpenSSH-authorized-keys-Zeilen inhaltlich (ohne Kommentar).
func PublicKeysEqual(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == b {
		return true
	}
	if a == "" || b == "" {
		return false
	}
	ca, oka := canonicalPublicKey(a)
	cb, okb := canonicalPublicKey(b)
	if oka && okb {
		return ca == cb
	}
	return false
}

// CanonicalPublicKey normalisiert eine authorized-keys-Zeile (Typ + Key-Blob).
func CanonicalPublicKey(line string) (string, bool) {
	return canonicalPublicKey(line)
}

func canonicalPublicKey(line string) (string, bool) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(line)))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), true
}
