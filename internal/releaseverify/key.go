package releaseverify

import (
	"crypto/ed25519"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

//go:embed release_ed25519.pub
var embeddedPubFile []byte

// PublicKey holds the 32-byte Ed25519 public key used to verify release manifests.
// Tests may replace it. Empty means verification fails closed.
var PublicKey []byte

func init() {
	PublicKey = ParsePublicKeyFile(embeddedPubFile)
}

// ParsePublicKeyFile reads a hex public key, ignoring comment lines.
func ParsePublicKeyFile(data []byte) []byte {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		b, err := hex.DecodeString(line)
		if err != nil || len(b) != 32 {
			return nil
		}
		return b
	}
	return nil
}

// PublicKeyHex returns the hex form of PublicKey, or empty if unset.
func PublicKeyHex() string {
	if len(PublicKey) != 32 {
		return ""
	}
	return hex.EncodeToString(PublicKey)
}

// PublicKeyPEM returns a PKIX PEM for openssl pkeyutl, or an error if unset.
func PublicKeyPEM() (string, error) {
	if len(PublicKey) != 32 {
		return "", fmt.Errorf("kein Release-Public-Key eingebettet")
	}
	spki, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(PublicKey))
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})), nil
}
