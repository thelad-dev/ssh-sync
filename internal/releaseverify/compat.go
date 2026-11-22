package releaseverify

import "fmt"

// PublicKeyPEM remains for install script generation until the installer worker
// switches to Sigstore. It always fails closed (no Ed25519 release key).
func PublicKeyPEM() (string, error) {
	return "", fmt.Errorf("Ed25519-Release-Key entfernt; Verifikation laeuft ueber Sigstore")
}
