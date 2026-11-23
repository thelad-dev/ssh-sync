package sshconfig

import (
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// PrivateKeyFingerprint liefert den SHA256-Fingerabdruck des eingebetteten Public Keys.
func PrivateKeyFingerprint(pemBytes []byte) (string, error) {
	key, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return "", fmt.Errorf("private key parsen: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return "", fmt.Errorf("signer: %w", err)
	}
	return ssh.FingerprintSHA256(signer.PublicKey()), nil
}

// PublicKeyFingerprint liefert den SHA256-Fingerabdruck einer authorized_keys-Zeile oder .pub-Datei.
func PublicKeyFingerprint(pubBytes []byte) (string, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes)
	if err != nil {
		return "", fmt.Errorf("public key parsen: %w", err)
	}
	return ssh.FingerprintSHA256(pub), nil
}

func filePrivateKeyFingerprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return PrivateKeyFingerprint(data)
}

// warnPubMismatch meldet, wenn keyPath.pub nicht zum Private Key unter keyPath passt.
func warnPubMismatch(keyPath string, warnings *[]string) {
	pubPath := keyPath + ".pub"
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		if !os.IsNotExist(err) {
			*warnings = append(*warnings, fmt.Sprintf("%s: lesen fehlgeschlagen: %v", pubPath, err))
		}
		return
	}
	keyFP, err := filePrivateKeyFingerprint(keyPath)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("%s: Private Key unlesbar (%v), .pub vorhanden", keyPath, err))
		return
	}
	pubFP, err := PublicKeyFingerprint(pubData)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("%s: ungueltig (%v)", pubPath, err))
		return
	}
	if pubFP != keyFP {
		*warnings = append(*warnings, fmt.Sprintf(
			"%s passt nicht zum Private Key %s (pub %s, key %s)",
			pubPath, keyPath, pubFP, keyFP,
		))
	}
}

func ensureTrailingNewline(data []byte) []byte {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		out := make([]byte, len(data)+1)
		copy(out, data)
		out[len(data)] = '\n'
		return out
	}
	return data
}
