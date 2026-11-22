package keygen

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Type beschreibt den Algorithmus für ssh-keygen.
type Type string

const (
	TypeEd25519 Type = "ed25519"
	TypeRSA     Type = "rsa"
)

// KeyPair ist ein frisch erzeugtes SSH-Keypair im OpenSSH-Format.
type KeyPair struct {
	PrivatePEM []byte
	PublicLine string
}

// Generate erzeugt ein SSH-Keypair (Standard: Ed25519).
func Generate(typ Type, comment string) (*KeyPair, error) {
	switch typ {
	case "", TypeEd25519:
		return generateEd25519(comment)
	case TypeRSA:
		return generateRSA(4096, comment)
	default:
		return nil, fmt.Errorf("unbekannter key-typ: %q (ed25519, rsa)", typ)
	}
}

func generateEd25519(comment string) (*KeyPair, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return keyPairFromPrivate(priv, comment)
}

func generateRSA(bits int, comment string) (*KeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return keyPairFromPrivate(priv, comment)
}

func keyPairFromPrivate(priv any, comment string) (*KeyPair, error) {
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		PrivatePEM: pem.EncodeToMemory(block),
		PublicLine: string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
	}, nil
}
