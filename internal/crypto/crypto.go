package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	SaltLen  = 16
	NonceLen = 12
	KeyLen   = 32
	TimeCost = 3
	MemoryMB = 64 * 1024
	Threads  = 4

	AuthInfo      = "ssh-sync-auth"
	EncInfo       = "ssh-sync-enc"
	ExportMACInfo = "ssh-sync-export-mac"

	// CipherVersionAAD markiert AES-GCM mit AAD (N5).
	CipherVersionAAD byte = 1
)

// DerivedKeys haelt Auth- und Verschluesselungsschluessel getrennt (H4/N1).
type DerivedKeys struct {
	AuthKey   []byte
	EncKey    []byte
	LegacyKey []byte // Argon2id-IKM = frueheres DeriveKey
}

// DeriveKey leitet den Legacy-AES-Schluessel (direkt Argon2id) ab.
// Wird fuer lokale Backup-Dateien und Legacy-Ciphertexts genutzt.
func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, TimeCost, MemoryMB, Threads, KeyLen)
}

// DeriveKeys leitet Auth- und Enc-Schluessel per HKDF aus dem Master-Passwort ab.
func DeriveKeys(password string, salt []byte) DerivedKeys {
	ikm := DeriveKey(password, salt)
	return DerivedKeys{
		AuthKey:   hkdfExpand(ikm, AuthInfo),
		EncKey:    hkdfExpand(ikm, EncInfo),
		LegacyKey: ikm,
	}
}

// DeriveExportMACKey leitet den HMAC-Schluessel fuer Konten-Archive ab.
func DeriveExportMACKey(password string, salt []byte) []byte {
	return hkdfExpand(DeriveKey(password, salt), ExportMACInfo)
}

func hkdfExpand(ikm []byte, info string) []byte {
	r := hkdf.New(sha256.New, ikm, nil, []byte(info))
	out := make([]byte, KeyLen)
	if _, err := io.ReadFull(r, out); err != nil {
		panic("hkdf: " + err.Error())
	}
	return out
}

// NewSalt erzeugt ein zufaelliges Salt fuer Argon2id.
func NewSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// IdentityAAD baut die AAD fuer Identity-Ciphertexts (N5).
func IdentityAAD(id, publicKey string) []byte {
	return []byte(id + "|" + publicKey)
}

// Encrypt verschluesselt Klartext mit AES-256-GCM ohne AAD (Legacy/Backup).
func Encrypt(key, plaintext []byte) (string, error) {
	return encryptRaw(key, plaintext, nil, false)
}

// EncryptWithAAD verschluesselt mit Versionsbyte und AAD.
func EncryptWithAAD(key, plaintext, aad []byte) (string, error) {
	return encryptRaw(key, plaintext, aad, true)
}

func encryptRaw(key, plaintext, aad []byte, withVersion bool) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, NonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	var combined []byte
	if withVersion {
		combined = make([]byte, 1+NonceLen+len(ciphertext))
		combined[0] = CipherVersionAAD
		copy(combined[1:], nonce)
		copy(combined[1+NonceLen:], ciphertext)
	} else {
		combined = make([]byte, NonceLen+len(ciphertext))
		copy(combined, nonce)
		copy(combined[NonceLen:], ciphertext)
	}
	return base64.StdEncoding.EncodeToString(combined), nil
}

// Decrypt entschluesselt einen Legacy-Ciphertext ohne AAD.
func Decrypt(key []byte, encoded string) ([]byte, error) {
	return decryptRaw(key, encoded, nil, false)
}

// DecryptWithAAD entschluesselt einen Version-1-Ciphertext.
func DecryptWithAAD(key []byte, encoded string, aad []byte) ([]byte, error) {
	return decryptRaw(key, encoded, aad, true)
}

func decryptRaw(key []byte, encoded string, aad []byte, expectVersion bool) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	var nonce, ct []byte
	if expectVersion {
		if len(raw) < 1+NonceLen {
			return nil, errors.New("ciphertext zu kurz")
		}
		if raw[0] != CipherVersionAAD {
			return nil, fmt.Errorf("unbekannte cipher-version %d", raw[0])
		}
		nonce = raw[1 : 1+NonceLen]
		ct = raw[1+NonceLen:]
	} else {
		if len(raw) < NonceLen {
			return nil, errors.New("ciphertext zu kurz")
		}
		nonce = raw[:NonceLen]
		ct = raw[NonceLen:]
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("entschluesselung fehlgeschlagen: %w", err)
	}
	return plaintext, nil
}

// DecryptIdentity versucht zuerst EncKey+AAD, dann LegacyKey ohne AAD.
func DecryptIdentity(keys DerivedKeys, id, publicKey, encoded string) ([]byte, error) {
	aad := IdentityAAD(id, publicKey)
	if plain, err := DecryptWithAAD(keys.EncKey, encoded, aad); err == nil {
		return plain, nil
	}
	if plain, err := Decrypt(keys.LegacyKey, encoded); err == nil {
		return plain, nil
	}
	return nil, errors.New("entschluesselung fehlgeschlagen")
}

// EncryptIdentity verschluesselt einen Private Key mit EncKey und AAD.
func EncryptIdentity(keys DerivedKeys, id, publicKey string, plaintext []byte) (string, error) {
	return EncryptWithAAD(keys.EncKey, plaintext, IdentityAAD(id, publicKey))
}

// IsVersionedCipher meldet, ob der Blob ein Versionsbyte traegt.
func IsVersionedCipher(encoded string) bool {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) < 1 {
		return false
	}
	return raw[0] == CipherVersionAAD
}
