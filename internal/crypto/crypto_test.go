package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	salt, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	key := DeriveKey("test-master-password", salt)
	plain := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----")

	enc, err := Encrypt(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(key, enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("roundtrip fehlgeschlagen: %q != %q", got, plain)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	salt, _ := NewSalt()
	key1 := DeriveKey("password-a", salt)
	key2 := DeriveKey("password-b", salt)
	enc, _ := Encrypt(key1, []byte("secret"))
	if _, err := Decrypt(key2, enc); err == nil {
		t.Fatal("falsches Passwort haette Fehler erzeugen muessen")
	}
}

func TestDeriveKeysSplitsAuthAndEnc(t *testing.T) {
	salt := bytes.Repeat([]byte{0x11}, SaltLen)
	keys := DeriveKeys("master-password-12", salt)
	if bytes.Equal(keys.AuthKey, keys.EncKey) {
		t.Fatal("auth und enc duerfen nicht identisch sein")
	}
	if !bytes.Equal(keys.LegacyKey, DeriveKey("master-password-12", salt)) {
		t.Fatal("legacy key muss dem alten DeriveKey entsprechen")
	}
	if bytes.Equal(keys.AuthKey, keys.LegacyKey) || bytes.Equal(keys.EncKey, keys.LegacyKey) {
		t.Fatal("HKDF-Schluessel muessen vom IKM abweichen")
	}
}

func TestEncryptIdentityAADPreventsSwap(t *testing.T) {
	salt := bytes.Repeat([]byte{0x22}, SaltLen)
	keys := DeriveKeys("master-password-12", salt)
	plain := []byte("PRIVATE-KEY-A")
	enc, err := EncryptIdentity(keys, "id-a", "ssh-ed25519 AAAAkeyA", plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptWithAAD(keys.EncKey, enc, IdentityAAD("id-b", "ssh-ed25519 AAAAkeyA")); err == nil {
		t.Fatal("Vertauschen der Identity-ID muss scheitern")
	}
	if _, err := DecryptWithAAD(keys.EncKey, enc, IdentityAAD("id-a", "ssh-ed25519 AAAAkeyB")); err == nil {
		t.Fatal("Vertauschen des Public Keys muss scheitern")
	}
	got, err := DecryptIdentity(keys, "id-a", "ssh-ed25519 AAAAkeyA", enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("got %q", got)
	}
}

func TestDecryptIdentityReadsLegacyCiphertext(t *testing.T) {
	salt := bytes.Repeat([]byte{0x33}, SaltLen)
	keys := DeriveKeys("master-password-12", salt)
	plain := []byte("legacy-private")
	enc, err := Encrypt(keys.LegacyKey, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptIdentity(keys, "id", "pub", enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("got %q", got)
	}
}
