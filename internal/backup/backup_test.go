package backup

import "testing"

func TestEncryptDecryptRoundtrip(t *testing.T) {
	data := &Data{
		Identities: []IdentityEntry{{Name: "github", PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n", PublicKey: "ssh-ed25519 AAA"}},
		Hosts:      []HostEntry{{Alias: "srv", HostName: "10.0.0.1", Port: 22, IdentityName: "github"}},
	}
	raw, err := Encrypt("test-password-123", data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt("test-password-123", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Identities) != 1 || got.Identities[0].Name != "github" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	raw, _ := Encrypt("correct-password", &Data{})
	if _, err := Decrypt("wrong-password", raw); err == nil {
		t.Fatal("falsches Passwort hätte Fehler erzeugen müssen")
	}
}
