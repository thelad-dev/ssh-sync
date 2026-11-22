package backup

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/crypto"
)

const (
	FormatID = "ssh-sync-backup"
	Version  = 1
)

// Data ist der Klartext-Inhalt eines Backups (nur innerhalb der Verschlüsselung).
type Data struct {
	Format     string          `json:"format"`
	Version    int             `json:"version"`
	ExportedAt time.Time       `json:"exported_at"`
	Identities []IdentityEntry `json:"identities"`
	Hosts      []HostEntry     `json:"hosts"`
	Devices    []DeviceEntry   `json:"devices"`
}

type IdentityEntry struct {
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
	Comment    string `json:"comment"`
}

type HostEntry struct {
	Alias          string `json:"alias"`
	HostName       string `json:"host_name"`
	User           string `json:"user"`
	Port           int    `json:"port"`
	IdentityName   string `json:"identity_name,omitempty"`
	ProxyJump      string `json:"proxy_jump,omitempty"`
	IdentitiesOnly bool   `json:"identities_only,omitempty"`
	Extra          string `json:"extra,omitempty"`
}

type DeviceEntry struct {
	Name string `json:"name"`
}

// Envelope ist die gespeicherte Backup-Datei.
type Envelope struct {
	Format     string `json:"format"`
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Salt       string `json:"salt"`
	Ciphertext string `json:"ciphertext"`
}

// Encrypt serialisiert und verschlüsselt Backup-Daten mit dem Passwort.
func Encrypt(password string, data *Data) ([]byte, error) {
	if data == nil {
		return nil, errors.New("keine Backup-Daten")
	}
	data.Format = FormatID
	data.Version = Version
	if data.ExportedAt.IsZero() {
		data.ExportedAt = time.Now().UTC()
	}
	plain, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	salt, err := crypto.NewSalt()
	if err != nil {
		return nil, err
	}
	key := crypto.DeriveKey(password, salt)
	ct, err := crypto.Encrypt(key, plain)
	if err != nil {
		return nil, err
	}
	env := Envelope{
		Format:     FormatID,
		Version:    Version,
		KDF:        "argon2id",
		Salt:       hex.EncodeToString(salt),
		Ciphertext: ct,
	}
	return json.MarshalIndent(env, "", "  ")
}

// Decrypt entschlüsselt eine Backup-Datei.
func Decrypt(password string, raw []byte) (*Data, error) {
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("ungültige Backup-Datei: %w", err)
	}
	if env.Format != FormatID {
		return nil, errors.New("unbekanntes Backup-Format")
	}
	if env.Version != Version {
		return nil, fmt.Errorf("Backup-Version %d wird nicht unterstützt", env.Version)
	}
	salt, err := hex.DecodeString(env.Salt)
	if err != nil {
		return nil, fmt.Errorf("ungültiges Salt: %w", err)
	}
	key := crypto.DeriveKey(password, salt)
	plain, err := crypto.Decrypt(key, env.Ciphertext)
	if err != nil {
		return nil, errors.New("Entschlüsselung fehlgeschlagen — falsches Passwort?")
	}
	var data Data
	if err := json.Unmarshal(plain, &data); err != nil {
		return nil, err
	}
	if data.Format != FormatID {
		return nil, errors.New("ungültiger Backup-Inhalt")
	}
	return &data, nil
}
