package accountexport

import (
	"encoding/hex"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/store"
)

const (
	FormatID      = "ssh-sync-account-export"
	SchemaVersion = 1
	// MaxArchiveBytes begrenzt die Dateigroesse (kein Zip; JSON-Bombe).
	MaxArchiveBytes = 64 << 20
	IntegrityAlg    = "hmac-sha256"
)

// Envelope ist das versionierte Konten-Archiv (eine JSON-Datei).
type Envelope struct {
	Format        string    `json:"format"`
	SchemaVersion int       `json:"schema_version"`
	ExportedAt    time.Time `json:"exported_at"`
	Integrity     Integrity `json:"integrity"`
	Payload       Payload   `json:"payload"`
}

// Integrity schuetzt das Payload gegen Manipulation.
type Integrity struct {
	Alg string `json:"alg"`
	MAC string `json:"mac"`
}

// Payload enthaelt Kontodaten; Private Keys bleiben verschluesselt wie gespeichert.
type Payload struct {
	KDFSalt    string            `json:"kdf_salt"`
	AuthScheme string            `json:"auth_scheme"`
	Identities []IdentityEntry   `json:"identities"`
	Hosts      []HostEntry       `json:"hosts"`
	Devices    []DeviceEntry     `json:"devices"`
	Settings   map[string]string `json:"settings"`
	Metadata   map[string]string `json:"metadata"`
}

type IdentityEntry struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	PublicKey           string `json:"public_key"`
	EncryptedPrivateKey string `json:"encrypted_private_key"`
	Comment             string `json:"comment"`
}

type HostEntry struct {
	ID             string  `json:"id"`
	Alias          string  `json:"alias"`
	HostName       string  `json:"host_name"`
	User           string  `json:"user"`
	Port           int     `json:"port"`
	IdentityID     *string `json:"identity_id,omitempty"`
	ProxyJump      string  `json:"proxy_jump,omitempty"`
	IdentitiesOnly bool    `json:"identities_only,omitempty"`
	Extra          string  `json:"extra,omitempty"`
	SortOrder      int     `json:"sort_order,omitempty"`
}

// DeviceEntry enthaelt nur Anzeigenamen; TokenHashes werden nie exportiert.
type DeviceEntry struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

// ConflictMode steuert den Import.
type ConflictMode string

const (
	ModeMerge   ConflictMode = "merge"
	ModeReplace ConflictMode = "replace"
)

// Report beschreibt Trockenlauf oder Import-Ergebnis.
type Report struct {
	DryRun             bool     `json:"dry_run"`
	Mode               string   `json:"mode"`
	IdentitiesUpserted int      `json:"identities_upserted"`
	IdentitiesSkipped  int      `json:"identities_skipped"`
	HostsUpserted      int      `json:"hosts_upserted"`
	HostsSkipped       int      `json:"hosts_skipped"`
	HostsDeleted       int      `json:"hosts_deleted,omitempty"`
	IdentitiesDeleted  int      `json:"identities_deleted,omitempty"`
	SettingsWritten    int      `json:"settings_written"`
	DevicesNoted       int      `json:"devices_noted"`
	Conflicts          []string `json:"conflicts,omitempty"`
	Notes              []string `json:"notes,omitempty"`
}

// FromStore baut ein Payload aus dem Store (Keys bleiben Ciphertext).
func FromStore(identities []store.Identity, hosts []store.Host, devices []store.Device, salt []byte, scheme string, settings map[string]string) Payload {
	p := Payload{
		KDFSalt:    encodeHex(salt),
		AuthScheme: scheme,
		Settings:   settings,
		Metadata: map[string]string{
			"generator": "ssh-sync",
		},
	}
	if p.Settings == nil {
		p.Settings = map[string]string{}
	}
	for _, id := range identities {
		p.Identities = append(p.Identities, IdentityEntry{
			ID:                  id.ID,
			Name:                id.Name,
			PublicKey:           id.PublicKey,
			EncryptedPrivateKey: id.EncryptedPrivateKey,
			Comment:             id.Comment,
		})
	}
	for _, h := range hosts {
		p.Hosts = append(p.Hosts, HostEntry{
			ID:             h.ID,
			Alias:          h.Alias,
			HostName:       h.HostName,
			User:           h.User,
			Port:           h.Port,
			IdentityID:     h.IdentityID,
			ProxyJump:      h.ProxyJump,
			IdentitiesOnly: h.IdentitiesOnly,
			Extra:          h.Extra,
			SortOrder:      h.SortOrder,
		})
	}
	for _, d := range devices {
		p.Devices = append(p.Devices, DeviceEntry{ID: d.ID, Name: d.Name})
	}
	return p
}

func encodeHex(b []byte) string {
	return hex.EncodeToString(b)
}
