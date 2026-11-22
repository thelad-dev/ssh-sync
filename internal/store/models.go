package store

import "time"

const (
	AuthSchemeLegacy = "legacy"
	AuthSchemeV1     = "auth_v1"
)

type User struct {
	ID           int64
	PasswordHash string
	KDFSalt      []byte
	AuthScheme   string
	CreatedAt    time.Time
}

type Device struct {
	ID        string
	Name      string
	TokenHash string
	CreatedAt time.Time
	LastSeen  *time.Time
}

type Identity struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	PublicKey           string    `json:"public_key"`
	EncryptedPrivateKey string    `json:"encrypted_private_key"`
	Comment             string    `json:"comment"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type Host struct {
	ID             string    `json:"id"`
	Alias          string    `json:"alias"`
	HostName       string    `json:"host_name"`
	User           string    `json:"user"`
	Port           int       `json:"port"`
	IdentityID     *string   `json:"identity_id"`
	ProxyJump      string    `json:"proxy_jump"`
	IdentitiesOnly bool      `json:"identities_only"`
	Extra          string    `json:"extra"`
	SortOrder      int       `json:"sort_order"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type SyncBundle struct {
	Hosts      []Host     `json:"hosts"`
	Identities []Identity `json:"identities"`
	DeviceIDs  []string   `json:"device_ids"`
}
