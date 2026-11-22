package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path+"?_foreign_keys=on&_journal_mode=WAL")
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	password_hash TEXT NOT NULL,
	kdf_salt BLOB NOT NULL,
	created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	token_hash TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL,
	last_seen TEXT
);

CREATE TABLE IF NOT EXISTS identities (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	public_key TEXT NOT NULL DEFAULT '',
	encrypted_private_key TEXT NOT NULL,
	comment TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
	id TEXT PRIMARY KEY,
	alias TEXT NOT NULL UNIQUE,
	host_name TEXT NOT NULL,
	user_name TEXT NOT NULL DEFAULT '',
	port INTEGER NOT NULL DEFAULT 22,
	identity_id TEXT REFERENCES identities(id) ON DELETE SET NULL,
	proxy_jump TEXT NOT NULL DEFAULT '',
	extra TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS profiles (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS profile_hosts (
	profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
	host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
	sort_order INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (profile_id, host_id)
);

CREATE TABLE IF NOT EXISTS profile_devices (
	profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
	device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	PRIMARY KEY (profile_id, device_id)
);
`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	if err := s.migrateCommands(); err != nil {
		return err
	}
	if err := s.migrateSettings(); err != nil {
		return err
	}
	if err := s.migrateHostSortOrder(); err != nil {
		return err
	}
	if err := s.migrateHostIdentitiesOnly(); err != nil {
		return err
	}
	return s.migrateUserAuthScheme()
}

func (s *Store) migrateUserAuthScheme() error {
	_, err := s.db.Exec(`ALTER TABLE users ADD COLUMN auth_scheme TEXT NOT NULL DEFAULT 'legacy'`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		return err
	}
	return nil
}

func (s *Store) migrateHostIdentitiesOnly() error {
	_, err := s.db.Exec(`ALTER TABLE hosts ADD COLUMN identities_only INTEGER NOT NULL DEFAULT 0`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		return err
	}
	return nil
}

func (s *Store) migrateHostSortOrder() error {
	_, err := s.db.Exec(`ALTER TABLE hosts ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		return err
	}
	return nil
}

func (s *Store) IsInitialized() (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n > 0, err
}

func (s *Store) CreateUser(passwordHash string, kdfSalt []byte) error {
	return s.CreateUserWithScheme(passwordHash, kdfSalt, AuthSchemeV1)
}

func (s *Store) CreateUserWithScheme(passwordHash string, kdfSalt []byte, scheme string) error {
	if scheme == "" {
		scheme = AuthSchemeV1
	}
	_, err := s.db.Exec(
		`INSERT INTO users (id, password_hash, kdf_salt, auth_scheme, created_at) VALUES (1, ?, ?, ?, ?)`,
		passwordHash, kdfSalt, scheme, time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

func (s *Store) GetUser() (*User, error) {
	var u User
	var created string
	err := s.db.QueryRow(`SELECT id, password_hash, kdf_salt, COALESCE(auth_scheme, 'legacy'), created_at FROM users WHERE id = 1`).Scan(
		&u.ID, &u.PasswordHash, &u.KDFSalt, &u.AuthScheme, &created,
	)
	if err != nil {
		return nil, err
	}
	u.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return &u, nil
}

func (s *Store) UpgradeAuthScheme(passwordHash string) error {
	_, err := s.db.Exec(
		`UPDATE users SET auth_scheme = ?, password_hash = ? WHERE id = 1`,
		AuthSchemeV1, passwordHash,
	)
	return err
}

func (s *Store) GetKDFSalt() ([]byte, error) {
	var salt []byte
	err := s.db.QueryRow(`SELECT kdf_salt FROM users WHERE id = 1`).Scan(&salt)
	return salt, err
}

func (s *Store) CreateDevice(d Device) error {
	_, err := s.db.Exec(
		`INSERT INTO devices (id, name, token_hash, created_at) VALUES (?, ?, ?, ?)`,
		d.ID, d.Name, d.TokenHash, d.CreatedAt.UTC().Format(time.RFC3339),
	)
	return err
}

func (s *Store) GetDeviceByTokenHash(hash string) (*Device, error) {
	return s.scanDevice(`SELECT id, name, token_hash, created_at, last_seen FROM devices WHERE token_hash = ?`, hash)
}

func (s *Store) GetDevice(id string) (*Device, error) {
	return s.scanDevice(`SELECT id, name, token_hash, created_at, last_seen FROM devices WHERE id = ?`, id)
}

func (s *Store) scanDevice(query string, arg any) (*Device, error) {
	var d Device
	var created string
	var lastSeen sql.NullString
	err := s.db.QueryRow(query, arg).Scan(&d.ID, &d.Name, &d.TokenHash, &created, &lastSeen)
	if err != nil {
		return nil, err
	}
	d.CreatedAt, _ = time.Parse(time.RFC3339, created)
	if lastSeen.Valid {
		t, _ := time.Parse(time.RFC3339, lastSeen.String)
		d.LastSeen = &t
	}
	return &d, nil
}

func (s *Store) ListDevices() ([]Device, error) {
	rows, err := s.db.Query(`SELECT id, name, token_hash, created_at, last_seen FROM devices ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanDevices(rows)
}

func (s *Store) TouchDevice(id string) error {
	_, err := s.db.Exec(`UPDATE devices SET last_seen = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339), id)
	return err
}

func (s *Store) DeleteDevice(id string) error {
	_, err := s.db.Exec(`DELETE FROM devices WHERE id = ?`, id)
	return err
}

func (s *Store) UpsertIdentity(i Identity) error {
	now := time.Now().UTC().Format(time.RFC3339)
	created := now
	if !i.CreatedAt.IsZero() {
		created = i.CreatedAt.UTC().Format(time.RFC3339)
	}
	_, err := s.db.Exec(`
		INSERT INTO identities (id, name, public_key, encrypted_private_key, comment, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			public_key = excluded.public_key,
			encrypted_private_key = excluded.encrypted_private_key,
			comment = excluded.comment,
			updated_at = excluded.updated_at
	`, i.ID, i.Name, i.PublicKey, i.EncryptedPrivateKey, i.Comment, created, now)
	return err
}

func (s *Store) ListIdentities() ([]Identity, error) {
	rows, err := s.db.Query(`SELECT id, name, public_key, encrypted_private_key, comment, created_at, updated_at FROM identities ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Identity
	for rows.Next() {
		var i Identity
		var created, updated string
		if err := rows.Scan(&i.ID, &i.Name, &i.PublicKey, &i.EncryptedPrivateKey, &i.Comment, &created, &updated); err != nil {
			return nil, err
		}
		i.CreatedAt, _ = time.Parse(time.RFC3339, created)
		i.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		out = append(out, i)
	}
	return out, rows.Err()
}

func (s *Store) DeleteIdentity(id string) error {
	_, err := s.db.Exec(`DELETE FROM identities WHERE id = ?`, id)
	return err
}

func (s *Store) UpsertHost(h Host) error {
	now := time.Now().UTC().Format(time.RFC3339)
	created := now
	if !h.CreatedAt.IsZero() {
		created = h.CreatedAt.UTC().Format(time.RFC3339)
	}
	_, err := s.db.Exec(`
		INSERT INTO hosts (id, alias, host_name, user_name, port, identity_id, proxy_jump, identities_only, extra, sort_order, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			alias = excluded.alias,
			host_name = excluded.host_name,
			user_name = excluded.user_name,
			port = excluded.port,
			identity_id = excluded.identity_id,
			proxy_jump = excluded.proxy_jump,
			identities_only = excluded.identities_only,
			extra = excluded.extra,
			sort_order = excluded.sort_order,
			updated_at = excluded.updated_at
	`, h.ID, h.Alias, h.HostName, h.User, h.Port, h.IdentityID, h.ProxyJump, boolToInt(h.IdentitiesOnly), h.Extra, h.SortOrder, created, now)
	return err
}

func (s *Store) ListHosts() ([]Host, error) {
	rows, err := s.db.Query(`SELECT id, alias, host_name, user_name, port, identity_id, proxy_jump, identities_only, extra, sort_order, created_at, updated_at FROM hosts ORDER BY sort_order, alias`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		var h Host
		var created, updated string
		var identityID sql.NullString
		var identitiesOnly int
		if err := rows.Scan(&h.ID, &h.Alias, &h.HostName, &h.User, &h.Port, &identityID, &h.ProxyJump, &identitiesOnly, &h.Extra, &h.SortOrder, &created, &updated); err != nil {
			return nil, err
		}
		h.IdentitiesOnly = identitiesOnly != 0
		if identityID.Valid {
			v := identityID.String
			h.IdentityID = &v
		}
		h.CreatedAt, _ = time.Parse(time.RFC3339, created)
		h.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) DeleteHost(id string) error {
	_, err := s.db.Exec(`DELETE FROM hosts WHERE id = ?`, id)
	return err
}

func (s *Store) SyncBundleForDevice(deviceID string) (*SyncBundle, error) {
	hosts, err := s.ListHosts()
	if err != nil {
		return nil, err
	}
	identities, err := s.ListIdentities()
	if err != nil {
		return nil, err
	}

	// Aktuell: alle Hosts an jedes Geraet. Die Tabellen profiles/* sind ungenutzt;
	// Doku beschreibt dieses Verhalten (M1). Keys nur, wenn mindestens einem Host zugewiesen.
	neededIdentities := map[string]bool{}
	for _, h := range hosts {
		if h.IdentityID != nil {
			neededIdentities[*h.IdentityID] = true
		}
	}
	filteredIdentities := filterIdentities(identities, neededIdentities)

	return &SyncBundle{
		Hosts:      hosts,
		Identities: filteredIdentities,
		DeviceIDs:  []string{deviceID},
	}, nil
}

func filterIdentities(in []Identity, needed map[string]bool) []Identity {
	var out []Identity
	for _, i := range in {
		if needed[i.ID] {
			out = append(out, i)
		}
	}
	return out
}

func scanDevices(rows *sql.Rows) ([]Device, error) {
	var out []Device
	for rows.Next() {
		var d Device
		var created string
		var lastSeen sql.NullString
		if err := rows.Scan(&d.ID, &d.Name, &d.TokenHash, &created, &lastSeen); err != nil {
			return nil, err
		}
		d.CreatedAt, _ = time.Parse(time.RFC3339, created)
		if lastSeen.Valid {
			t, _ := time.Parse(time.RFC3339, lastSeen.String)
			d.LastSeen = &t
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) DB() *sql.DB {
	return s.db
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func FormatErr(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w", err)
}
