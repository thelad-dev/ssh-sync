package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"strings"
	"time"
)

const (
	CommandSync    = "sync"
	CommandImport  = "import"
	CommandPurge   = "purge"
	StatusPending  = "pending"
	StatusRunning  = "running"
	StatusComplete = "completed"
	StatusFailed   = "failed"
)

type DeviceCommand struct {
	ID            string
	DeviceID      string
	Command       string
	Payload       string
	Status        string
	CreatedAt     time.Time
	StartedAt     *time.Time
	CompletedAt   *time.Time
	ResultMessage string
}

func (s *Store) migrateCommands() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS device_commands (
	id TEXT PRIMARY KEY,
	device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	command TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'pending',
	created_at TEXT NOT NULL,
	started_at TEXT,
	completed_at TEXT,
	result_message TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_device_commands_device_status ON device_commands(device_id, status);
`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`ALTER TABLE device_commands ADD COLUMN payload TEXT NOT NULL DEFAULT ''`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		return err
	}
	return nil
}

func (s *Store) EnqueueCommand(deviceID, command string) (*DeviceCommand, error) {
	return s.EnqueueCommandWithPayload(deviceID, command, "")
}

func (s *Store) EnqueueCommandWithPayload(deviceID, command, payload string) (*DeviceCommand, error) {
	id, err := newRandID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	c := DeviceCommand{
		ID:        id,
		DeviceID:  deviceID,
		Command:   command,
		Payload:   payload,
		Status:    StatusPending,
		CreatedAt: now,
	}
	_, err = s.db.Exec(
		`INSERT INTO device_commands (id, device_id, command, payload, status, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		c.ID, c.DeviceID, c.Command, c.Payload, c.Status, c.CreatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) ClaimNextCommand(deviceID string) (*DeviceCommand, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var c DeviceCommand
	var created string
	err = tx.QueryRow(`
		SELECT id, device_id, command, COALESCE(payload, ''), status, created_at
		FROM device_commands
		WHERE device_id = ? AND status = ?
		ORDER BY created_at ASC
		LIMIT 1
	`, deviceID, StatusPending).Scan(&c.ID, &c.DeviceID, &c.Command, &c.Payload, &c.Status, &created)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.CreatedAt, _ = time.Parse(time.RFC3339, created)
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.Exec(
		`UPDATE device_commands SET status = ?, started_at = ? WHERE id = ? AND status = ?`,
		StatusRunning, now, c.ID, StatusPending,
	); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	c.Status = StatusRunning
	t, _ := time.Parse(time.RFC3339, now)
	c.StartedAt = &t
	return &c, nil
}

func (s *Store) CompleteCommand(id, status, message string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(
		`UPDATE device_commands SET status = ?, completed_at = ?, result_message = ? WHERE id = ?`,
		status, now, message, id,
	)
	return err
}

func (s *Store) HasActiveCommand(deviceID, command string) (bool, error) {
	var n int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM device_commands
		WHERE device_id = ? AND command = ? AND status IN (?, ?)
	`, deviceID, command, StatusPending, StatusRunning).Scan(&n)
	return n > 0, err
}

func (s *Store) GetCommand(id string) (*DeviceCommand, error) {
	var c DeviceCommand
	var created, started, completed sql.NullString
	err := s.db.QueryRow(`
		SELECT id, device_id, command, COALESCE(payload, ''), status, created_at, started_at, completed_at, result_message
		FROM device_commands WHERE id = ?
	`, id).Scan(&c.ID, &c.DeviceID, &c.Command, &c.Payload, &c.Status, &created, &started, &completed, &c.ResultMessage)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.CreatedAt, _ = time.Parse(time.RFC3339, created.String)
	if started.Valid {
		t, _ := time.Parse(time.RFC3339, started.String)
		c.StartedAt = &t
	}
	if completed.Valid {
		t, _ := time.Parse(time.RFC3339, completed.String)
		c.CompletedAt = &t
	}
	return &c, nil
}

func (s *Store) LastCommandForDevice(deviceID string) (*DeviceCommand, error) {
	var c DeviceCommand
	var created, started, completed sql.NullString
	err := s.db.QueryRow(`
		SELECT id, device_id, command, COALESCE(payload, ''), status, created_at, started_at, completed_at, result_message
		FROM device_commands WHERE device_id = ? ORDER BY created_at DESC LIMIT 1
	`, deviceID).Scan(&c.ID, &c.DeviceID, &c.Command, &c.Payload, &c.Status, &created, &started, &completed, &c.ResultMessage)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.CreatedAt, _ = time.Parse(time.RFC3339, created.String)
	if started.Valid {
		t, _ := time.Parse(time.RFC3339, started.String)
		c.StartedAt = &t
	}
	if completed.Valid {
		t, _ := time.Parse(time.RFC3339, completed.String)
		c.CompletedAt = &t
	}
	return &c, nil
}

func newRandID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
