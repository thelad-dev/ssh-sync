package accountexport

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/crypto"
)

// wireEnvelope ist das Dateiformat; Payload bleibt Raw fuer stabile MACs.
type wireEnvelope struct {
	Format        string          `json:"format"`
	SchemaVersion int             `json:"schema_version"`
	ExportedAt    time.Time       `json:"exported_at"`
	Integrity     Integrity       `json:"integrity"`
	Payload       json.RawMessage `json:"payload"`
}

// Seal baut ein signiertes Archiv. password ist das Master-Passwort (nur lokal).
func Seal(password string, payload Payload) ([]byte, error) {
	if password == "" {
		return nil, errors.New("Master-Passwort erforderlich")
	}
	salt, err := hex.DecodeString(payload.KDFSalt)
	if err != nil || len(salt) != crypto.SaltLen {
		return nil, errors.New("kdf_salt ungueltig")
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	macKey := crypto.DeriveExportMACKey(password, salt)
	mac := hmac.New(sha256.New, macKey)
	_, _ = mac.Write(payloadJSON)
	env := wireEnvelope{
		Format:        FormatID,
		SchemaVersion: SchemaVersion,
		ExportedAt:    time.Now().UTC(),
		Integrity: Integrity{
			Alg: IntegrityAlg,
			MAC: hex.EncodeToString(mac.Sum(nil)),
		},
		Payload: payloadJSON,
	}
	// Kompakt serialisieren: MarshalIndent wuerde RawMessage umbrechen und den MAC brechen.
	out, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	if len(out) > MaxArchiveBytes {
		return nil, fmt.Errorf("Archiv zu gross (%d Bytes, Limit %d)", len(out), MaxArchiveBytes)
	}
	return out, nil
}

// Open liest und prueft Schema sowie HMAC.
func Open(password string, raw []byte) (*Envelope, error) {
	if len(raw) == 0 {
		return nil, errors.New("leeres Archiv")
	}
	if len(raw) > MaxArchiveBytes {
		return nil, fmt.Errorf("Archiv zu gross (%d Bytes, Limit %d)", len(raw), MaxArchiveBytes)
	}
	n, err := countTopLevelKey(raw, "payload")
	if err != nil {
		return nil, fmt.Errorf("ungueltiges Archiv: %w", err)
	}
	if n != 1 {
		return nil, errors.New("Archiv enthaelt nicht genau ein payload")
	}
	var wire wireEnvelope
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("ungueltiges Archiv: %w", err)
	}
	if wire.Format != FormatID {
		return nil, errors.New("unbekanntes Archiv-Format")
	}
	if wire.SchemaVersion < 1 {
		return nil, errors.New("schema_version fehlt oder ungueltig")
	}
	if wire.SchemaVersion > SchemaVersion {
		return nil, fmt.Errorf("Archiv-Version %d neuer als unterstuetzt (%d)", wire.SchemaVersion, SchemaVersion)
	}
	if wire.Integrity.Alg != IntegrityAlg {
		return nil, fmt.Errorf("unbekannter Integritaetsalgorithmus %q", wire.Integrity.Alg)
	}
	var payload Payload
	if err := json.Unmarshal(wire.Payload, &payload); err != nil {
		return nil, fmt.Errorf("Payload ungueltig: %w", err)
	}
	salt, err := hex.DecodeString(payload.KDFSalt)
	if err != nil || len(salt) != crypto.SaltLen {
		return nil, errors.New("kdf_salt im Archiv ungueltig")
	}
	macKey := crypto.DeriveExportMACKey(password, salt)
	mac := hmac.New(sha256.New, macKey)
	_, _ = mac.Write(wire.Payload)
	want, err := hex.DecodeString(wire.Integrity.MAC)
	if err != nil {
		return nil, errors.New("Integritaets-MAC ungueltig")
	}
	if !hmac.Equal(want, mac.Sum(nil)) {
		return nil, errors.New("Integritaetspruefung fehlgeschlagen (falsches Passwort oder manipuliertes Archiv)")
	}
	if err := ValidatePayload(&payload); err != nil {
		return nil, err
	}
	return &Envelope{
		Format:        wire.Format,
		SchemaVersion: wire.SchemaVersion,
		ExportedAt:    wire.ExportedAt,
		Integrity:     wire.Integrity,
		Payload:       payload,
	}, nil
}

// countTopLevelKey zaehlt einen Objekt-Schluessel auf der obersten Ebene (\u-Escapes werden aufgeloest).
func countTopLevelKey(raw []byte, want string) (int, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return 0, err
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return 0, errors.New("Objekt erwartet")
	}
	n := 0
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return 0, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return 0, errors.New("Schluessel erwartet")
		}
		if key == want {
			n++
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return 0, err
		}
	}
	if _, err := dec.Token(); err != nil {
		return 0, err
	}
	return n, nil
}
