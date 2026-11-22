package accountexport

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/thelad-dev/ssh-sync/internal/sshconfig"
)

var resourceIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidatePayload prueft Felder und H2-Allowlist (kein ungeprueftes ssh_config-Material).
func ValidatePayload(p *Payload) error {
	if p == nil {
		return fmt.Errorf("Payload fehlt")
	}
	if strings.TrimSpace(p.KDFSalt) == "" {
		return fmt.Errorf("kdf_salt fehlt")
	}
	seenID := map[string]bool{}
	for i, id := range p.Identities {
		if !resourceIDPattern.MatchString(id.ID) {
			return fmt.Errorf("identity[%d]: ungueltige id", i)
		}
		if strings.TrimSpace(id.Name) == "" {
			return fmt.Errorf("identity[%d]: name fehlt", i)
		}
		if strings.TrimSpace(id.EncryptedPrivateKey) == "" {
			return fmt.Errorf("identity[%d]: encrypted_private_key fehlt", i)
		}
		if seenID[id.ID] {
			return fmt.Errorf("identity[%d]: doppelte id", i)
		}
		seenID[id.ID] = true
	}
	seenHost := map[string]bool{}
	seenAlias := map[string]bool{}
	for i, h := range p.Hosts {
		if !resourceIDPattern.MatchString(h.ID) {
			return fmt.Errorf("host[%d]: ungueltige id", i)
		}
		if seenHost[h.ID] {
			return fmt.Errorf("host[%d]: doppelte id", i)
		}
		seenHost[h.ID] = true
		extra, err := sshconfig.NormalizeExtra(h.Extra)
		if err != nil {
			return fmt.Errorf("host %s: %w", h.Alias, err)
		}
		if err := sshconfig.ValidateHostFields(h.Alias, h.HostName, h.User, h.ProxyJump, extra); err != nil {
			return fmt.Errorf("host %s: %w", h.Alias, err)
		}
		p.Hosts[i].Extra = extra
		if h.IdentityID != nil && *h.IdentityID != "" && !resourceIDPattern.MatchString(*h.IdentityID) {
			return fmt.Errorf("host %s: ungueltige identity_id", h.Alias)
		}
		if seenAlias[h.Alias] {
			return fmt.Errorf("host %s: doppelter alias", h.Alias)
		}
		seenAlias[h.Alias] = true
	}
	for i, d := range p.Devices {
		if strings.TrimSpace(d.Name) == "" {
			return fmt.Errorf("device[%d]: name fehlt", i)
		}
	}
	return nil
}

// MigratePayloadForward zieht aeltere Schema-Versionen auf den aktuellen Stand.
func MigratePayloadForward(schemaVersion int, p *Payload) error {
	if schemaVersion < 1 {
		return fmt.Errorf("schema_version %d nicht unterstuetzt", schemaVersion)
	}
	if schemaVersion > SchemaVersion {
		return fmt.Errorf("schema_version %d zu neu", schemaVersion)
	}
	// Schema 1 ist aktuell; Platzhalter fuer kuenftige Migrationen.
	if p.Settings == nil {
		p.Settings = map[string]string{}
	}
	if p.Metadata == nil {
		p.Metadata = map[string]string{}
	}
	if p.AuthScheme == "" {
		p.AuthScheme = "auth_v1"
	}
	return nil
}
