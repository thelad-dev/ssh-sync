package agentsync

import (
	"fmt"

	"github.com/thelad-dev/ssh-sync/internal/agentconfig"
	"github.com/thelad-dev/ssh-sync/internal/client"
	"github.com/thelad-dev/ssh-sync/internal/crypto"
	"github.com/thelad-dev/ssh-sync/internal/importlocal"
	"github.com/thelad-dev/ssh-sync/internal/releaseverify"
)

// ImportResult beschreibt einen Upload von ~/.ssh zum Server.
type ImportResult struct {
	Identities        int
	Hosts             int
	SkippedIdentities int
	SkippedHosts      int
	Conflicts         []string
}

// ImportLocal liest ~/.ssh und laedt Config + Keys zum Server.
// master bleibt lokal fuer die Verschluesselung; es geht kein Klartext-Passwort an den Server.
func ImportLocal(cfg *agentconfig.Config, master string, skipExisting bool) (*ImportResult, error) {
	if err := releaseverify.CheckServerURL(cfg.ServerURL, false); err != nil {
		return nil, err
	}
	sshDir := cfg.ResolveSSHDir()
	bundle, err := importlocal.LoadSSHDir(sshDir)
	if err != nil {
		return nil, err
	}

	api := client.New(cfg.ServerURL, cfg.JWT)
	api.AccessClientID = cfg.AccessClientID
	api.AccessClientSecret = cfg.AccessClientSecret

	salt, err := api.KDFSalt()
	if err != nil {
		return nil, fmt.Errorf("kdf-salt: %w", err)
	}
	keys := crypto.DeriveKeys(master, salt)

	payload := client.AgentImportPayload{
		SkipExisting: skipExisting,
	}
	for _, id := range bundle.Identities {
		enc, err := crypto.EncryptIdentity(keys, id.ID, id.PublicKey, id.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("verschluesseln %s: %w", id.Name, err)
		}
		payload.Identities = append(payload.Identities, client.AgentImportIdentity{
			ID:                  id.ID,
			Name:                id.Name,
			PublicKey:           id.PublicKey,
			EncryptedPrivateKey: enc,
			Comment:             "importiert von " + id.Path,
		})
	}
	for _, h := range bundle.Hosts {
		identityID := bundle.IdentityIDForPath(sshDir, h.IdentityPath)
		payload.Hosts = append(payload.Hosts, client.AgentImportHost{
			ID:             h.ID,
			Alias:          h.Alias,
			HostName:       h.HostName,
			User:           h.User,
			Port:           h.Port,
			IdentityID:     identityID,
			ProxyJump:      h.ProxyJump,
			IdentitiesOnly: h.IdentitiesOnly,
		})
	}

	res, err := api.AgentImport(payload)
	if err != nil {
		return nil, err
	}
	out := &ImportResult{
		Identities:        res.Identities,
		Hosts:             res.Hosts,
		SkippedIdentities: res.SkippedIdentities,
		SkippedHosts:      res.SkippedHosts,
		Conflicts:         res.Conflicts,
	}
	return out, nil
}

func (r *ImportResult) Summary() string {
	msg := fmt.Sprintf("%d Keys, %d Hosts neu", r.Identities, r.Hosts)
	if r.SkippedIdentities > 0 || r.SkippedHosts > 0 {
		msg += fmt.Sprintf("; uebersprungen %d Keys, %d Hosts", r.SkippedIdentities, r.SkippedHosts)
	}
	if len(r.Conflicts) > 0 {
		msg += fmt.Sprintf("; %d Konflikt(e)", len(r.Conflicts))
	}
	return msg
}
