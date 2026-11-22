package backup

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/thelad-dev/ssh-sync/internal/client"
	"github.com/thelad-dev/ssh-sync/internal/crypto"
)

type RestoreOptions struct {
	SkipExisting bool
}

type RestoreResult struct {
	Identities int
	Hosts      int
	Skipped    int
}

// Restore laedt Backup-Daten auf den Server (Identities werden neu verschluesselt).
func Restore(api *client.API, keys crypto.DerivedKeys, data *Data, opts RestoreOptions) (*RestoreResult, error) {
	existingNames := map[string]bool{}
	existingAliases := map[string]bool{}
	if opts.SkipExisting {
		if list, err := api.ListIdentities(); err == nil {
			for _, i := range list {
				existingNames[i.Name] = true
			}
		}
		if list, err := api.ListHosts(); err == nil {
			for _, h := range list {
				existingAliases[h.Alias] = true
			}
		}
	}

	res := &RestoreResult{}
	identityIDs := map[string]string{}

	for _, id := range data.Identities {
		if existingNames[id.Name] {
			res.Skipped++
			if list, err := api.ListIdentities(); err == nil {
				for _, e := range list {
					if e.Name == id.Name {
						identityIDs[id.Name] = e.ID
					}
				}
			}
			continue
		}
		newID, err := newID()
		if err != nil {
			return nil, err
		}
		enc, err := crypto.EncryptIdentity(keys, newID, id.PublicKey, []byte(id.PrivateKey))
		if err != nil {
			return nil, err
		}
		if err := api.PutIdentity(newID, client.IdentityPayload{
			Name:                id.Name,
			PublicKey:           id.PublicKey,
			EncryptedPrivateKey: enc,
			Comment:             id.Comment,
		}); err != nil {
			return nil, fmt.Errorf("identity %q: %w", id.Name, err)
		}
		identityIDs[id.Name] = newID
		res.Identities++
	}

	for _, h := range data.Hosts {
		if existingAliases[h.Alias] {
			res.Skipped++
			continue
		}
		newID, err := newID()
		if err != nil {
			return nil, err
		}
		var identityID *string
		if h.IdentityName != "" {
			if v, ok := identityIDs[h.IdentityName]; ok {
				identityID = &v
			}
		}
		port := h.Port
		if port == 0 {
			port = 22
		}
		if err := api.PutHost(newID, client.HostPayload{
			Alias:          h.Alias,
			HostName:       h.HostName,
			User:           h.User,
			Port:           port,
			IdentityID:     identityID,
			ProxyJump:      h.ProxyJump,
			IdentitiesOnly: h.IdentitiesOnly,
			Extra:          h.Extra,
		}); err != nil {
			return nil, fmt.Errorf("host %q: %w", h.Alias, err)
		}
		res.Hosts++
	}

	return res, nil
}

func newID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
