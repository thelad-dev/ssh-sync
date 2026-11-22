package clientauth

import (
	"encoding/hex"
	"fmt"

	"github.com/thelad-dev/ssh-sync/internal/client"
	"github.com/thelad-dev/ssh-sync/internal/crypto"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

// PortalLogin meldet sich mit Auth-Key an und migriert Legacy-Konten bei Bedarf.
// Das Master-Passwort verlaesst den Client nur, wenn der Server das Konto als legacy meldet.
func PortalLogin(api *client.API, master string) (crypto.DerivedKeys, error) {
	salt, err := api.KDFSalt()
	if err != nil {
		return crypto.DerivedKeys{}, fmt.Errorf("kdf-salt: %w", err)
	}
	keys := crypto.DeriveKeys(master, salt)
	authHex := hex.EncodeToString(keys.AuthKey)

	res, err := api.LoginWithAuthKey(authHex)
	if err == nil {
		api.Token = res.Token
		return keys, nil
	}
	if !client.IsLegacyAuthRequired(err) {
		return crypto.DerivedKeys{}, err
	}

	res, err = api.LoginLegacyPassword(master)
	if err != nil {
		return crypto.DerivedKeys{}, err
	}
	api.Token = res.Token
	if res.AuthScheme == store.AuthSchemeV1 {
		return keys, nil
	}
	if err := UpgradeLegacy(api, keys, master); err != nil {
		return crypto.DerivedKeys{}, fmt.Errorf("auth-upgrade: %w", err)
	}
	return keys, nil
}

// UpgradeLegacy verschluesselt Identities neu und stellt auth_v1 ein.
// password ist das bisherige Legacy-Master-Passwort (Server-Nachweis).
func UpgradeLegacy(api *client.API, keys crypto.DerivedKeys, password string) error {
	list, err := api.ListIdentities()
	if err != nil {
		return err
	}
	var upgraded []client.AuthUpgradeIdentity
	for _, id := range list {
		plain, err := crypto.DecryptIdentity(keys, id.ID, id.PublicKey, id.EncryptedPrivateKey)
		if err != nil {
			return fmt.Errorf("identity %s: %w", id.Name, err)
		}
		enc, err := crypto.EncryptIdentity(keys, id.ID, id.PublicKey, plain)
		if err != nil {
			return fmt.Errorf("identity %s neu verschluesseln: %w", id.Name, err)
		}
		upgraded = append(upgraded, client.AuthUpgradeIdentity{
			ID:                  id.ID,
			EncryptedPrivateKey: enc,
		})
	}
	return api.UpgradeAuth(hex.EncodeToString(keys.AuthKey), password, upgraded)
}
