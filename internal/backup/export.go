package backup

import (
	"time"

	"github.com/thelad-dev/ssh-sync/internal/client"
	"github.com/thelad-dev/ssh-sync/internal/crypto"
)

// BuildFromServer laedt alle Daten und entschluesselt Private Keys fuer das Backup.
func BuildFromServer(api *client.API, keys crypto.DerivedKeys) (*Data, error) {
	identities, err := api.ListIdentities()
	if err != nil {
		return nil, err
	}
	hosts, err := api.ListHosts()
	if err != nil {
		return nil, err
	}
	devices, err := api.ListDevices()
	if err != nil {
		return nil, err
	}

	idNames := map[string]string{}
	for _, i := range identities {
		idNames[i.ID] = i.Name
	}

	data := &Data{
		ExportedAt: time.Now().UTC(),
	}

	for _, i := range identities {
		plain, err := crypto.DecryptIdentity(keys, i.ID, i.PublicKey, i.EncryptedPrivateKey)
		if err != nil {
			return nil, err
		}
		data.Identities = append(data.Identities, IdentityEntry{
			Name:       i.Name,
			PublicKey:  i.PublicKey,
			PrivateKey: string(plain),
			Comment:    i.Comment,
		})
	}

	for _, h := range hosts {
		entry := HostEntry{
			Alias:          h.Alias,
			HostName:       h.HostName,
			User:           h.User,
			Port:           h.Port,
			ProxyJump:      h.ProxyJump,
			IdentitiesOnly: h.IdentitiesOnly,
			Extra:          h.Extra,
		}
		if h.IdentityID != nil {
			entry.IdentityName = idNames[*h.IdentityID]
		}
		data.Hosts = append(data.Hosts, entry)
	}

	for _, d := range devices {
		data.Devices = append(data.Devices, DeviceEntry{Name: d.Name})
	}

	return data, nil
}
