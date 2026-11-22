package accountexport

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/crypto"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

// ApplyOptions steuert Import in den Store.
type ApplyOptions struct {
	Mode   ConflictMode
	DryRun bool
}

// Apply schreibt Payload in den Store. Geraete-Token werden nicht uebernommen.
func Apply(st *store.Store, payload Payload, opts ApplyOptions) (*Report, error) {
	if err := MigratePayloadForward(SchemaVersion, &payload); err != nil {
		return nil, err
	}
	if err := ValidatePayload(&payload); err != nil {
		return nil, err
	}

	salt, err := hex.DecodeString(payload.KDFSalt)
	if err != nil || len(salt) != crypto.SaltLen {
		return nil, fmt.Errorf("kdf_salt ungueltig")
	}
	user, err := st.GetUser()
	if err != nil {
		return nil, err
	}
	if !hmacEqualSalt(user.KDFSalt, salt) {
		return nil, fmt.Errorf("Zielkonto hat anderes KDF-Salt; Archiv gehoert zu einem anderen Master-Passwort/Konto. Frisches Setup mit dem Salt aus dem Archiv nutzen")
	}

	mode := opts.Mode
	if mode == "" {
		mode = ModeMerge
	}
	rep := &Report{DryRun: opts.DryRun, Mode: string(mode)}
	rep.Notes = append(rep.Notes, "Geraete-Token werden nicht importiert; Geraete am Ziel neu registrieren")
	rep.DevicesNoted = len(payload.Devices)

	existingIDs, err := st.ListIdentities()
	if err != nil {
		return nil, err
	}
	existingHosts, err := st.ListHosts()
	if err != nil {
		return nil, err
	}
	idByID := map[string]store.Identity{}
	idByName := map[string]store.Identity{}
	for _, id := range existingIDs {
		idByID[id.ID] = id
		idByName[id.Name] = id
	}
	hostByID := map[string]store.Host{}
	hostByAlias := map[string]store.Host{}
	for _, h := range existingHosts {
		hostByID[h.ID] = h
		hostByAlias[h.Alias] = h
	}

	if mode == ModeReplace && !opts.DryRun {
		for _, h := range existingHosts {
			if err := st.DeleteHost(h.ID); err != nil {
				return nil, err
			}
			rep.HostsDeleted++
		}
		for _, id := range existingIDs {
			if err := st.DeleteIdentity(id.ID); err != nil {
				return nil, err
			}
			rep.IdentitiesDeleted++
		}
		idByID, idByName, hostByID, hostByAlias = map[string]store.Identity{}, map[string]store.Identity{}, map[string]store.Host{}, map[string]store.Host{}
	} else if mode == ModeReplace && opts.DryRun {
		rep.HostsDeleted = len(existingHosts)
		rep.IdentitiesDeleted = len(existingIDs)
	}

	now := time.Now().UTC()
	for _, id := range payload.Identities {
		if ex, ok := idByName[id.Name]; ok && ex.ID != id.ID {
			rep.Conflicts = append(rep.Conflicts, fmt.Sprintf("Identity-Name %q existiert mit anderer ID", id.Name))
			if mode == ModeMerge {
				rep.IdentitiesSkipped++
				continue
			}
		}
		if _, ok := idByID[id.ID]; ok && mode == ModeMerge {
			rep.IdentitiesSkipped++
			continue
		}
		if opts.DryRun {
			rep.IdentitiesUpserted++
			continue
		}
		if err := st.UpsertIdentity(store.Identity{
			ID:                  id.ID,
			Name:                id.Name,
			PublicKey:           id.PublicKey,
			EncryptedPrivateKey: id.EncryptedPrivateKey,
			Comment:             id.Comment,
			CreatedAt:           now,
			UpdatedAt:           now,
		}); err != nil {
			return nil, err
		}
		rep.IdentitiesUpserted++
		idByID[id.ID] = store.Identity{ID: id.ID, Name: id.Name}
		idByName[id.Name] = idByID[id.ID]
	}

	for _, h := range payload.Hosts {
		if ex, ok := hostByAlias[h.Alias]; ok && ex.ID != h.ID {
			rep.Conflicts = append(rep.Conflicts, fmt.Sprintf("Host-Alias %q existiert mit anderer ID", h.Alias))
			if mode == ModeMerge {
				rep.HostsSkipped++
				continue
			}
		}
		if _, ok := hostByID[h.ID]; ok && mode == ModeMerge {
			rep.HostsSkipped++
			continue
		}
		if opts.DryRun {
			rep.HostsUpserted++
			continue
		}
		port := h.Port
		if port == 0 {
			port = 22
		}
		if err := st.UpsertHost(store.Host{
			ID:             h.ID,
			Alias:          h.Alias,
			HostName:       h.HostName,
			User:           h.User,
			Port:           port,
			IdentityID:     h.IdentityID,
			ProxyJump:      h.ProxyJump,
			IdentitiesOnly: h.IdentitiesOnly,
			Extra:          h.Extra,
			SortOrder:      h.SortOrder,
			CreatedAt:      now,
			UpdatedAt:      now,
		}); err != nil {
			return nil, err
		}
		rep.HostsUpserted++
		hostByID[h.ID] = store.Host{ID: h.ID, Alias: h.Alias}
		hostByAlias[h.Alias] = hostByID[h.ID]
	}

	for k, v := range payload.Settings {
		if k == "" {
			continue
		}
		if opts.DryRun {
			rep.SettingsWritten++
			continue
		}
		if err := st.SetSetting(k, v); err != nil {
			return nil, err
		}
		rep.SettingsWritten++
	}
	return rep, nil
}

func hmacEqualSalt(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
