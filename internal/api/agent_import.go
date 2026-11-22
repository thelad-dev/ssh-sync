package api

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/auth"
	"github.com/thelad-dev/ssh-sync/internal/sshconfig"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

func (s *Server) handleAgentKDFSalt(w http.ResponseWriter, r *http.Request) {
	salt, err := s.store.GetKDFSalt()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"kdf_salt": hex.EncodeToString(salt)})
}

type agentImportRequest struct {
	Password     string                `json:"password"`
	SkipExisting bool                  `json:"skip_existing"`
	Identities   []agentImportIdentity `json:"identities"`
	Hosts        []agentImportHost     `json:"hosts"`
}

type agentImportIdentity struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	PublicKey           string `json:"public_key"`
	EncryptedPrivateKey string `json:"encrypted_private_key"`
	Comment             string `json:"comment"`
}

type agentImportHost struct {
	ID             string  `json:"id"`
	Alias          string  `json:"alias"`
	HostName       string  `json:"host_name"`
	User           string  `json:"user"`
	Port           int     `json:"port"`
	IdentityID     *string `json:"identity_id"`
	ProxyJump      string  `json:"proxy_jump"`
	IdentitiesOnly bool    `json:"identities_only"`
	Extra          string  `json:"extra"`
}

type agentImportResponse struct {
	Identities        int      `json:"identities"`
	Hosts             int      `json:"hosts"`
	SkippedIdentities int      `json:"skipped_identities"`
	SkippedHosts      int      `json:"skipped_hosts"`
	Conflicts         []string `json:"conflicts"`
}

func (s *Server) handleAgentImport(w http.ResponseWriter, r *http.Request) {
	var req agentImportRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "ungültige Anfrage")
		return
	}
	// Geraete-JWT reicht; optionales password nur fuer Altagenten (wird gegen Hash geprueft).
	if req.Password != "" {
		user, err := s.store.GetUser()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		ok := false
		switch user.AuthScheme {
		case store.AuthSchemeV1:
			ok = auth.CheckPassword(user.PasswordHash, req.Password)
		default:
			ok = auth.CheckPassword(user.PasswordHash, req.Password)
		}
		if !ok {
			writeError(w, http.StatusUnauthorized, "falsches Passwort")
			return
		}
	}

	existingByName := map[string]store.Identity{}
	existingHostsByAlias := map[string]store.Host{}
	if list, err := s.store.ListIdentities(); err == nil {
		for _, i := range list {
			existingByName[i.Name] = i
		}
	}
	if req.SkipExisting {
		if list, err := s.store.ListHosts(); err == nil {
			for _, h := range list {
				existingHostsByAlias[h.Alias] = h
			}
		}
	}

	now := time.Now()
	var importedIDs, importedHosts, skippedIDs, skippedHosts int
	var conflicts []string
	identityIDMap := map[string]string{}

	for _, id := range req.Identities {
		if id.Name == "" || id.EncryptedPrivateKey == "" || id.ID == "" {
			writeError(w, http.StatusBadRequest, "identity: id, name und encrypted_private_key erforderlich")
			return
		}
		if !validResourceID(id.ID) {
			writeError(w, http.StatusBadRequest, "identity: ungültige id")
			return
		}
		if existing, ok := existingByName[id.Name]; ok && req.SkipExisting {
			if id.PublicKey != "" && existing.PublicKey != "" &&
				!sshconfig.PublicKeysEqual(id.PublicKey, existing.PublicKey) {
				conflicts = append(conflicts, fmt.Sprintf("Key %s: anderer Public Key auf dem Server", id.Name))
				skippedIDs++
				continue
			}
			identityIDMap[id.ID] = existing.ID
			if existing.PublicKey == "" && id.PublicKey != "" {
				existing.PublicKey = id.PublicKey
				existing.UpdatedAt = now
				if err := s.store.UpsertIdentity(existing); err != nil {
					writeError(w, http.StatusInternalServerError, err.Error())
					return
				}
				importedIDs++
			} else {
				skippedIDs++
			}
			continue
		}
		if err := s.store.UpsertIdentity(store.Identity{
			ID:                  id.ID,
			Name:                id.Name,
			PublicKey:           id.PublicKey,
			EncryptedPrivateKey: id.EncryptedPrivateKey,
			Comment:             id.Comment,
			CreatedAt:           now,
			UpdatedAt:           now,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		identityIDMap[id.ID] = id.ID
		importedIDs++
	}

	for _, h := range req.Hosts {
		if h.Alias == "" || h.HostName == "" || h.ID == "" {
			writeError(w, http.StatusBadRequest, "host: id, alias und host_name erforderlich")
			return
		}
		if !validResourceID(h.ID) {
			writeError(w, http.StatusBadRequest, "host: ungültige id")
			return
		}
		if h.IdentityID != nil && *h.IdentityID != "" && !validResourceID(*h.IdentityID) {
			writeError(w, http.StatusBadRequest, "host: ungültige identity_id")
			return
		}
		extra, err := sshconfig.NormalizeExtra(h.Extra)
		if err != nil {
			writeError(w, http.StatusBadRequest, "host "+h.Alias+": "+err.Error())
			return
		}
		if err := sshconfig.ValidateHostFields(h.Alias, h.HostName, h.User, h.ProxyJump, extra); err != nil {
			writeError(w, http.StatusBadRequest, "host "+h.Alias+": "+err.Error())
			return
		}
		h.Extra = extra
		resolvedIdentityID := remapImportIdentityID(h.IdentityID, identityIDMap)
		if existing, ok := existingHostsByAlias[h.Alias]; ok && req.SkipExisting {
			port := h.Port
			if port == 0 {
				port = 22
			}
			exPort := existing.Port
			if exPort == 0 {
				exPort = 22
			}
			if existing.HostName != h.HostName || existing.User != h.User || exPort != port {
				conflicts = append(conflicts, fmt.Sprintf(
					"Host %s: Server %s ≠ import %s@%s:%d",
					h.Alias, formatHostTarget(existing.User, existing.HostName, exPort),
					h.User, h.HostName, port,
				))
				skippedHosts++
				continue
			}
			if resolvedIdentityID != nil && existing.IdentityID == nil {
				existing.IdentityID = resolvedIdentityID
				existing.UpdatedAt = now
				if err := s.store.UpsertHost(existing); err != nil {
					writeError(w, http.StatusInternalServerError, err.Error())
					return
				}
				importedHosts++
			} else {
				skippedHosts++
			}
			continue
		}
		port := h.Port
		if port == 0 {
			port = 22
		}
		if err := s.store.UpsertHost(store.Host{
			ID:             h.ID,
			Alias:          h.Alias,
			HostName:       h.HostName,
			User:           h.User,
			Port:           port,
			IdentityID:     resolvedIdentityID,
			ProxyJump:      h.ProxyJump,
			IdentitiesOnly: h.IdentitiesOnly,
			Extra:          h.Extra,
			CreatedAt:      now,
			UpdatedAt:      now,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		importedHosts++
	}

	writeJSON(w, http.StatusOK, agentImportResponse{
		Identities:        importedIDs,
		Hosts:             importedHosts,
		SkippedIdentities: skippedIDs,
		SkippedHosts:      skippedHosts,
		Conflicts:         conflicts,
	})
}

func formatHostTarget(user, hostName string, port int) string {
	if user != "" {
		return fmt.Sprintf("%s@%s:%d", user, hostName, port)
	}
	return fmt.Sprintf("%s:%d", hostName, port)
}

// remapImportIdentityID mappt vom Client erzeugte Import-IDs auf bestehende Server-IDs
// (bei skip_existing), damit hosts.identity_id die FK-Constraint erfüllt.
func remapImportIdentityID(importID *string, idMap map[string]string) *string {
	if importID == nil {
		return nil
	}
	serverID, ok := idMap[*importID]
	if !ok || serverID == "" {
		return nil
	}
	v := serverID
	return &v
}
