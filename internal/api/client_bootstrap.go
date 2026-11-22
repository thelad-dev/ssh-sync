package api

import (
	"net/http"
	"os"
)

type clientBootstrapResponse struct {
	AccessClientID     string `json:"access_client_id,omitempty"`
	AccessClientSecret string `json:"access_client_secret,omitempty"`
	Source             string `json:"source,omitempty"` // "env", "portal", ""
}

func (s *Server) cfBootstrapCredentials() (id, secret, source string) {
	id = os.Getenv("SSH_SYNC_CF_ACCESS_CLIENT_ID")
	secret = os.Getenv("SSH_SYNC_CF_ACCESS_CLIENT_SECRET")
	if id != "" && secret != "" {
		return id, secret, "env"
	}
	if id == "" {
		id, _ = s.store.GetSetting("cf_access_client_id")
	}
	if secret == "" {
		secret, _ = s.store.GetSetting("cf_access_client_secret")
	}
	if id != "" && secret != "" {
		return id, secret, "portal"
	}
	return id, secret, ""
}

// GET /api/client-bootstrap  -  CF Service Token für Geräte-Setup (env oder Portal-Einstellung).
// Hinweis (N14): Ein gemeinsamer Token für alle Geräte; Widerruf wirkt global. Siehe docs/cloudflare-access.md.
func (s *Server) handleClientBootstrapGet(w http.ResponseWriter, r *http.Request) {
	id, secret, source := s.cfBootstrapCredentials()
	writeJSON(w, http.StatusOK, clientBootstrapResponse{
		AccessClientID:     id,
		AccessClientSecret: secret,
		Source:             source,
	})
}

// PUT /api/client-bootstrap  -  CF Token im Portal speichern (nur eingeloggt).
func (s *Server) handleClientBootstrapPut(w http.ResponseWriter, r *http.Request) {
	var req clientBootstrapResponse
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "ungültige Anfrage")
		return
	}
	if req.AccessClientID == "" || req.AccessClientSecret == "" {
		writeError(w, http.StatusBadRequest, "access_client_id und access_client_secret erforderlich")
		return
	}
	if err := s.store.SetSetting("cf_access_client_id", req.AccessClientID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.SetSetting("cf_access_client_secret", req.AccessClientSecret); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, clientBootstrapResponse{
		AccessClientID:     req.AccessClientID,
		AccessClientSecret: req.AccessClientSecret,
		Source:             "portal",
	})
}
