package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/thelad-dev/ssh-sync/internal/accountexport"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

func (s *Server) registerAccountExportRoutes() {
	s.mux.Handle("GET /api/account/export", s.requireUser(http.HandlerFunc(s.handleAccountExport)))
	s.mux.Handle("POST /api/account/import", s.requireUser(http.HandlerFunc(s.handleAccountImport)))
}

func (s *Server) handleAccountExport(w http.ResponseWriter, r *http.Request) {
	user, err := s.store.GetUser()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	identities, err := s.store.ListIdentities()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	hosts, err := s.store.ListHosts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	devices, err := s.store.ListDevices()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	settings, err := s.store.ListSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	scheme := user.AuthScheme
	if scheme == "" {
		scheme = store.AuthSchemeLegacy
	}
	payload := accountexport.FromStore(identities, hosts, devices, user.KDFSalt, scheme, settings)
	writeJSON(w, http.StatusOK, payload)
}

type accountImportRequest struct {
	Payload accountexport.Payload      `json:"payload"`
	Mode    accountexport.ConflictMode `json:"mode"`
	DryRun  bool                       `json:"dry_run"`
}

func (s *Server) handleAccountImport(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, accountexport.MaxArchiveBytes+1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Anfrage nicht lesbar")
		return
	}
	var req accountImportRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "ungueltige Anfrage")
		return
	}
	mode := req.Mode
	if mode == "" {
		mode = accountexport.ModeMerge
	}
	if mode != accountexport.ModeMerge && mode != accountexport.ModeReplace {
		writeError(w, http.StatusBadRequest, "mode muss merge oder replace sein")
		return
	}
	if err := accountexport.ValidatePayload(&req.Payload); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rep, err := accountexport.Apply(s.store, req.Payload, accountexport.ApplyOptions{
		Mode:   mode,
		DryRun: req.DryRun,
	})
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "Salt") || strings.Contains(msg, "ungueltig") || strings.Contains(msg, "Allowlist") || strings.Contains(msg, "nicht erlaubt") {
			writeError(w, http.StatusBadRequest, msg)
			return
		}
		writeError(w, http.StatusInternalServerError, msg)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}
