package api

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/store"
)

func (s *Server) registerAgentRoutes() {
	s.mux.Handle("POST /api/devices/{id}/trigger-sync", s.requireUser(http.HandlerFunc(s.handleTriggerSync)))
	s.mux.Handle("POST /api/devices/{id}/trigger-import", s.requireUser(http.HandlerFunc(s.handleTriggerImport)))
	s.mux.Handle("POST /api/devices/{id}/trigger-purge", s.requireUser(http.HandlerFunc(s.handleTriggerPurge)))
	s.mux.Handle("GET /api/agent/commands", s.requireDevice(http.HandlerFunc(s.handleAgentPollCommand)))
	s.mux.Handle("POST /api/agent/commands/{id}/complete", s.requireDevice(http.HandlerFunc(s.handleAgentCompleteCommand)))
	s.mux.Handle("GET /api/agent/ping", s.requireDevice(http.HandlerFunc(s.handleAgentPing)))
	s.mux.Handle("POST /api/agent/import", s.requireDevice(http.HandlerFunc(s.handleAgentImport)))
	s.mux.Handle("GET /api/agent/kdf-salt", s.requireDevice(http.HandlerFunc(s.handleAgentKDFSalt)))
}

func (s *Server) handleTriggerSync(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("id")
	if deviceID == "" {
		writeError(w, http.StatusBadRequest, "geräte-id fehlt")
		return
	}
	devices, err := s.store.ListDevices()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	found := false
	for _, d := range devices {
		if d.ID == deviceID {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "gerät nicht gefunden")
		return
	}
	active, err := s.store.HasActiveCommand(deviceID, store.CommandSync)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if active {
		writeJSON(w, http.StatusOK, map[string]string{"status": "already_queued"})
		return
	}
	cmd, err := s.store.EnqueueCommand(deviceID, store.CommandSync)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": cmd.ID, "status": "queued"})
}

func (s *Server) handleTriggerImport(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("id")
	if deviceID == "" {
		writeError(w, http.StatusBadRequest, "geräte-id fehlt")
		return
	}
	if !s.deviceExists(deviceID) {
		writeError(w, http.StatusNotFound, "gerät nicht gefunden")
		return
	}
	active, err := s.store.HasActiveCommand(deviceID, store.CommandImport)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if active {
		writeJSON(w, http.StatusOK, map[string]string{"status": "already_queued"})
		return
	}
	cmd, err := s.store.EnqueueCommand(deviceID, store.CommandImport)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": cmd.ID, "status": "queued"})
}

func (s *Server) handleTriggerPurge(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("id")
	if deviceID == "" {
		writeError(w, http.StatusBadRequest, "geräte-id fehlt")
		return
	}
	dev := s.deviceByID(deviceID)
	if dev.ID == "" {
		writeError(w, http.StatusNotFound, "gerät nicht gefunden")
		return
	}
	if !deviceOnline(dev.LastSeen) {
		writeError(w, http.StatusConflict, "Gerät offline — Gerät abgeben nur wenn der Agent erreichbar ist. Lokal: ssh-sync purge")
		return
	}
	active, err := s.store.HasActiveCommand(deviceID, store.CommandPurge)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if active {
		writeJSON(w, http.StatusOK, map[string]string{"status": "already_queued"})
		return
	}
	cmd, err := s.store.EnqueueCommand(deviceID, store.CommandPurge)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": cmd.ID, "status": "queued"})
}

func (s *Server) handleAgentPollCommand(w http.ResponseWriter, r *http.Request) {
	deviceID := deviceIDFromContext(r.Context())
	if err := s.store.TouchDevice(deviceID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cmd, err := s.store.ClaimNextCommand(deviceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cmd == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	out := map[string]any{"id": cmd.ID, "command": cmd.Command}
	if cmd.Payload != "" {
		out["payload"] = json.RawMessage(cmd.Payload)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAgentCompleteCommand(w http.ResponseWriter, r *http.Request) {
	deviceID := deviceIDFromContext(r.Context())
	cmdID := r.PathValue("id")
	var req struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := readJSON(r, &req); err != nil || req.Status == "" {
		writeError(w, http.StatusBadRequest, "status erforderlich")
		return
	}
	if req.Status != store.StatusComplete && req.Status != store.StatusFailed {
		writeError(w, http.StatusBadRequest, "ungültiger status")
		return
	}
	cmd, err := s.store.GetCommand(cmdID)
	if err != nil || cmd == nil || cmd.DeviceID != deviceID {
		writeError(w, http.StatusNotFound, "befehl nicht gefunden")
		return
	}
	if err := s.store.CompleteCommand(cmdID, req.Status, req.Message); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cmd.Command == store.CommandPurge && req.Status == store.StatusComplete {
		if err := s.store.DeleteDevice(deviceID); err != nil {
			log.Printf("purge: gerät %s aus Portal entfernen: %v", deviceID, err)
			writeError(w, http.StatusInternalServerError, "purge abgeschlossen, Gerät konnte im Portal nicht entfernt werden")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAgentPing(w http.ResponseWriter, r *http.Request) {
	deviceID := deviceIDFromContext(r.Context())
	if err := s.store.TouchDevice(deviceID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "device_id": deviceID})
}

func (s *Server) deviceExists(deviceID string) bool {
	return s.deviceByID(deviceID).ID != ""
}

func (s *Server) deviceByID(deviceID string) store.Device {
	devices, err := s.store.ListDevices()
	if err != nil {
		return store.Device{}
	}
	for _, d := range devices {
		if d.ID == deviceID {
			return d
		}
	}
	return store.Device{}
}

func deviceOnline(lastSeen *time.Time) bool {
	if lastSeen == nil {
		return false
	}
	// 2× typisches Poll-Intervall (30s) + Puffer
	return time.Since(*lastSeen) < 2*time.Minute
}
