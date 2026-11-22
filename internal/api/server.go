package api

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/auth"
	"github.com/thelad-dev/ssh-sync/internal/crypto"
	"github.com/thelad-dev/ssh-sync/internal/sshconfig"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

var resourceIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func subtleConstantTimeEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

const (
	upgradeFailWindow = 5 * time.Minute
	upgradeFailMax    = 5
)

type Server struct {
	store         *store.Store
	secret        []byte
	mux           *http.ServeMux
	upgradeFailMu sync.Mutex
	upgradeFails  []time.Time
}

func NewServer(st *store.Store, secret []byte) *Server {
	s := &Server{store: st, secret: secret, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.cors(s.mux)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/setup/status", s.handleSetupStatus)
	s.mux.HandleFunc("POST /api/setup", s.handleSetup)
	s.mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	s.mux.HandleFunc("GET /api/auth/kdf-salt", s.handleKDFSalt)
	s.mux.Handle("POST /api/auth/upgrade", s.requireUser(http.HandlerFunc(s.handleAuthUpgrade)))

	s.mux.Handle("GET /api/identities", s.requireUser(http.HandlerFunc(s.handleListIdentities)))
	s.mux.Handle("PUT /api/identities/{id}", s.requireUser(http.HandlerFunc(s.handlePutIdentity)))
	s.mux.Handle("DELETE /api/identities/{id}", s.requireUser(http.HandlerFunc(s.handleDeleteIdentity)))

	s.mux.Handle("GET /api/hosts", s.requireUser(http.HandlerFunc(s.handleListHosts)))
	s.mux.Handle("PUT /api/hosts/{id}", s.requireUser(http.HandlerFunc(s.handlePutHost)))
	s.mux.Handle("DELETE /api/hosts/{id}", s.requireUser(http.HandlerFunc(s.handleDeleteHost)))

	s.mux.Handle("GET /api/client-bootstrap", s.requireUser(http.HandlerFunc(s.handleClientBootstrapGet)))
	s.mux.Handle("PUT /api/client-bootstrap", s.requireUser(http.HandlerFunc(s.handleClientBootstrapPut)))

	s.mux.Handle("GET /api/devices", s.requireUser(http.HandlerFunc(s.handleListDevices)))
	s.mux.Handle("POST /api/devices", s.requireUser(http.HandlerFunc(s.handleCreateDevice)))
	s.mux.Handle("DELETE /api/devices/{id}", s.requireUser(http.HandlerFunc(s.handleDeleteDevice)))

	s.mux.Handle("GET /api/sync", s.requireDevice(http.HandlerFunc(s.handleSync)))
	s.registerAgentRoutes()
	s.registerAccountExportRoutes()
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Kein Access-Control-Allow-Origin: * (N15): Portal wird same-origin ausgeliefert.
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Setup-Token")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := s.authenticate(r)
		if err != nil || claims.Scope != auth.ScopeUser {
			writeError(w, http.StatusUnauthorized, "nicht autorisiert")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireDevice(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := bearerToken(r)
		claims, err := s.authenticateToken(raw)
		if err != nil || claims.Scope != auth.ScopeDevice || claims.DeviceID == "" {
			writeError(w, http.StatusUnauthorized, "nicht autorisiert")
			return
		}
		dev, err := s.store.GetDevice(claims.DeviceID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeError(w, http.StatusUnauthorized, "nicht autorisiert")
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		want := []byte(dev.TokenHash)
		got := []byte(auth.HashToken(raw))
		if subtle.ConstantTimeCompare(want, got) != 1 {
			writeError(w, http.StatusUnauthorized, "nicht autorisiert")
			return
		}
		r = r.WithContext(withDeviceID(r.Context(), claims.DeviceID))
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authenticate(r *http.Request) (*auth.Claims, error) {
	return s.authenticateToken(bearerToken(r))
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}

func (s *Server) authenticateToken(token string) (*auth.Claims, error) {
	if token == "" {
		return nil, errors.New("kein Token")
	}
	return auth.ParseToken(s.secret, token)
}

func validResourceID(id string) bool {
	return resourceIDPattern.MatchString(id)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	ok, err := s.store.IsInitialized()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"initialized": ok})
}

type setupRequest struct {
	AuthKey string `json:"auth_key"`
	KDFSalt string `json:"kdf_salt"`
	// Password bleibt nur fuer Fehlermeldungen an veraltete Clients erkennbar.
	Password string `json:"password,omitempty"`
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	ok, err := s.store.IsInitialized()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ok {
		writeError(w, http.StatusConflict, "Setup bereits abgeschlossen")
		return
	}
	if expected := strings.TrimSpace(os.Getenv("SSH_SYNC_SETUP_TOKEN")); expected != "" {
		if subtleConstantTimeEq(r.Header.Get("X-Setup-Token"), expected) == false {
			writeError(w, http.StatusForbidden, "Setup-Token erforderlich (Header X-Setup-Token)")
			return
		}
	}
	var req setupRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "ungueltige Anfrage")
		return
	}
	if req.Password != "" && req.AuthKey == "" {
		writeError(w, http.StatusBadRequest, "Setup erwartet auth_key und kdf_salt (kein Klartext-Passwort)")
		return
	}
	authKey, err := decodeAuthKey(req.AuthKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "auth_key ungueltig")
		return
	}
	salt, err := hex.DecodeString(req.KDFSalt)
	if err != nil || len(salt) != crypto.SaltLen {
		writeError(w, http.StatusBadRequest, "kdf_salt ungueltig")
		return
	}
	hash, err := auth.HashPassword(hex.EncodeToString(authKey))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.CreateUserWithScheme(hash, salt, store.AuthSchemeV1); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	token, err := auth.IssueUserToken(s.secret, 24*time.Hour)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":       token,
		"kdf_salt":    hex.EncodeToString(salt),
		"auth_scheme": store.AuthSchemeV1,
	})
}

type loginRequest struct {
	AuthKey  string `json:"auth_key,omitempty"`
	Password string `json:"password,omitempty"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ok, err := s.store.IsInitialized()
	if err != nil || !ok {
		writeError(w, http.StatusBadRequest, "Setup noch nicht abgeschlossen")
		return
	}
	var req loginRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "ungueltige Anfrage")
		return
	}
	user, err := s.store.GetUser()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	scheme := user.AuthScheme
	if scheme == "" {
		scheme = store.AuthSchemeLegacy
	}
	switch {
	case req.AuthKey != "":
		authKey, err := decodeAuthKey(req.AuthKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "auth_key ungueltig")
			return
		}
		if scheme != store.AuthSchemeV1 || !auth.CheckPassword(user.PasswordHash, hex.EncodeToString(authKey)) {
			writeError(w, http.StatusUnauthorized, "falscher auth_key")
			return
		}
	case req.Password != "":
		if scheme != store.AuthSchemeLegacy || !auth.CheckPassword(user.PasswordHash, req.Password) {
			writeError(w, http.StatusUnauthorized, "falsches Passwort")
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "auth_key oder password erforderlich")
		return
	}
	token, err := auth.IssueUserToken(s.secret, 24*time.Hour)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"token":       token,
		"auth_scheme": scheme,
	})
}

type authUpgradeRequest struct {
	AuthKey    string                `json:"auth_key"`
	Password   string                `json:"password,omitempty"`
	Identities []authUpgradeIdentity `json:"identities"`
}

type authUpgradeIdentity struct {
	ID                  string `json:"id"`
	EncryptedPrivateKey string `json:"encrypted_private_key"`
}

func (s *Server) handleAuthUpgrade(w http.ResponseWriter, r *http.Request) {
	user, err := s.store.GetUser()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if user.AuthScheme == store.AuthSchemeV1 {
		writeJSON(w, http.StatusOK, map[string]string{"auth_scheme": store.AuthSchemeV1})
		return
	}
	if !s.allowUpgradeAttempt() {
		writeError(w, http.StatusTooManyRequests, "zu viele Fehlversuche, spaeter erneut")
		return
	}
	var req authUpgradeRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "ungueltige Anfrage")
		return
	}
	if !s.verifyUpgradeSecret(user.PasswordHash, req.Password, r.Header.Get("X-Setup-Token")) {
		s.recordUpgradeFail()
		writeError(w, http.StatusUnauthorized, "aktuelles Passwort oder Setup-Token erforderlich")
		return
	}
	authKey, err := decodeAuthKey(req.AuthKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "auth_key ungueltig")
		return
	}
	existing, err := s.store.ListIdentities()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	byID := map[string]store.Identity{}
	for _, id := range existing {
		byID[id.ID] = id
	}
	now := time.Now()
	for _, up := range req.Identities {
		cur, ok := byID[up.ID]
		if !ok || up.EncryptedPrivateKey == "" {
			writeError(w, http.StatusBadRequest, "identity upgrade ungueltig")
			return
		}
		if !crypto.IsVersionedCipher(up.EncryptedPrivateKey) {
			writeError(w, http.StatusBadRequest, "identity cipher ohne Versionsbyte")
			return
		}
		cur.EncryptedPrivateKey = up.EncryptedPrivateKey
		cur.UpdatedAt = now
		if err := s.store.UpsertIdentity(cur); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	hash, err := auth.HashPassword(hex.EncodeToString(authKey))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.UpgradeAuthScheme(hash); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"auth_scheme": store.AuthSchemeV1})
}

// verifyUpgradeSecret verlangt das bisherige Legacy-Passwort oder ein konfiguriertes Setup-Token.
func (s *Server) verifyUpgradeSecret(passwordHash, password, setupHeader string) bool {
	if password != "" {
		return auth.CheckPassword(passwordHash, password)
	}
	expected := strings.TrimSpace(os.Getenv("SSH_SYNC_SETUP_TOKEN"))
	if expected == "" {
		return false
	}
	return subtleConstantTimeEq(setupHeader, expected)
}

func (s *Server) allowUpgradeAttempt() bool {
	s.upgradeFailMu.Lock()
	defer s.upgradeFailMu.Unlock()
	cutoff := time.Now().Add(-upgradeFailWindow)
	kept := s.upgradeFails[:0]
	for _, t := range s.upgradeFails {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	s.upgradeFails = kept
	return len(s.upgradeFails) < upgradeFailMax
}

func (s *Server) recordUpgradeFail() {
	s.upgradeFailMu.Lock()
	defer s.upgradeFailMu.Unlock()
	s.upgradeFails = append(s.upgradeFails, time.Now())
}

func decodeAuthKey(hexKey string) ([]byte, error) {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	if len(raw) != crypto.KeyLen {
		return nil, errors.New("auth_key laenge")
	}
	return raw, nil
}

func (s *Server) handleKDFSalt(w http.ResponseWriter, r *http.Request) {
	salt, err := s.store.GetKDFSalt()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"kdf_salt": hex.EncodeToString(salt)})
}

func (s *Server) handleListIdentities(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListIdentities()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if list == nil {
		list = []store.Identity{}
	}
	writeJSON(w, http.StatusOK, list)
}

type identityRequest struct {
	Name                string `json:"name"`
	PublicKey           string `json:"public_key"`
	EncryptedPrivateKey string `json:"encrypted_private_key"`
	Comment             string `json:"comment"`
}

func (s *Server) handlePutIdentity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validResourceID(id) {
		writeError(w, http.StatusBadRequest, "ungültige id")
		return
	}
	var req identityRequest
	if err := readJSON(r, &req); err != nil || req.Name == "" || req.EncryptedPrivateKey == "" {
		writeError(w, http.StatusBadRequest, "name und encrypted_private_key erforderlich")
		return
	}
	now := time.Now()
	if err := s.store.UpsertIdentity(store.Identity{
		ID:                  id,
		Name:                req.Name,
		PublicKey:           req.PublicKey,
		EncryptedPrivateKey: req.EncryptedPrivateKey,
		Comment:             req.Comment,
		CreatedAt:           now,
		UpdatedAt:           now,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

func (s *Server) handleDeleteIdentity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validResourceID(id) {
		writeError(w, http.StatusBadRequest, "ungültige id")
		return
	}
	if err := s.store.DeleteIdentity(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListHosts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if list == nil {
		list = []store.Host{}
	}
	writeJSON(w, http.StatusOK, list)
}

type hostRequest struct {
	Alias          string  `json:"alias"`
	HostName       string  `json:"host_name"`
	User           string  `json:"user"`
	Port           int     `json:"port"`
	IdentityID     *string `json:"identity_id"`
	ProxyJump      string  `json:"proxy_jump"`
	IdentitiesOnly bool    `json:"identities_only"`
	Extra          string  `json:"extra"`
	SortOrder      int     `json:"sort_order"`
}

func (s *Server) handlePutHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validResourceID(id) {
		writeError(w, http.StatusBadRequest, "ungültige id")
		return
	}
	var req hostRequest
	if err := readJSON(r, &req); err != nil || req.Alias == "" || req.HostName == "" {
		writeError(w, http.StatusBadRequest, "alias und host_name erforderlich")
		return
	}
	if req.Port == 0 {
		req.Port = 22
	}
	extra, err := sshconfig.NormalizeExtra(req.Extra)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := sshconfig.ValidateHostFields(req.Alias, req.HostName, req.User, req.ProxyJump, extra); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Extra = extra
	now := time.Now()
	if err := s.store.UpsertHost(store.Host{
		ID:             id,
		Alias:          req.Alias,
		HostName:       req.HostName,
		User:           req.User,
		Port:           req.Port,
		IdentityID:     req.IdentityID,
		ProxyJump:      req.ProxyJump,
		IdentitiesOnly: req.IdentitiesOnly,
		Extra:          req.Extra,
		SortOrder:      req.SortOrder,
		CreatedAt:      now,
		UpdatedAt:      now,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

func (s *Server) handleDeleteHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validResourceID(id) {
		writeError(w, http.StatusBadRequest, "ungültige id")
		return
	}
	if err := s.store.DeleteHost(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListDevices()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	type lastCommandView struct {
		Command   string     `json:"command"`
		Status    string     `json:"status"`
		Message   string     `json:"message,omitempty"`
		UpdatedAt *time.Time `json:"updated_at,omitempty"`
	}
	type deviceView struct {
		ID          string           `json:"id"`
		Name        string           `json:"name"`
		CreatedAt   time.Time        `json:"created_at"`
		LastSeen    *time.Time       `json:"last_seen,omitempty"`
		Online      bool             `json:"online"`
		LastCommand *lastCommandView `json:"last_command,omitempty"`
	}
	out := make([]deviceView, 0, len(list))
	for _, d := range list {
		v := deviceView{
			ID:        d.ID,
			Name:      d.Name,
			CreatedAt: d.CreatedAt,
			LastSeen:  d.LastSeen,
			Online:    deviceOnline(d.LastSeen),
		}
		if cmd, err := s.store.LastCommandForDevice(d.ID); err == nil && cmd != nil {
			lc := &lastCommandView{Command: cmd.Command, Status: cmd.Status, Message: cmd.ResultMessage}
			if cmd.CompletedAt != nil {
				lc.UpdatedAt = cmd.CompletedAt
			} else if cmd.StartedAt != nil {
				lc.UpdatedAt = cmd.StartedAt
			} else {
				t := cmd.CreatedAt
				lc.UpdatedAt = &t
			}
			v.LastCommand = lc
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

type createDeviceRequest struct {
	Name string `json:"name"`
}

func (s *Server) handleCreateDevice(w http.ResponseWriter, r *http.Request) {
	var req createDeviceRequest
	if err := readJSON(r, &req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, "name erforderlich")
		return
	}
	rawToken, err := auth.NewDeviceToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	id, err := newID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	jwtToken, err := auth.IssueDeviceToken(s.secret, id, auth.DeviceTokenTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	device := store.Device{
		ID:        id,
		Name:      req.Name,
		TokenHash: auth.HashToken(jwtToken),
		CreatedAt: time.Now(),
	}
	if err := s.store.CreateDevice(device); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"id":           id,
		"name":         req.Name,
		"device_token": rawToken,
		"jwt":          jwtToken,
	})
}

func (s *Server) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validResourceID(id) {
		writeError(w, http.StatusBadRequest, "ungültige id")
		return
	}
	if err := s.store.DeleteDevice(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	deviceID := deviceIDFromContext(r.Context())
	if err := s.store.TouchDevice(deviceID); err != nil {
		log.Printf("device touch: %v", err)
	}
	bundle, err := s.store.SyncBundleForDevice(deviceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, bundle)
}

func newID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("json encode: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
