package client

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/accountexport"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

type API struct {
	BaseURL            string
	Token              string
	AccessClientID     string
	AccessClientSecret string
	SetupToken         string
	HTTP               *http.Client
}

func New(baseURL, token string) *API {
	return &API{
		BaseURL: trimSlash(baseURL),
		Token:   token,
		HTTP: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (a *API) KDFSalt() ([]byte, error) {
	path := "/api/auth/kdf-salt"
	if a.Token != "" {
		path = "/api/agent/kdf-salt"
	}
	var resp struct {
		KDFSalt string `json:"kdf_salt"`
	}
	if err := a.get(path, &resp); err != nil {
		return nil, err
	}
	return hex.DecodeString(resp.KDFSalt)
}

type DeviceCommand struct {
	ID      string          `json:"id"`
	Command string          `json:"command"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

func (a *API) PollCommand() (*DeviceCommand, error) {
	req, err := http.NewRequest(http.MethodGet, a.BaseURL+"/api/agent/commands", nil)
	if err != nil {
		return nil, err
	}
	a.setHeaders(req)
	res, err := a.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if res.StatusCode >= 300 {
		return nil, readAPIError(res)
	}
	var cmd DeviceCommand
	if err := json.NewDecoder(res.Body).Decode(&cmd); err != nil {
		return nil, err
	}
	if cmd.ID == "" {
		return nil, nil
	}
	return &cmd, nil
}

func (a *API) CompleteCommand(id, status, message string) error {
	body, _ := json.Marshal(map[string]string{"status": status, "message": message})
	req, err := http.NewRequest(http.MethodPost, a.BaseURL+"/api/agent/commands/"+id+"/complete", bytes.NewReader(body))
	if err != nil {
		return err
	}
	a.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	res, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return readAPIError(res)
	}
	return nil
}

func (a *API) DaemonPing() error {
	return a.get("/api/agent/ping", &map[string]string{})
}

func (a *API) Sync() (*store.SyncBundle, error) {
	var bundle store.SyncBundle
	if err := a.get("/api/sync", &bundle); err != nil {
		return nil, err
	}
	return &bundle, nil
}

type RegisterDeviceResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DeviceToken string `json:"device_token"`
	JWT         string `json:"jwt"`
}

type LoginResult struct {
	Token      string
	AuthScheme string
}

func (a *API) Login(password string) (string, error) {
	res, err := a.LoginLegacyPassword(password)
	if err != nil {
		return "", err
	}
	return res.Token, nil
}

func (a *API) LoginWithAuthKey(authKeyHex string) (*LoginResult, error) {
	return a.login(map[string]string{"auth_key": authKeyHex})
}

func (a *API) LoginLegacyPassword(password string) (*LoginResult, error) {
	return a.login(map[string]string{"password": password})
}

func (a *API) login(payload map[string]string) (*LoginResult, error) {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, a.BaseURL+"/api/auth/login", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	a.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	res, err := a.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return nil, readAPIError(res)
	}
	var out struct {
		Token      string `json:"token"`
		AuthScheme string `json:"auth_scheme"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &LoginResult{Token: out.Token, AuthScheme: out.AuthScheme}, nil
}

type AuthUpgradeIdentity struct {
	ID                  string `json:"id"`
	EncryptedPrivateKey string `json:"encrypted_private_key"`
}

func (a *API) UpgradeAuth(authKeyHex string, password string, identities []AuthUpgradeIdentity) error {
	payload := struct {
		AuthKey    string                `json:"auth_key"`
		Password   string                `json:"password,omitempty"`
		Identities []AuthUpgradeIdentity `json:"identities"`
	}{AuthKey: authKeyHex, Password: password, Identities: identities}
	return a.sendJSON(http.MethodPost, "/api/auth/upgrade", payload, nil)
}

type IdentityPayload struct {
	Name                string `json:"name"`
	PublicKey           string `json:"public_key"`
	EncryptedPrivateKey string `json:"encrypted_private_key"`
	Comment             string `json:"comment"`
}

type HostPayload struct {
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

func (a *API) ListIdentities() ([]store.Identity, error) {
	var list []store.Identity
	if err := a.get("/api/identities", &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (a *API) ListHosts() ([]store.Host, error) {
	var list []store.Host
	if err := a.get("/api/hosts", &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (a *API) PutIdentity(id string, payload IdentityPayload) error {
	return a.putJSON("/api/identities/"+id, payload)
}

func (a *API) PutHost(id string, payload HostPayload) error {
	return a.putJSON("/api/hosts/"+id, payload)
}

type DeviceView struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (a *API) ListDevices() ([]DeviceView, error) {
	var list []DeviceView
	if err := a.get("/api/devices", &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (a *API) RegisterDevice(name string) (*RegisterDeviceResponse, error) {
	body, _ := json.Marshal(map[string]string{"name": name})
	req, err := http.NewRequest(http.MethodPost, a.BaseURL+"/api/devices", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	a.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	res, err := a.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return nil, readAPIError(res)
	}
	var out RegisterDeviceResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *API) putJSON(path string, payload any) error {
	return a.sendJSON(http.MethodPut, path, payload, nil)
}

func (a *API) Setup(authKeyHex, kdfSaltHex string) error {
	var out struct {
		Token string `json:"token"`
	}
	if err := a.sendJSON(http.MethodPost, "/api/setup", map[string]string{
		"auth_key": authKeyHex,
		"kdf_salt": kdfSaltHex,
	}, &out); err != nil {
		return err
	}
	a.Token = out.Token
	return nil
}

func (a *API) AccountExport() (*accountexport.Payload, error) {
	var out accountexport.Payload
	if err := a.get("/api/account/export", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *API) AccountImport(payload accountexport.Payload, mode accountexport.ConflictMode, dryRun bool) (*accountexport.Report, error) {
	var out accountexport.Report
	body := map[string]any{
		"payload": payload,
		"mode":    mode,
		"dry_run": dryRun,
	}
	if err := a.sendJSON(http.MethodPost, "/api/account/import", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type AgentImportPayload struct {
	// Password ist veraltet; Geraete-JWT reicht. Feld bleibt fuer Altagenten optional.
	Password     string                `json:"password,omitempty"`
	SkipExisting bool                  `json:"skip_existing"`
	Identities   []AgentImportIdentity `json:"identities"`
	Hosts        []AgentImportHost     `json:"hosts"`
}

type AgentImportIdentity struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	PublicKey           string `json:"public_key"`
	EncryptedPrivateKey string `json:"encrypted_private_key"`
	Comment             string `json:"comment"`
}

type AgentImportHost struct {
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

type AgentImportResult struct {
	Identities        int      `json:"identities"`
	Hosts             int      `json:"hosts"`
	SkippedIdentities int      `json:"skipped_identities"`
	SkippedHosts      int      `json:"skipped_hosts"`
	Conflicts         []string `json:"conflicts"`
}

func (a *API) AgentImport(payload AgentImportPayload) (*AgentImportResult, error) {
	var out AgentImportResult
	if err := a.sendJSON(http.MethodPost, "/api/agent/import", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *API) sendJSON(method, path string, payload any, out any) error {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(method, a.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	a.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	res, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return readAPIError(res)
	}
	if out == nil {
		return nil
	}
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return wrapJSONError(data, err)
	}
	return nil
}

func (a *API) setHeaders(req *http.Request) {
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	if a.SetupToken != "" {
		req.Header.Set("X-Setup-Token", a.SetupToken)
	}
	if a.AccessClientID != "" && a.AccessClientSecret != "" {
		req.Header.Set("CF-Access-Client-Id", a.AccessClientID)
		req.Header.Set("CF-Access-Client-Secret", a.AccessClientSecret)
	}
}

func (a *API) get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, a.BaseURL+path, nil)
	if err != nil {
		return err
	}
	a.setHeaders(req)
	res, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return readAPIError(res)
	}
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return wrapJSONError(data, err)
	}
	return nil
}

func wrapJSONError(body []byte, err error) error {
	trim := bytes.TrimSpace(body)
	if len(trim) > 0 && trim[0] == '<' {
		return fmt.Errorf("Antwort ist HTML statt JSON (Cloudflare Access?) — access_client_id und access_client_secret in ~/.config/ssh-sync/config.json setzen")
	}
	return err
}

func readAPIError(res *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	trim := bytes.TrimSpace(body)
	if len(trim) > 0 && trim[0] == '<' {
		return fmt.Errorf("%s: Cloudflare Access blockiert (access_client_id/secret in config.json prüfen)", res.Status)
	}
	if res.StatusCode == http.StatusFound || res.StatusCode == http.StatusMovedPermanently {
		return fmt.Errorf("%s: Cloudflare Access Redirect — access_client_id/secret in config.json setzen", res.Status)
	}
	var parsed struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &parsed) == nil && parsed.Error != "" {
		return fmt.Errorf("%s: %s", res.Status, parsed.Error)
	}
	return fmt.Errorf("%s: %s", res.Status, string(body))
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
