package agentauth

import (
	"fmt"
	"strings"

	"github.com/thelad-dev/ssh-sync/internal/agentconfig"
	"github.com/thelad-dev/ssh-sync/internal/client"
	"github.com/thelad-dev/ssh-sync/internal/keyring"
)

// EnsureDeviceJWT makes sure cfg.JWT is accepted by the current server.
// On HTTP 401 it silently rebinds using the master password from the keyring
// and Legacy-password login only (does NOT trigger auth_v1 upgrade).
// Idempotent: if the current JWT already works, this is a no-op.
func EnsureDeviceJWT(cfgPath string, cfg *agentconfig.Config) error {
	api := client.New(cfg.ServerURL, cfg.JWT)
	api.AccessClientID = cfg.AccessClientID
	api.AccessClientSecret = cfg.AccessClientSecret
	if err := api.DaemonPing(); err == nil {
		return nil
	} else if !isUnauthorized(err) {
		return err
	}

	master, err := keyring.GetMasterPassword()
	if err != nil {
		return fmt.Errorf("geraet neu anbinden: master-passwort fehlt (unlock): %w", err)
	}
	userAPI := client.New(cfg.ServerURL, "")
	userAPI.AccessClientID = cfg.AccessClientID
	userAPI.AccessClientSecret = cfg.AccessClientSecret
	res, err := userAPI.LoginLegacyPassword(master)
	if err != nil {
		return fmt.Errorf("geraet neu anbinden: login: %w", err)
	}
	userAPI.Token = res.Token
	jwt, err := userAPI.RotateDevice(cfg.DeviceID)
	if err != nil {
		return fmt.Errorf("geraet neu anbinden: rotate: %w", err)
	}
	cfg.JWT = jwt
	if err := agentconfig.Save(cfgPath, cfg); err != nil {
		return fmt.Errorf("geraet neu anbinden: config speichern: %w", err)
	}
	return nil
}

func isUnauthorized(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "401") || strings.Contains(s, "nicht autorisiert") || strings.Contains(s, "unauthorized")
}
