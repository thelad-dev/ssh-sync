package main

import (
	"os"
	"strings"

	"github.com/thelad-dev/ssh-sync/internal/agentconfig"
	"github.com/thelad-dev/ssh-sync/internal/client"
)

// applyCloudflareAccess setzt CF Service-Token-Header für Portal-API-Aufrufe
// (import, backup). Reihenfolge: config.json → Umgebungsvariablen → CLI-Flags.
func applyCloudflareAccess(api *client.API, cfgPath, flagID, flagSecret string) {
	if cfg, err := agentconfig.Load(cfgPath); err == nil {
		if cfg.AccessClientID != "" {
			api.AccessClientID = cfg.AccessClientID
		}
		if cfg.AccessClientSecret != "" {
			api.AccessClientSecret = cfg.AccessClientSecret
		}
	}
	if api.AccessClientID == "" {
		api.AccessClientID = strings.TrimSpace(os.Getenv("CF_ACCESS_CLIENT_ID"))
	}
	if api.AccessClientSecret == "" {
		api.AccessClientSecret = strings.TrimSpace(os.Getenv("CF_ACCESS_CLIENT_SECRET"))
	}
	if flagID != "" {
		api.AccessClientID = strings.TrimSpace(flagID)
	}
	if flagSecret != "" {
		api.AccessClientSecret = strings.TrimSpace(flagSecret)
	}
}
