package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/agentauth"
	"github.com/thelad-dev/ssh-sync/internal/agentconfig"
	"github.com/thelad-dev/ssh-sync/internal/agentpurge"
	"github.com/thelad-dev/ssh-sync/internal/agentsync"
	"github.com/thelad-dev/ssh-sync/internal/client"
	"github.com/thelad-dev/ssh-sync/internal/keyring"
	"github.com/thelad-dev/ssh-sync/internal/releaseverify"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

func runDaemon(cfgPath string, args []string) {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	configPath := fs.String("config", cfgPath, "Agent-Config-Pfad")
	_ = fs.Parse(args)

	cfg, err := agentconfig.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config laden fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}

	interval := cfg.PollIntervalSec
	if interval <= 0 {
		interval = 30
	}

	log.Printf("ssh-sync daemon (Gerät %s, Intervall %ds) — Strg+C zum Beenden", cfg.DeviceID, interval)
	if cfg.AccessClientID == "" || cfg.AccessClientSecret == "" {
		log.Printf("WARNUNG: access_client_id/secret fehlen in config — hinter Cloudflare Access schlägt ping fehl")
	}

	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		close(stop)
	}()

	if err := agentauth.EnsureDeviceJWT(*configPath, cfg); err != nil {
		log.Printf("geraete-token erneuern fehlgeschlagen: %v", err)
	}
	runDaemonUntil(cfg, stop)
}

// runDaemonUntil pollt den Server bis stop geschlossen wird.
func runDaemonUntil(cfg *agentconfig.Config, stop <-chan struct{}) {
	interval := cfg.PollIntervalSec
	if interval <= 0 {
		interval = 30
	}

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	runDaemonLoop(cfg)

	for {
		select {
		case <-ticker.C:
			runDaemonLoop(cfg)
		case <-stop:
			log.Println("daemon beendet")
			return
		}
	}
}

func runDaemonLoop(cfg *agentconfig.Config) {
	if err := releaseverify.CheckServerURL(cfg.ServerURL, false); err != nil {
		log.Printf("server_url abgelehnt: %v", err)
		return
	}
	api := newAgentAPI(cfg)
	if err := api.DaemonPing(); err != nil {
		log.Printf("ping fehlgeschlagen: %v", err)
		return
	}

	cmd, err := api.PollCommand()
	if err != nil {
		log.Printf("poll fehlgeschlagen: %v", err)
		return
	}
	if cmd != nil {
		log.Printf("befehl empfangen: %s (%s)", cmd.Command, cmd.ID)
		switch cmd.Command {
		case store.CommandSync:
			runSyncCommand(api, cfg, cmd.ID)
		case store.CommandImport:
			runImportCommand(api, cfg, cmd.ID)
		case store.CommandPurge:
			runPurgeCommand(api, cmd.ID)
		default:
			_ = api.CompleteCommand(cmd.ID, store.StatusFailed, "unbekannter befehl")
		}
		return
	}

	// Kein Portal-Befehl: regelmäßig Server-Config nach ~/.ssh ziehen (Dauer-Sync).
	runAutoSync(api, cfg)
}

func runAutoSync(api *client.API, cfg *agentconfig.Config) {
	master, err := keyring.GetMasterPassword()
	if err != nil {
		return // unlock noch nicht — still überspringen
	}
	result, err := agentsync.Pull(cfg, master)
	if err != nil {
		log.Printf("auto-sync fehlgeschlagen: %v", err)
		return
	}
	if result.ConfigBackup != "" {
		log.Printf("auto-sync: %d Hosts, %d Keys — alte config → %s", result.Hosts, result.Keys, result.ConfigBackup)
	} else {
		log.Printf("auto-sync: %d Hosts, %d Keys", result.Hosts, result.Keys)
	}
}

func runSyncCommand(api *client.API, cfg *agentconfig.Config, cmdID string) {
	master, err := keyring.GetMasterPassword()
	if err != nil {
		_ = api.CompleteCommand(cmdID, store.StatusFailed, err.Error())
		log.Printf("sync fehlgeschlagen: %v", err)
		return
	}

	result, err := agentsync.Pull(cfg, master)
	if err != nil {
		_ = api.CompleteCommand(cmdID, store.StatusFailed, err.Error())
		log.Printf("sync fehlgeschlagen: %v", err)
		return
	}

	msg := fmt.Sprintf("%d Hosts, %d Keys", result.Hosts, result.Keys)
	if result.ConfigBackup != "" {
		msg += "; backup " + result.ConfigBackup
	}
	_ = api.CompleteCommand(cmdID, store.StatusComplete, msg)
	log.Printf("sync abgeschlossen: %s", msg)
}

func runImportCommand(api *client.API, cfg *agentconfig.Config, cmdID string) {
	master, err := keyring.GetMasterPassword()
	if err != nil {
		_ = api.CompleteCommand(cmdID, store.StatusFailed, "unlock erforderlich: ssh-sync unlock")
		log.Printf("import fehlgeschlagen: %v", err)
		return
	}
	result, err := agentsync.ImportLocal(cfg, master, true)
	if err != nil {
		_ = api.CompleteCommand(cmdID, store.StatusFailed, err.Error())
		log.Printf("import fehlgeschlagen: %v", err)
		return
	}
	msg := result.Summary()
	if len(result.Conflicts) > 0 {
		msg += " — " + strings.Join(result.Conflicts, "; ")
	}
	_ = api.CompleteCommand(cmdID, store.StatusComplete, msg)
	log.Printf("import abgeschlossen: %s", msg)
}

func runPurgeCommand(api *client.API, cmdID string) {
	cfgPath, err := agentconfig.DefaultPath()
	if err != nil {
		_ = api.CompleteCommand(cmdID, store.StatusFailed, "config-Pfad: "+err.Error())
		log.Printf("purge fehlgeschlagen: config-Pfad: %v", err)
		return
	}
	cfg, err := agentconfig.Load(cfgPath)
	if err != nil {
		_ = api.CompleteCommand(cmdID, store.StatusFailed, err.Error())
		log.Printf("purge fehlgeschlagen: %v", err)
		return
	}
	// Vollwipe von ~/.ssh (ohne Backup) bevor completed gemeldet wird; JWT noch gueltig.
	if err := agentpurge.WipeSSHDir(cfg.ResolveSSHDir()); err != nil {
		_ = api.CompleteCommand(cmdID, store.StatusFailed, err.Error())
		log.Printf("purge wipe fehlgeschlagen: %v", err)
		return
	}
	if err := api.CompleteCommand(cmdID, store.StatusComplete, "Gerät abgegeben"); err != nil {
		log.Printf("purge ack fehlgeschlagen: %v", err)
		return
	}
	log.Printf("purge ack gesendet - starte lokale Bereinigung (Vollwipe, ohne managed-only)")
	spawnPostAckPurge(false)
}

func newAgentAPI(cfg *agentconfig.Config) *client.API {
	api := client.New(cfg.ServerURL, cfg.JWT)
	api.AccessClientID = cfg.AccessClientID
	api.AccessClientSecret = cfg.AccessClientSecret
	return api
}
