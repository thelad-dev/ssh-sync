package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/thelad-dev/ssh-sync/internal/agentconfig"
	"github.com/thelad-dev/ssh-sync/internal/agentservice"
	"github.com/thelad-dev/ssh-sync/internal/client"
	"github.com/thelad-dev/ssh-sync/internal/selfupdate"
)

func runUpdate(cfgPath string, args []string) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	server := fs.String("server", "", "API-URL (leer = aus config.json oder SSH_SYNC_URL)")
	dest := fs.String("dest", "", "Zielpfad (Standard: aktuelles ssh-sync Binary)")
	noRestart := fs.Bool("no-restart", false, "Daemon/Scheduled Task nicht neu starten")
	insecure := fs.Bool("insecure", false, "http:// ausserhalb Loopback erlauben (unsicher)")
	accessID := fs.String("access-client-id", "", "Cloudflare Access Service Token ID")
	accessSecret := fs.String("access-client-secret", "", "Cloudflare Access Service Token Secret")
	_ = fs.Parse(args)

	if !*noRestart {
		stopAgentServiceForUpdate()
	}

	maybeReexecUpdate(*dest, args)

	serverURL := *server
	if serverURL == "" {
		serverURL = os.Getenv("SSH_SYNC_URL")
	}
	if serverURL == "" {
		if cfg, err := agentconfig.Load(cfgPath); err == nil {
			serverURL = cfg.ServerURL
		}
	}
	if serverURL == "" {
		fmt.Fprintln(os.Stderr, "Server-URL fehlt  -  config.json, SSH_SYNC_URL oder --server setzen")
		os.Exit(1)
	}

	api := client.New(serverURL, "")
	applyCloudflareAccess(api, cfgPath, *accessID, *accessSecret)

	result, err := selfupdate.Apply(selfupdate.Options{
		ServerURL:          serverURL,
		AccessClientID:     api.AccessClientID,
		AccessClientSecret: api.AccessClientSecret,
		DestPath:           *dest,
		Insecure:           *insecure,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Update fehlgeschlagen: %v\n", err)
		if result != nil && result.RolledBack {
			fmt.Fprintln(os.Stderr, "Vorheriges Binary wurde wiederhergestellt.")
		}
		if runtime.GOOS == "windows" {
			fmt.Fprintln(os.Stderr, "Tipp: ssh-sync update --no-restart  oder  ssh-sync service status")
		} else {
			fmt.Fprintln(os.Stderr, "Tipp: ssh-sync update --no-restart")
			fmt.Fprintln(os.Stderr, "      cp ~/.local/bin/ssh-sync /tmp/ssh-sync && /tmp/ssh-sync update")
		}
		os.Exit(1)
	}

	fmt.Printf("Aktualisiert: %s → %s (%d Bytes, Version %s)\n", result.Asset, result.DestPath, result.Bytes, result.Version)

	if !*noRestart {
		startAgentServiceForUpdate()
	}
}

func stopAgentServiceForUpdate() {
	res, err := agentservice.Stop()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Dienst stoppen fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	if res.Changed {
		fmt.Printf("Dienst gestoppt (%s)\n", res.Method)
	}
}

func startAgentServiceForUpdate() {
	res, err := agentservice.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Dienst starten fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	if res.Changed {
		fmt.Printf("Dienst gestartet (%s)\n", res.Method)
	}
}
