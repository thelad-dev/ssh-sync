//go:build !windows

package main

import (
	"fmt"
	"os"

	"github.com/thelad-dev/ssh-sync/internal/agentservice"
)

func runServiceCommand(cfgPath string, args []string) {
	fmt.Fprintln(os.Stderr, "ssh-sync service: nur unter Windows verfügbar")
	fmt.Fprintln(os.Stderr, "Linux: systemd user service (install/linux.sh) oder ssh-sync daemon")
	os.Exit(1)
}

func stopAgentService() {
	res, err := agentservice.Stop()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Dienst stoppen: %v\n", err)
		return
	}
	if res.Changed {
		fmt.Printf("Dienst gestoppt (%s)\n", res.Method)
	}
}

func startAgentService() {
	res, err := agentservice.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Dienst starten: %v\n", err)
		return
	}
	if res.Changed {
		fmt.Printf("Dienst gestartet (%s)\n", res.Method)
	}
}
