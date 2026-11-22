package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/thelad-dev/ssh-sync/internal/agentconfig"
	"github.com/thelad-dev/ssh-sync/internal/agentpurge"
)

func runPurge(cfgPath string, args []string) {
	fs := flag.NewFlagSet("purge", flag.ExitOnError)
	yes := fs.Bool("yes", false, "Bestätigung überspringen (Tests / nach Portal-Ack)")
	postAck := fs.Bool("post-ack", false, "Intern: Purge nach Daemon-Ack (keine erneute Bestätigung)")
	managedOnly := fs.Bool("managed-only", false, "Nur verwaltete ssh-sync-Dateien entfernen")
	configPath := fs.String("config", cfgPath, "Agent-Config-Pfad")
	_ = fs.Parse(args)

	if !*postAck && !*yes {
		if !confirmPurgePhrase() {
			fmt.Fprintln(os.Stderr, "Abgebrochen — nichts gelöscht.")
			os.Exit(1)
		}
	}

	if err := agentpurge.Execute(agentpurge.Options{
		ManagedOnly: *managedOnly,
		ConfigPath:  *configPath,
		SkipBinary:  false,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Purge fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Gerät abgegeben — ssh-sync und lokale Sync-Daten entfernt.")
}

func confirmPurgePhrase() bool {
	fmt.Fprint(os.Stderr, "Lokale SSH-Sync-Daten werden geloescht (authorized_keys/known_hosts bleiben). Zur Bestaetigung PURGE eingeben: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	return strings.TrimSpace(line) == "PURGE"
}

func spawnPostAckPurge(managedOnly bool) {
	cfgPath, err := agentconfig.DefaultPath()
	if err != nil {
		log.Printf("purge nach ack: config-Pfad: %v", err)
		os.Exit(0)
	}
	args := []string{"purge", "--yes", "--post-ack", "--config", cfgPath}
	if managedOnly {
		args = append(args, "--managed-only")
	}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	detachPurgeCmd(cmd)
	if err := cmd.Start(); err != nil {
		log.Printf("purge nach ack: Hintergrund-Prozess starten fehlgeschlagen: %v — lokal: ssh-sync purge", err)
		os.Exit(0)
	}
	os.Exit(0)
}
