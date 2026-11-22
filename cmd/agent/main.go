package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/thelad-dev/ssh-sync/internal/agentconfig"
	"github.com/thelad-dev/ssh-sync/internal/agentsync"
	"github.com/thelad-dev/ssh-sync/internal/client"
	"github.com/thelad-dev/ssh-sync/internal/releaseverify"
	"github.com/thelad-dev/ssh-sync/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	cfgPath, _ := agentconfig.DefaultPath()
	switch os.Args[1] {
	case "init":
		runInit(cfgPath, os.Args[2:])
	case "pull":
		runPull(cfgPath, os.Args[2:])
	case "status":
		runStatus(cfgPath)
	case "import":
		if len(os.Args) >= 3 && !strings.HasPrefix(os.Args[2], "-") {
			runAccountImportFile(cfgPath, os.Args[2], os.Args[3:])
		} else {
			runImport(cfgPath, os.Args[2:])
		}
	case "export":
		runAccountExport(cfgPath, os.Args[2:])
	case "backup":
		runBackup(os.Args[2:])
	case "daemon":
		runDaemon(cfgPath, os.Args[2:])
	case "service":
		runServiceCommand(cfgPath, os.Args[2:])
	case "keygen":
		runKeygen(cfgPath, os.Args[2:])
	case "unlock":
		runUnlock()
	case "update":
		runUpdate(cfgPath, os.Args[2:])
	case "purge":
		runPurge(cfgPath, os.Args[2:])
	case "version":
		fmt.Println(version.Agent)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unbekannter Befehl: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `ssh-sync Agent

Befehle:
  init    --server URL --name NAME [--device-id ID --jwt JWT] [--user-token TOKEN]
  export  --out DATEI [--server URL]   Konten-Archiv (Keys bleiben verschluesselt)
  import  DATEI [--server URL] [--mode merge|replace] [--dry-run] [--setup-new]
  import  [--server URL] [--ssh-dir PATH] [--dry-run]   lokales ~/.ssh importieren
  backup  export|import [--server URL] [--output|--input DATEI]
  unlock                       Master-Passwort im Keyring speichern
  daemon                       Hintergrund-Agent (Vordergrund, Strg+C)
  service install|repair|start|stop   Windows-Dienst (Hintergrund)
  keygen  --name NAME [--type ed25519|rsa] [--upload] [--local-dir PATH]
  pull    [--config PATH]
  status
  update  [--server URL] [--no-restart]
  purge   [--managed-only] [--yes]   Gerät abgeben (löscht ~/.ssh, Config, Binary)
  version

Beispiel:
  ssh-sync init --server https://ssh.example.com --name laptop-linux
  ssh-sync unlock
  ssh-sync daemon
`)
}

func runInit(cfgPath string, args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	server := fs.String("server", "", "API-URL (z.B. https://portal.example)")
	name := fs.String("name", "", "Gerätename")
	userToken := fs.String("user-token", "", "Portal-Login-Token (nur für Neuregistrierung)")
	deviceID := fs.String("device-id", "", "Geräte-ID aus Portal (überspringt Registrierung)")
	deviceJWT := fs.String("jwt", "", "Geräte-JWT aus Portal (überspringt Registrierung)")
	accessID := fs.String("access-client-id", "", "Cloudflare Access Service Token ID")
	accessSecret := fs.String("access-client-secret", "", "Cloudflare Access Service Token Secret")
	insecure := fs.Bool("insecure", false, "http:// ausserhalb Loopback erlauben (unsicher)")
	_ = fs.Parse(args)

	if *server == "" || *name == "" {
		fmt.Fprintln(os.Stderr, "--server und --name sind erforderlich")
		os.Exit(1)
	}
	if err := releaseverify.CheckServerURL(*server, *insecure); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var id, jwt string
	if *deviceID != "" && *deviceJWT != "" {
		id, jwt = *deviceID, *deviceJWT
	} else {
		token := *userToken
		if token == "" {
			fmt.Fprintln(os.Stderr, "Gerät im Portal anlegen (Geräte → + Gerät) und Config kopieren  -  oder --device-id/--jwt bzw. --user-token angeben.")
			token = promptLine("Portal-Login-Token (nur falls init ohne Portal-Config):")
		}
		api := client.New(*server, token)
		api.AccessClientID = *accessID
		api.AccessClientSecret = *accessSecret
		resp, err := api.RegisterDevice(*name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Gerät registrieren fehlgeschlagen: %v\n", err)
			os.Exit(1)
		}
		id, jwt = resp.ID, resp.JWT
	}

	cfg := &agentconfig.Config{
		ServerURL:          *server,
		DeviceID:           id,
		JWT:                jwt,
		AccessClientID:     *accessID,
		AccessClientSecret: *accessSecret,
	}
	if err := agentconfig.Save(cfgPath, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Config speichern fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Gerät konfiguriert: %s (%s)\n", *name, id)
	fmt.Printf("Config: %s\n", cfgPath)
	fmt.Println("Nächster Schritt: ssh-sync unlock && ssh-sync daemon")
}

func runPull(cfgPath string, args []string) {
	fs := flag.NewFlagSet("pull", flag.ExitOnError)
	configPath := fs.String("config", cfgPath, "Agent-Config-Pfad")
	_ = fs.Parse(args)

	cfg, err := agentconfig.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config laden fehlgeschlagen (%s): %v\n", *configPath, err)
		fmt.Fprintln(os.Stderr, "Zuerst: ssh-sync init --server URL --name NAME")
		os.Exit(1)
	}

	master := promptPassword("Master-Passwort:")
	result, err := agentsync.Pull(cfg, master)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sync fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Sync abgeschlossen für Gerät %s\n", cfg.DeviceID)
	fmt.Printf("  Hosts:    %d\n", result.Hosts)
	fmt.Printf("  Keys:     %d\n", result.Keys)
	fmt.Printf("  Config:   %s\n", result.Config)
	if result.ConfigBackup != "" {
		fmt.Printf("  Backup:   %s (alte config, einmalig)\n", result.ConfigBackup)
	}
	for _, p := range result.KeyPaths {
		fmt.Printf("  Key:      %s\n", p)
	}
}

func runStatus(cfgPath string) {
	cfg, err := agentconfig.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config fehlerhaft (%s): %v\n", cfgPath, err)
		os.Exit(1)
	}
	fmt.Printf("Server:   %s\n", cfg.ServerURL)
	fmt.Printf("Gerät:    %s\n", cfg.DeviceID)
	fmt.Printf("SSH-Dir:  %s\n", cfg.ResolveSSHDir())
	fmt.Printf("Config:   %s\n", cfgPath)
	if cfg.AccessClientID == "" || cfg.AccessClientSecret == "" {
		fmt.Println("CF Access: FEHLT (access_client_id/secret in config.json)")
	} else {
		fmt.Println("CF Access: gesetzt")
	}

	api := newAgentAPI(cfg)
	if err := api.DaemonPing(); err != nil {
		fmt.Fprintf(os.Stderr, "Ping fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Ping:     ok")
	bundle, err := api.Sync()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Server nicht erreichbar: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Remote:   %d Hosts, %d Keys\n", len(bundle.Hosts), len(bundle.Identities))
}

func promptPassword(label string) string {
	fmt.Fprint(os.Stderr, label+" ")
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Passwort lesen fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	return string(b)
}

func promptLine(label string) string {
	fmt.Fprint(os.Stderr, label+" ")
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "Eingabe fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	return strings.TrimSpace(line)
}
