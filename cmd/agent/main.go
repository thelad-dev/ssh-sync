package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/thelad-dev/ssh-sync/internal/agentauth"
	"github.com/thelad-dev/ssh-sync/internal/agentconfig"
	"github.com/thelad-dev/ssh-sync/internal/agentsync"
	"github.com/thelad-dev/ssh-sync/internal/client"
	"github.com/thelad-dev/ssh-sync/internal/keyring"
	"github.com/thelad-dev/ssh-sync/internal/releaseverify"
	"github.com/thelad-dev/ssh-sync/internal/sshconfig"
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
  pull    [--config PATH] [--dry-run] [--apply]
  status
  update  [--server URL] [--no-restart]
  purge   [--managed-only] [--yes]   Gerät abgeben (löscht ~/.ssh, Config, Binary)
  version

Beispiel:
  ssh-sync init --server https://ssh.example.com --name laptop-linux
  ssh-sync unlock
  ssh-sync pull --apply
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
	dryRun := fs.Bool("dry-run", false, "nur anzeigen, nichts schreiben")
	apply := fs.Bool("apply", false, "ersten Abgleich wirklich schreiben (ohne managed Block)")
	_ = fs.Parse(args)

	cfg, err := agentconfig.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config laden fehlgeschlagen (%s): %v\n", *configPath, err)
		fmt.Fprintln(os.Stderr, "Zuerst: ssh-sync init --server URL --name NAME")
		os.Exit(1)
	}

	master, err := keyring.ResolveMasterPassword(term.IsTerminal(int(syscall.Stdin)), promptPasswordErr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	opts := agentsync.PullOptions{
		DryRun:          *dryRun,
		AllowFirstWrite: *apply,
	}

	// Erster Lauf ohne --apply: Trockenlauf, bei TTY Rueckfrage.
	first := !sshconfigHasManaged(cfg)
	if first && !*apply && !*dryRun {
		opts.DryRun = true
	}

	result, err := agentsync.Pull(cfg, master, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sync fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	printPullResult(cfg.DeviceID, result)

	if result.NeedsConfirm && !*apply {
		if !*dryRun && term.IsTerminal(int(syscall.Stdin)) {
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Noch kein verwalteter Config-Block vorhanden.")
			if promptConfirm("Jetzt schreiben? [y/N]: ") {
				result, err = agentsync.Pull(cfg, master, agentsync.PullOptions{AllowFirstWrite: true})
				if err != nil {
					fmt.Fprintf(os.Stderr, "Sync fehlgeschlagen: %v\n", err)
					os.Exit(1)
				}
				printPullResult(cfg.DeviceID, result)
				return
			}
		}
		fmt.Fprintln(os.Stderr, "Kein Schreibvorgang. Erneut mit: ssh-sync pull --apply")
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

	if err := agentauth.EnsureDeviceJWT(cfgPath, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Geraete-Token erneuern fehlgeschlagen: %v\n", err)
		os.Exit(1)
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

func sshconfigHasManaged(cfg *agentconfig.Config) bool {
	return sshconfig.HasManagedBlock(cfg.ResolveSSHDir())
}

func printPullResult(deviceID string, result *agentsync.PullResult) {
	title := "Sync abgeschlossen"
	if result.DryRun {
		title = "Trockenlauf (nichts geschrieben)"
	}
	fmt.Printf("%s für Gerät %s\n", title, deviceID)
	fmt.Printf("  Hosts:    %d\n", result.Hosts)
	fmt.Printf("  Keys:     %d\n", result.Keys)
	fmt.Printf("  Config:   %s\n", result.Config)
	if result.ConfigBackup != "" {
		fmt.Printf("  Backup:   %s\n", result.ConfigBackup)
	}
	for _, p := range result.KeyPaths {
		fmt.Printf("  Key:      %s\n", p)
	}
	for _, line := range result.Plans {
		fmt.Printf("  Plan:     %s\n", line)
	}
	for _, w := range result.Warnings {
		fmt.Fprintf(os.Stderr, "  Warnung:  %s\n", w)
	}
}

func promptConfirm(label string) bool {
	fmt.Fprint(os.Stderr, label)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	s := strings.TrimSpace(strings.ToLower(line))
	return s == "y" || s == "yes" || s == "j" || s == "ja"
}

func promptPassword(label string) string {
	pw, err := promptPasswordErr(label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Passwort lesen fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	return pw
}

func promptPasswordErr(label string) (string, error) {
	fmt.Fprint(os.Stderr, label+" ")
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
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
