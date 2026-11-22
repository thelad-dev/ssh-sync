package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/thelad-dev/ssh-sync/internal/agentconfig"
	"github.com/thelad-dev/ssh-sync/internal/backup"
	"github.com/thelad-dev/ssh-sync/internal/client"
	"github.com/thelad-dev/ssh-sync/internal/clientauth"
	"github.com/thelad-dev/ssh-sync/internal/crypto"
)

func runBackup(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Verwendung: ssh-sync backup export|import …")
		os.Exit(1)
	}
	cfgPath, _ := agentconfig.DefaultPath()
	switch args[0] {
	case "export":
		runBackupExport(cfgPath, args[1:])
	case "import":
		runBackupImport(cfgPath, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unbekannter backup-Befehl: %s\n", args[0])
		os.Exit(1)
	}
}

func runBackupExport(cfgPath string, args []string) {
	fs := flag.NewFlagSet("backup export", flag.ExitOnError)
	server := fs.String("server", "", "API-URL")
	output := fs.String("output", "ssh-sync-backup.json", "Zieldatei")
	_ = fs.Parse(args)

	api, encKey := loginAPI(cfgPath, *server)
	data, err := backup.BuildFromServer(api, encKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Backup erstellen fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}

	master := promptPassword("Backup-Passwort (zum Verschlüsseln):")
	raw, err := backup.Encrypt(master, data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Verschlüsseln fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*output, raw, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "Schreiben fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Backup gespeichert: %s\n", *output)
	fmt.Printf("  %d Keys, %d Hosts, %d Geräte (Metadaten)\n",
		len(data.Identities), len(data.Hosts), len(data.Devices))
}

func runBackupImport(cfgPath string, args []string) {
	fs := flag.NewFlagSet("backup import", flag.ExitOnError)
	server := fs.String("server", "", "API-URL")
	input := fs.String("input", "", "Backup-Datei")
	skipExisting := fs.Bool("skip-existing", true, "Vorhandene Einträge überspringen")
	_ = fs.Parse(args)

	if *input == "" {
		fmt.Fprintln(os.Stderr, "--input erforderlich")
		os.Exit(1)
	}

	raw, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Datei lesen fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}

	master := promptPassword("Backup-Passwort:")
	data, err := backup.Decrypt(master, raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Entschlüsseln fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}

	api, encKey := loginAPI(cfgPath, *server)
	res, err := backup.Restore(api, encKey, data, backup.RestoreOptions{SkipExisting: *skipExisting})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Wiederherstellen fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Wiederherstellung abgeschlossen: %d Keys, %d Hosts (%d übersprungen)\n",
		res.Identities, res.Hosts, res.Skipped)
	fmt.Println("Geräte müssen auf neuer Installation per ssh-sync init neu registriert werden.")
}

func loginAPI(cfgPath, server string) (*client.API, crypto.DerivedKeys) {
	serverURL := server
	if serverURL == "" {
		if cfg, err := agentconfig.Load(cfgPath); err == nil {
			serverURL = cfg.ServerURL
		}
	}
	if serverURL == "" {
		fmt.Fprintln(os.Stderr, "--server oder Agent-Config erforderlich")
		os.Exit(1)
	}

	master := promptPassword("Master-Passwort (Server-Login):")
	api := client.New(serverURL, "")
	applyCloudflareAccess(api, cfgPath, "", "")
	keys, err := clientauth.PortalLogin(api, master)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Login fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	return api, keys
}
