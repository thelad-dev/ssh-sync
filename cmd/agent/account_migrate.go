package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/thelad-dev/ssh-sync/internal/accountexport"
	"github.com/thelad-dev/ssh-sync/internal/agentconfig"
	"github.com/thelad-dev/ssh-sync/internal/client"
	"github.com/thelad-dev/ssh-sync/internal/clientauth"
	"github.com/thelad-dev/ssh-sync/internal/crypto"
)

func runAccountExport(cfgPath string, args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	server := fs.String("server", "", "API-URL")
	out := fs.String("out", "", "Zieldatei")
	_ = fs.Parse(args)
	if *out == "" {
		fmt.Fprintln(os.Stderr, "--out erforderlich")
		os.Exit(1)
	}

	api, _, master := loginAPIWithMaster(cfgPath, *server)
	payload, err := api.AccountExport()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Export fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	confirm := promptPassword("Master-Passwort bestaetigen (Archiv-Integritaet):")
	if confirm != master {
		fmt.Fprintln(os.Stderr, "Passwort-Bestaetigung stimmt nicht")
		os.Exit(1)
	}
	raw, err := accountexport.Seal(master, *payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Archiv erzeugen fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	if err := accountexport.WriteFile(*out, raw); err != nil {
		fmt.Fprintf(os.Stderr, "Schreiben fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Konten-Archiv gespeichert: %s\n", *out)
	fmt.Printf("  %d Keys, %d Hosts, %d Geraete (nur Namen)\n",
		len(payload.Identities), len(payload.Hosts), len(payload.Devices))
	fmt.Println("Hinweis: Private Keys bleiben verschluesselt; Geraete-Token sind nicht enthalten.")
}

func runAccountImportFile(cfgPath string, file string, args []string) {
	fs := flag.NewFlagSet("import-account", flag.ExitOnError)
	server := fs.String("server", "", "API-URL")
	mode := fs.String("mode", "merge", "merge oder replace")
	dryRun := fs.Bool("dry-run", false, "Nur Bericht, nichts schreiben")
	setupNew := fs.Bool("setup-new", false, "Zielserver ist leer: Setup mit Salt aus dem Archiv")
	_ = fs.Parse(args)

	raw, err := accountexport.ReadFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Archiv lesen fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	master := promptPassword("Master-Passwort (Archiv):")
	env, err := accountexport.Open(master, raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Archiv oeffnen fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	if err := accountexport.MigratePayloadForward(env.SchemaVersion, &env.Payload); err != nil {
		fmt.Fprintf(os.Stderr, "Migration fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}

	serverURL := *server
	if serverURL == "" {
		if cfg, err := agentconfig.Load(cfgPath); err == nil {
			serverURL = cfg.ServerURL
		}
	}
	if serverURL == "" {
		fmt.Fprintln(os.Stderr, "--server oder Agent-Config erforderlich")
		os.Exit(1)
	}

	api := client.New(serverURL, "")
	applyCloudflareAccess(api, cfgPath, "", "")
	api.SetupToken = os.Getenv("SSH_SYNC_SETUP_TOKEN")

	if *setupNew {
		salt, err := hex.DecodeString(env.Payload.KDFSalt)
		if err != nil || len(salt) != crypto.SaltLen {
			fmt.Fprintln(os.Stderr, "kdf_salt im Archiv ungueltig")
			os.Exit(1)
		}
		keys := crypto.DeriveKeys(master, salt)
		if err := api.Setup(hex.EncodeToString(keys.AuthKey), env.Payload.KDFSalt); err != nil {
			fmt.Fprintf(os.Stderr, "Setup fehlgeschlagen: %v\n", err)
			os.Exit(1)
		}
	} else {
		if _, err := clientauth.PortalLogin(api, master); err != nil {
			fmt.Fprintf(os.Stderr, "Login fehlgeschlagen: %v\n", err)
			os.Exit(1)
		}
	}

	m := accountexport.ConflictMode(strings.ToLower(*mode))
	rep, err := api.AccountImport(env.Payload, m, *dryRun)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Import fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	printImportReport(rep)
}

func printImportReport(rep *accountexport.Report) {
	prefix := "Import"
	if rep.DryRun {
		prefix = "Trockenlauf"
	}
	fmt.Printf("%s (%s): +%d Keys, +%d Hosts, skip %d/%d, settings %d\n",
		prefix, rep.Mode, rep.IdentitiesUpserted, rep.HostsUpserted,
		rep.IdentitiesSkipped, rep.HostsSkipped, rep.SettingsWritten)
	if rep.IdentitiesDeleted > 0 || rep.HostsDeleted > 0 {
		fmt.Printf("  ersetzt/geloescht: %d Keys, %d Hosts\n", rep.IdentitiesDeleted, rep.HostsDeleted)
	}
	for _, n := range rep.Notes {
		fmt.Printf("  Hinweis: %s\n", n)
	}
	for _, c := range rep.Conflicts {
		fmt.Printf("  Konflikt: %s\n", c)
	}
}

func loginAPIWithMaster(cfgPath, server string) (*client.API, crypto.DerivedKeys, string) {
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
	return api, keys, master
}
