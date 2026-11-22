package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/thelad-dev/ssh-sync/internal/agentconfig"
	"github.com/thelad-dev/ssh-sync/internal/agentsync"
	"github.com/thelad-dev/ssh-sync/internal/client"
	"github.com/thelad-dev/ssh-sync/internal/clientauth"
	"github.com/thelad-dev/ssh-sync/internal/crypto"
	"github.com/thelad-dev/ssh-sync/internal/importlocal"
)

func runImport(cfgPath string, args []string) {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	server := fs.String("server", "", "API-URL (leer = aus Agent-Config)")
	sshDir := fs.String("ssh-dir", "", "SSH-Verzeichnis (Standard: ~/.ssh)")
	dryRun := fs.Bool("dry-run", false, "Nur anzeigen, nicht hochladen")
	skipExisting := fs.Bool("skip-existing", true, "Bereits vorhandene Namen/Aliase überspringen")
	accessID := fs.String("access-client-id", "", "Cloudflare Access Service Token ID")
	accessSecret := fs.String("access-client-secret", "", "Cloudflare Access Service Token Secret")
	_ = fs.Parse(args)

	cfg, cfgErr := agentconfig.Load(cfgPath)
	serverURL := *server
	if serverURL == "" && cfgErr == nil {
		serverURL = cfg.ServerURL
	}
	if serverURL == "" {
		fmt.Fprintln(os.Stderr, "--server oder Agent-Config mit server_url erforderlich")
		os.Exit(1)
	}

	dir := *sshDir
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".ssh")
	}

	bundle, err := importlocal.LoadSSHDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Import lesen fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Gefunden: %d Identities, %d Hosts in %s\n", len(bundle.Identities), len(bundle.Hosts), dir)
	for _, id := range bundle.Identities {
		fmt.Printf("  Identity: %s (%s)\n", id.Name, id.Path)
	}
	for _, h := range bundle.Hosts {
		fmt.Printf("  Host: %s → %s@%s:%d\n", h.Alias, h.User, h.HostName, h.Port)
	}

	if *dryRun {
		return
	}

	master := promptPassword("Master-Passwort:")

	deviceJWT := ""
	if cfgErr == nil {
		deviceJWT = cfg.JWT
	}
	if deviceJWT != "" {
		fmt.Println("→ Import via Geräte-Auth (/api/agent/import)")
		agentCfg := &agentconfig.Config{
			ServerURL:          serverURL,
			JWT:                deviceJWT,
			SSHDir:             dir,
			AccessClientID:     *accessID,
			AccessClientSecret: *accessSecret,
		}
		if cfgErr == nil {
			agentCfg.DeviceID = cfg.DeviceID
			if *accessID == "" {
				agentCfg.AccessClientID = cfg.AccessClientID
			}
			if *accessSecret == "" {
				agentCfg.AccessClientSecret = cfg.AccessClientSecret
			}
		}
		result, err := agentsync.ImportLocal(agentCfg, master, *skipExisting)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Import fehlgeschlagen: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(result.Summary())
		for _, c := range result.Conflicts {
			fmt.Printf("  Konflikt: %s\n", c)
		}
		fmt.Println("Nächster Schritt: Im Portal „Jetzt syncen“")
		return
	}

	fmt.Fprintln(os.Stderr, "→ config.json ohne jwt — veralteter Portal-Login-Weg")
	fmt.Fprintln(os.Stderr, "  Im Portal Gerät anlegen, config.json kopieren, dann erneut importieren.")
	runPortalImport(cfgPath, serverURL, dir, bundle, master, *skipExisting, *accessID, *accessSecret)
}

func runPortalImport(cfgPath, serverURL, sshDir string, bundle *importlocal.Bundle, master string, skipExisting bool, accessID, accessSecret string) {
	api := client.New(serverURL, "")
	applyCloudflareAccess(api, cfgPath, accessID, accessSecret)
	keys, err := clientauth.PortalLogin(api, master)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Login fehlgeschlagen: %v\n", err)
		fmt.Fprintln(os.Stderr, "Tipp: Geraet im Portal anlegen und config.json mit jwt verwenden (ssh-sync import nutzt dann Geraete-Auth wie ping).")
		os.Exit(1)
	}

	existingNames := map[string]bool{}
	existingAliases := map[string]bool{}
	nameToServerID := map[string]string{}
	if skipExisting {
		if list, err := api.ListIdentities(); err == nil {
			for _, i := range list {
				existingNames[i.Name] = true
				nameToServerID[i.Name] = i.ID
			}
		}
		if list, err := api.ListHosts(); err == nil {
			for _, h := range list {
				existingAliases[h.Alias] = true
			}
		}
	}

	importedIDs := 0
	importedHosts := 0
	for _, id := range bundle.Identities {
		if existingNames[id.Name] {
			fmt.Printf("  uebersprungen (existiert): Identity %s\n", id.Name)
			continue
		}
		enc, err := crypto.EncryptIdentity(keys, id.ID, id.PublicKey, id.PrivateKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Verschluesseln %s: %v\n", id.Name, err)
			os.Exit(1)
		}
		if err := api.PutIdentity(id.ID, client.IdentityPayload{
			Name:                id.Name,
			PublicKey:           id.PublicKey,
			EncryptedPrivateKey: enc,
			Comment:             "importiert von " + id.Path,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "Upload Identity %s: %v\n", id.Name, err)
			os.Exit(1)
		}
		nameToServerID[id.Name] = id.ID
		importedIDs++
		fmt.Printf("  hochgeladen: Identity %s\n", id.Name)
	}

	for _, h := range bundle.Hosts {
		identityID := resolvePortalIdentityID(bundle, sshDir, h.IdentityPath, nameToServerID)
		if existingAliases[h.Alias] {
			if identityID != nil {
				list, err := api.ListHosts()
				if err == nil {
					for _, ex := range list {
						if ex.Alias != h.Alias || ex.IdentityID != nil {
							continue
						}
						if err := api.PutHost(ex.ID, client.HostPayload{
							Alias:          ex.Alias,
							HostName:       ex.HostName,
							User:           ex.User,
							Port:           ex.Port,
							IdentityID:     identityID,
							ProxyJump:      ex.ProxyJump,
							IdentitiesOnly: ex.IdentitiesOnly,
							Extra:          ex.Extra,
						}); err == nil {
							fmt.Printf("  verknüpft: Host %s → Identity\n", h.Alias)
							importedHosts++
						}
						break
					}
				}
			}
			fmt.Printf("  übersprungen (existiert): Host %s\n", h.Alias)
			continue
		}
		if err := api.PutHost(h.ID, client.HostPayload{
			Alias:          h.Alias,
			HostName:       h.HostName,
			User:           h.User,
			Port:           h.Port,
			IdentityID:     identityID,
			ProxyJump:      h.ProxyJump,
			IdentitiesOnly: h.IdentitiesOnly,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "Upload Host %s: %v\n", h.Alias, err)
			os.Exit(1)
		}
		importedHosts++
		fmt.Printf("  hochgeladen: Host %s\n", h.Alias)
	}

	fmt.Printf("\nImport abgeschlossen: %d Identities, %d Hosts\n", importedIDs, importedHosts)
	fmt.Println("Nächster Schritt: Im Portal „An alle Clients syncen“ oder ssh-sync pull")
}

func resolvePortalIdentityID(bundle *importlocal.Bundle, sshDir, identityPath string, nameToServerID map[string]string) *string {
	localID := bundle.IdentityIDForPath(sshDir, identityPath)
	if localID == nil {
		return nil
	}
	for _, id := range bundle.Identities {
		if id.ID != *localID {
			continue
		}
		if serverID, ok := nameToServerID[id.Name]; ok {
			v := serverID
			return &v
		}
		break
	}
	return localID
}
