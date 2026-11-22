package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/thelad-dev/ssh-sync/internal/agentconfig"
	"github.com/thelad-dev/ssh-sync/internal/client"
	"github.com/thelad-dev/ssh-sync/internal/clientauth"
	"github.com/thelad-dev/ssh-sync/internal/crypto"
	"github.com/thelad-dev/ssh-sync/internal/importlocal"
	"github.com/thelad-dev/ssh-sync/internal/keygen"
)

func runKeygen(cfgPath string, args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	name := fs.String("name", "", "Identity-Name (z.B. deploy-github)")
	keyType := fs.String("type", "ed25519", "Key-Typ: ed25519 oder rsa")
	server := fs.String("server", "", "API-URL (leer = config.json)")
	upload := fs.Bool("upload", true, "Key zum Server hochladen")
	localDir := fs.String("local-dir", "", "Zusätzlich nach ~/.ssh schreiben (leer = nicht)")
	accessID := fs.String("access-client-id", "", "Cloudflare Access Service Token ID")
	accessSecret := fs.String("access-client-secret", "", "Cloudflare Access Service Token Secret")
	_ = fs.Parse(args)

	if *name == "" {
		fmt.Fprintln(os.Stderr, "--name erforderlich")
		os.Exit(1)
	}

	kp, err := keygen.Generate(keygen.Type(*keyType), *name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Key erzeugen: %v\n", err)
		os.Exit(1)
	}

	if *localDir != "" {
		if err := writeLocalKeypair(*localDir, *name, kp.PrivatePEM, kp.PublicLine); err != nil {
			fmt.Fprintf(os.Stderr, "Lokal schreiben: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Lokal gespeichert: %s/%s\n", *localDir, *name)
	}

	if !*upload {
		fmt.Println(kp.PublicLine)
		return
	}

	cfg, cfgErr := agentconfig.Load(cfgPath)
	serverURL := *server
	if serverURL == "" && cfgErr == nil {
		serverURL = cfg.ServerURL
	}
	if serverURL == "" {
		fmt.Fprintln(os.Stderr, "--server oder config.json erforderlich")
		os.Exit(1)
	}

	master := promptPassword("Master-Passwort:")
	id, err := importlocal.NewID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ID: %v\n", err)
		os.Exit(1)
	}

	if cfgErr == nil && cfg.JWT != "" {
		uploadKeygenAgent(cfgPath, serverURL, cfg.JWT, master, id, *name, kp.PrivatePEM, kp.PublicLine, *accessID, *accessSecret)
		return
	}
	uploadKeygenPortal(cfgPath, serverURL, master, id, *name, kp.PrivatePEM, kp.PublicLine, *accessID, *accessSecret)
}

func uploadKeygenAgent(cfgPath, serverURL, jwt, master, id, name string, privatePEM []byte, publicLine, accessID, accessSecret string) {
	api := client.New(serverURL, jwt)
	applyCloudflareAccess(api, cfgPath, accessID, accessSecret)
	salt, err := api.KDFSalt()
	if err != nil {
		fmt.Fprintf(os.Stderr, "KDF-Salt: %v\n", err)
		os.Exit(1)
	}
	keys := crypto.DeriveKeys(master, salt)
	enc, err := crypto.EncryptIdentity(keys, id, publicLine, privatePEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Verschluesseln: %v\n", err)
		os.Exit(1)
	}
	_, err = api.AgentImport(client.AgentImportPayload{
		SkipExisting: true,
		Identities: []client.AgentImportIdentity{{
			ID:                  id,
			Name:                name,
			PublicKey:           publicLine,
			EncryptedPrivateKey: enc,
			Comment:             "ssh-sync keygen",
		}},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Upload fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Identity %q hochgeladen (ID %s)\n", name, id)
	fmt.Println(publicLine)
	fmt.Println("Naechster Schritt: Im Portal Hosts zuordnen und Sync ausloesen")
}

func uploadKeygenPortal(cfgPath, serverURL, master, id, name string, privatePEM []byte, publicLine, accessID, accessSecret string) {
	api := client.New(serverURL, "")
	applyCloudflareAccess(api, cfgPath, accessID, accessSecret)
	keys, err := clientauth.PortalLogin(api, master)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Login: %v\n", err)
		os.Exit(1)
	}
	enc, err := crypto.EncryptIdentity(keys, id, publicLine, privatePEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Verschluesseln: %v\n", err)
		os.Exit(1)
	}
	if err := api.PutIdentity(id, client.IdentityPayload{
		Name:                name,
		PublicKey:           publicLine,
		EncryptedPrivateKey: enc,
		Comment:             "ssh-sync keygen",
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Upload: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Identity %q hochgeladen (ID %s)\n", name, id)
	fmt.Println(publicLine)
	fmt.Println("Naechster Schritt: Im Portal Hosts zuordnen und Sync ausloesen")
}

func writeLocalKeypair(dir, name string, privatePEM []byte, publicLine string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	privPath := filepath.Join(dir, name)
	pubPath := privPath + ".pub"
	if err := os.WriteFile(privPath, privatePEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(pubPath, []byte(publicLine+"\n"), 0o644)
}
