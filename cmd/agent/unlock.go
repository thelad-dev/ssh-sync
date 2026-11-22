package main

import (
	"fmt"
	"os"

	"github.com/thelad-dev/ssh-sync/internal/keyring"
)

func runUnlock() {
	master := promptPassword("Master-Passwort (für Hintergrund-Sync im Keyring speichern):")
	if len(master) < 12 {
		fmt.Fprintln(os.Stderr, "Passwort mindestens 12 Zeichen")
		os.Exit(1)
	}
	if err := keyring.SetMasterPassword(master); err != nil {
		fmt.Fprintf(os.Stderr, "Speichern fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	if os.Getenv("SSH_TTY") != "" {
		fmt.Println("Master-Passwort in ~/.config/ssh-sync/.master-key gespeichert (SSH: kein GNOME-Keyring).")
	} else {
		fmt.Println("Master-Passwort gespeichert (Keyring oder ~/.config/ssh-sync/.master-key).")
	}
	fmt.Println("Nächster Schritt: ssh-sync service start (Windows) oder ssh-sync daemon / systemd (Linux)")
}
