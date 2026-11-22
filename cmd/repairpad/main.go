// repairpad repariert OpenSSH-Private-Key-Padding in der SQLite-Datenbank.
//
//	repairpad -db /app/data/ssh-sync.db
//
// Master-Passwort: SSH_SYNC_MASTER_PASSWORD oder interaktiv.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/thelad-dev/ssh-sync/internal/crypto"
	"github.com/thelad-dev/ssh-sync/internal/opensshkey"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

func main() {
	dbPath := flag.String("db", "data/ssh-sync.db", "SQLite-Datenbank")
	dryRun := flag.Bool("dry-run", false, "nur prüfen, nichts schreiben")
	flag.Parse()

	master := strings.TrimSpace(os.Getenv("SSH_SYNC_MASTER_PASSWORD"))
	if master == "" {
		fmt.Fprint(os.Stderr, "Master-Passwort: ")
		b, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fatal(err)
		}
		master = string(b)
	}
	if master == "" {
		fatal(fmt.Errorf("Master-Passwort fehlt"))
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		fatal(err)
	}
	defer st.Close()

	salt, err := st.GetKDFSalt()
	if err != nil {
		fatal(err)
	}
	keys := crypto.DeriveKeys(master, salt)

	ids, err := st.ListIdentities()
	if err != nil {
		fatal(err)
	}

	var fixedN, okN, errN int
	for _, id := range ids {
		plain, err := crypto.DecryptIdentity(keys, id.ID, id.PublicKey, id.EncryptedPrivateKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL  %s: entschluesseln: %v\n", id.Name, err)
			errN++
			continue
		}
		fixed, changed, err := opensshkey.FixPadding(plain)
		if err != nil {
			fmt.Printf("SKIP  %s: %v\n", id.Name, err)
			okN++
			continue
		}
		if !changed {
			fmt.Printf("OK    %s\n", id.Name)
			okN++
			continue
		}
		if *dryRun {
			fmt.Printf("WOULD %s (padding kaputt -> reparieren)\n", id.Name)
			fixedN++
			continue
		}
		enc, err := crypto.EncryptIdentity(keys, id.ID, id.PublicKey, fixed)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL  %s: verschluesseln: %v\n", id.Name, err)
			errN++
			continue
		}
		id.EncryptedPrivateKey = enc
		if err := st.UpsertIdentity(id); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL  %s: speichern: %v\n", id.Name, err)
			errN++
			continue
		}
		fmt.Printf("FIXED %s\n", id.Name)
		fixedN++
	}

	fmt.Printf("\nfertig: %d repariert, %d ok, %d fehler/skip (dry-run=%v)\n", fixedN, okN, errN, *dryRun)
	if errN > 0 {
		os.Exit(1)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "repairpad: %v\n", err)
	os.Exit(1)
}
