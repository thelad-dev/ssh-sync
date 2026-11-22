// Command genreleasekey generates or derives an Ed25519 release signing keypair.
//
// Usage:
//
//	genreleasekey -out ~/ssh-sync-release.seed
//	genreleasekey -seed ~/ssh-sync-release.seed
//
// Never commit the seed. Write it outside the repository with mode 0600.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	out := flag.String("out", "", "Neue Seed-Datei schreiben (32 Byte Hex, 0600)")
	seedPath := flag.String("seed", "", "Bestehende Seed-Datei lesen und Public Key ableiten")
	flag.Parse()

	path := strings.TrimSpace(*seedPath)
	creating := false
	if path == "" {
		path = strings.TrimSpace(*out)
		creating = true
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "usage: genreleasekey -out ~/ssh-sync-release.seed")
		fmt.Fprintln(os.Stderr, "       genreleasekey -seed ~/ssh-sync-release.seed")
		os.Exit(2)
	}

	var seed []byte
	if creating {
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := writeSeedFile(path, seed); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	} else {
		var err error
		seed, err = readSeedFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	pubHex := hex.EncodeToString(pub)
	fp := sha256.Sum256(pub)

	fpFull := hex.EncodeToString(fp[:])
	fmt.Printf("public_key_hex=%s\n", pubHex)
	fmt.Printf("fingerprint_sha256=%s\n", fpFull)
	fmt.Printf("fingerprint_short=%s\n", fpFull[:16])
	fmt.Println()
	fmt.Println("# Zeile fuer internal/releaseverify/release_ed25519.pub:")
	fmt.Println(pubHex)
	fmt.Println()
	fmt.Printf("# Secret setzen (Seed-Datei, Inhalt nie loggen):\n")
	fmt.Printf("gh secret set RELEASE_SIGNING_KEY < %s\n", path)
}

func writeSeedFile(path string, seed []byte) error {
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("seed: erwarte %d Bytes", ed25519.SeedSize)
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Chmod(path, 0o600)
}

func readSeedFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	line := ""
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		line = l
		break
	}
	raw, err := hex.DecodeString(line)
	if err != nil {
		return nil, fmt.Errorf("seed hex: %w", err)
	}
	if len(raw) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed: erwarte %d Bytes, got %d", ed25519.SeedSize, len(raw))
	}
	return raw, nil
}
