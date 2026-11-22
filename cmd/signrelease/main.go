// Command signrelease builds and signs downloads/manifest.json for agent releases.
//
// Usage:
//
//	signrelease -version 1.2.3 -dir downloads -key release.ed25519.priv
//
// The private key file contains 64 hex characters (ed25519 seed||pub or pure
// 64-byte private key). Never commit the private key.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/thelad-dev/ssh-sync/internal/releaseverify"
)

func main() {
	dir := flag.String("dir", "downloads", "Verzeichnis mit Agent-Binaries")
	version := flag.String("version", "", "Release-Version (semver-like)")
	keyPath := flag.String("key", "", "Pfad zum Private-Key (64 Hex-Zeichen, eine Zeile)")
	flag.Parse()
	if strings.TrimSpace(*version) == "" || strings.TrimSpace(*keyPath) == "" {
		fmt.Fprintln(os.Stderr, "usage: signrelease -version 1.2.3 -key release.ed25519.priv [-dir downloads]")
		os.Exit(2)
	}
	priv, err := loadPrivateKey(*keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	entries, err := os.ReadDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	assets := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == releaseverify.ManifestName || name == releaseverify.SigName || name == ".gitkeep" {
			continue
		}
		hash, err := releaseverify.FileSHA256(filepath.Join(*dir, name))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		assets[name] = hash
	}
	if len(assets) == 0 {
		fmt.Fprintln(os.Stderr, "keine Assets in", *dir)
		os.Exit(1)
	}
	m := releaseverify.Manifest{Version: *version, Assets: assets}
	canon, sig, err := releaseverify.SignManifest(m, priv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(*dir, releaseverify.ManifestName), canon, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(*dir, releaseverify.SigName), sig, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("geschrieben: %s und %s (version %s, %d assets)\n",
		releaseverify.ManifestName, releaseverify.SigName, *version, len(assets))
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
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
		return nil, fmt.Errorf("key hex: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("key: erwarte 32 oder 64 Bytes, got %d", len(raw))
	}
}
