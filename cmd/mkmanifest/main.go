// Command mkmanifest builds downloads/manifest.json for agent releases.
//
// Usage:
//
//	mkmanifest -version 1.2.3 -dir dist
//	mkmanifest -version 1.2.3 -dir dist -min-version 1.0.0 -timestamp 2026-11-22T12:00:00Z
//
// The manifest lists platform binaries with SHA-256, size, and downgrade floor.
// Signing is done separately (Sigstore / cosign); this tool only writes JSON.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const manifestName = "manifest.json"

// Identity expectations for Sigstore keyless verification (documented here for
// workflow authors; the client constants live only in internal/releaseverify/identity.go):
//
//      OIDC issuer:  https://token.actions.githubusercontent.com
//      Subject SAN:  https://github.com/thelad-dev/ssh-sync/.github/workflows/release.yml@refs/tags/v<semver>
//      Subject regex: ^https://github\.com/thelad-dev/ssh-sync/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$
//      sourceRepositoryURI:      https://github.com/thelad-dev/ssh-sync
//      sourceRepositoryOwnerURI: https://github.com/thelad-dev

var binaryNameRE = regexp.MustCompile(`^ssh-sync-(linux|darwin|windows)-(amd64|arm64)(\.exe)?$`)

type artifact struct {
	Platform string `json:"platform"`
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

type manifest struct {
	Version    string     `json:"version"`
	MinVersion string     `json:"min_version"`
	Timestamp  string     `json:"timestamp"`
	Artifacts  []artifact `json:"artifacts"`
}

func main() {
	dir := flag.String("dir", "dist", "Verzeichnis mit Agent-Binaries")
	version := flag.String("version", "", "Release-Version (semver ohne v-Prefix)")
	minVersion := flag.String("min-version", "", "Mindestversion fuer Downgrade-Schutz (default: version)")
	ts := flag.String("timestamp", "", "RFC3339-Zeitstempel (default: jetzt UTC)")
	flag.Parse()

	if strings.TrimSpace(*version) == "" {
		fmt.Fprintln(os.Stderr, "usage: mkmanifest -version 1.2.3 [-dir dist] [-min-version 1.0.0] [-timestamp RFC3339]")
		os.Exit(2)
	}
	if err := writeManifest(*dir, *version, *minVersion, *ts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func writeManifest(dir, version, minVersion, timestamp string) error {
	version = strings.TrimSpace(version)
	min := strings.TrimSpace(minVersion)
	if min == "" {
		min = version
	}
	stamp := strings.TrimSpace(timestamp)
	if stamp == "" {
		stamp = time.Now().UTC().Format(time.RFC3339)
	} else if _, err := time.Parse(time.RFC3339, stamp); err != nil {
		return fmt.Errorf("timestamp: %w", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	var arts []artifact
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !binaryNameRE.MatchString(name) {
			continue
		}
		path := filepath.Join(dir, name)
		info, err := e.Info()
		if err != nil {
			return err
		}
		sum, err := fileSHA256(path)
		if err != nil {
			return err
		}
		platform, err := platformFromFilename(name)
		if err != nil {
			return err
		}
		arts = append(arts, artifact{
			Platform: platform,
			Filename: name,
			SHA256:   sum,
			Size:     info.Size(),
		})
	}
	if len(arts) == 0 {
		return fmt.Errorf("keine Agent-Binaries in %s", dir)
	}
	sort.Slice(arts, func(i, j int) bool {
		if arts[i].Platform != arts[j].Platform {
			return arts[i].Platform < arts[j].Platform
		}
		return arts[i].Filename < arts[j].Filename
	})

	m := manifest{
		Version:    version,
		MinVersion: min,
		Timestamp:  stamp,
		Artifacts:  arts,
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	out := filepath.Join(dir, manifestName)
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		return err
	}
	fmt.Printf("geschrieben: %s (version %s, %d artifacts)\n", manifestName, m.Version, len(arts))
	return nil
}

func platformFromFilename(name string) (string, error) {
	m := binaryNameRE.FindStringSubmatch(name)
	if m == nil {
		return "", fmt.Errorf("kein Plattform-Binary: %s", name)
	}
	return m[1] + "-" + m[2], nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
