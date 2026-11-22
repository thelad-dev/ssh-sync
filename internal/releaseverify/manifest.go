package releaseverify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const (
	ManifestName = "manifest.json"
	BundleName   = "manifest.json.sigstore.json"
)

// Manifest describes signed release assets (Sigstore-signed as raw JSON bytes).
type Manifest struct {
	Version    string          `json:"version"`
	MinVersion string          `json:"min_version,omitempty"`
	Timestamp  string          `json:"timestamp,omitempty"`
	Assets     []ManifestAsset `json:"assets"`
}

// ManifestAsset is one platform binary listed in the release manifest.
type ManifestAsset struct {
	Platform string `json:"platform"`
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

// ParseManifest parses manifest JSON.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if strings.TrimSpace(m.Version) == "" {
		return nil, fmt.Errorf("manifest: version fehlt")
	}
	if len(m.Assets) == 0 {
		return nil, fmt.Errorf("manifest: assets fehlen")
	}
	for i := range m.Assets {
		a := &m.Assets[i]
		a.Filename = strings.TrimSpace(a.Filename)
		if a.Filename == "" {
			return nil, fmt.Errorf("manifest: filename fehlt")
		}
		h := strings.ToLower(strings.TrimSpace(a.SHA256))
		if len(h) != 64 {
			return nil, fmt.Errorf("manifest: ungueltiger Hash fuer %s", a.Filename)
		}
		if _, err := hex.DecodeString(h); err != nil {
			return nil, fmt.Errorf("manifest: ungueltiger Hash fuer %s", a.Filename)
		}
		a.SHA256 = h
		if a.Size < 0 {
			return nil, fmt.Errorf("manifest: ungueltige Groesse fuer %s", a.Filename)
		}
	}
	return &m, nil
}

// AssetByFilename returns the asset entry for name.
func (m *Manifest) AssetByFilename(name string) (*ManifestAsset, bool) {
	if m == nil {
		return nil, false
	}
	for i := range m.Assets {
		if m.Assets[i].Filename == name {
			return &m.Assets[i], true
		}
	}
	return nil, false
}

// FileSHA256 returns the hex SHA-256 of path.
func FileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyAssetHash checks the file against the manifest entry.
func VerifyAssetHash(m *Manifest, assetName, path string) error {
	want, ok := m.AssetByFilename(assetName)
	if !ok {
		return fmt.Errorf("Asset %q fehlt im Manifest", assetName)
	}
	got, err := FileSHA256(path)
	if err != nil {
		return err
	}
	if got != want.SHA256 {
		return fmt.Errorf("SHA-256 stimmt nicht: got %s want %s", got, want.SHA256)
	}
	if want.Size > 0 {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if info.Size() != want.Size {
			return fmt.Errorf("Groesse stimmt nicht: got %d want %d", info.Size(), want.Size)
		}
	}
	return nil
}
