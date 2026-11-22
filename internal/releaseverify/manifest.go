package releaseverify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

const (
	ManifestName = "manifest.json"
	SigName      = "manifest.sig"
)

// Manifest describes signed release assets.
type Manifest struct {
	Version string            `json:"version"`
	Assets  map[string]string `json:"assets"` // name -> sha256 hex
}

// CanonicalJSON returns a stable JSON encoding for signing.
func (m Manifest) CanonicalJSON() ([]byte, error) {
	if m.Assets == nil {
		m.Assets = map[string]string{}
	}
	names := make([]string, 0, len(m.Assets))
	for k := range m.Assets {
		names = append(names, k)
	}
	sort.Strings(names)
	type pair struct {
		Name string `json:"name"`
		Hash string `json:"sha256"`
	}
	// Stable object: version + sorted assets object via json.Marshal on ordered struct.
	ordered := struct {
		Version string            `json:"version"`
		Assets  map[string]string `json:"assets"`
	}{
		Version: m.Version,
		Assets:  make(map[string]string, len(names)),
	}
	for _, n := range names {
		ordered.Assets[n] = strings.ToLower(strings.TrimSpace(m.Assets[n]))
	}
	// encoding/json maps are sorted by key since Go 1.x deterministic for maps? Actually Go randomizes map order.
	// Build manually for stability.
	var b strings.Builder
	b.WriteString(`{"assets":{`)
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		kj, err := json.Marshal(n)
		if err != nil {
			return nil, err
		}
		vj, err := json.Marshal(ordered.Assets[n])
		if err != nil {
			return nil, err
		}
		b.Write(kj)
		b.WriteByte(':')
		b.Write(vj)
	}
	b.WriteString(`},"version":`)
	vj, err := json.Marshal(m.Version)
	if err != nil {
		return nil, err
	}
	b.Write(vj)
	b.WriteByte('}')
	return []byte(b.String()), nil
}

// ParseManifest parses manifest JSON (any key order).
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
	for name, hash := range m.Assets {
		h := strings.ToLower(strings.TrimSpace(hash))
		if len(h) != 64 {
			return nil, fmt.Errorf("manifest: ungültiger Hash für %s", name)
		}
		if _, err := hex.DecodeString(h); err != nil {
			return nil, fmt.Errorf("manifest: ungültiger Hash für %s", name)
		}
		m.Assets[name] = h
	}
	return &m, nil
}

// SignManifest signs the canonical manifest with the private key.
func SignManifest(m Manifest, privateKey ed25519.PrivateKey) ([]byte, []byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("ungültiger Private Key")
	}
	canon, err := m.CanonicalJSON()
	if err != nil {
		return nil, nil, err
	}
	sig := ed25519.Sign(privateKey, canon)
	return canon, sig, nil
}

// VerifySignature checks sig over raw manifest bytes using the embedded/public key.
// It re-parses and re-canonicalizes so key order in the file does not matter.
func VerifySignature(manifestBytes, sig []byte) (*Manifest, error) {
	if len(PublicKey) != 32 {
		return nil, fmt.Errorf("kein Release-Public-Key eingebettet (siehe docs/release-signing.md)")
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("Signatur hat ungültige Länge (%d)", len(sig))
	}
	m, err := ParseManifest(manifestBytes)
	if err != nil {
		return nil, err
	}
	canon, err := m.CanonicalJSON()
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(PublicKey, canon, sig) {
		return nil, fmt.Errorf("Signatur ungültig")
	}
	return m, nil
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
	want, ok := m.Assets[assetName]
	if !ok {
		return fmt.Errorf("Asset %q fehlt im Manifest", assetName)
	}
	got, err := FileSHA256(path)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("SHA-256 stimmt nicht: got %s want %s", got, want)
	}
	return nil
}
