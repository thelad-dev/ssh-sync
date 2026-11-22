package importlocal

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/thelad-dev/ssh-sync/internal/sshconfig"
)

type Identity struct {
	ID         string
	Name       string
	PrivateKey []byte
	PublicKey  string
	Path       string
}

type Host struct {
	ID             string
	Alias          string
	HostName       string
	User           string
	Port           int
	IdentityPath   string
	ProxyJump      string
	IdentitiesOnly bool
}

type Bundle struct {
	Identities []Identity
	Hosts      []Host
}

// LoadSSHDir liest ~/.ssh/config und referenzierte Private Keys.
func LoadSSHDir(sshDir string) (*Bundle, error) {
	configPath := filepath.Join(sshDir, "config")
	data, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("config lesen: %w", err)
	}

	parsed := sshconfig.Parse(string(data))
	identityPaths := map[string]bool{}
	for _, h := range parsed {
		if h.IdentityFile != "" {
			identityPaths[resolvePath(sshDir, h.IdentityFile)] = true
		}
	}
	for _, name := range []string{"id_ed25519", "id_rsa", "id_ecdsa"} {
		p := filepath.Join(sshDir, name)
		if isPrivateKeyFile(p) {
			identityPaths[p] = true
		}
	}

	var identities []Identity
	pathToID := map[string]string{}
	for p := range identityPaths {
		priv, err := os.ReadFile(p)
		if err != nil || !isPrivateKey(priv) {
			continue
		}
		name := sshconfig.IdentityNameFromPath(p)
		id, err := newID()
		if err != nil {
			return nil, err
		}
		pub := readPublicKey(p)
		if pub == "" {
			pub = derivePublicKeyFromPrivate(priv)
		} else if canon, ok := sshconfig.CanonicalPublicKey(pub); ok {
			pub = canon
		}
		identities = append(identities, Identity{
			ID:         id,
			Name:       name,
			PrivateKey: priv,
			PublicKey:  pub,
			Path:       p,
		})
		pathToID[p] = id
	}

	var hosts []Host
	for _, h := range parsed {
		id, err := newID()
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, Host{
			ID:             id,
			Alias:          h.Alias,
			HostName:       h.HostName,
			User:           h.User,
			Port:           h.Port,
			IdentityPath:   resolvePath(sshDir, h.IdentityFile),
			ProxyJump:      h.ProxyJump,
			IdentitiesOnly: h.IdentitiesOnly,
		})
	}

	return &Bundle{Identities: identities, Hosts: hosts}, nil
}

func (b *Bundle) IdentityIDForPath(sshDir, identityPath string) *string {
	if identityPath == "" {
		return nil
	}
	resolved := resolvePath(sshDir, identityPath)
	for _, id := range b.Identities {
		if id.Path == resolved {
			v := id.ID
			return &v
		}
	}
	for _, id := range b.Identities {
		for _, cand := range sshconfig.IdentityNameCandidates(resolved) {
			if id.Name == cand || sshconfig.NormalizeIdentityName(id.Name) == cand {
				v := id.ID
				return &v
			}
		}
	}
	return nil
}

func resolvePath(sshDir, p string) string {
	p = strings.Trim(p, "\"")
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "$HOME/") {
		rest := strings.TrimPrefix(strings.TrimPrefix(p, "~/"), "$HOME/")
		return filepath.Join(sshDir, rest)
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(sshDir, p)
}

func isPrivateKeyFile(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return isPrivateKey(data)
}

func isPrivateKey(data []byte) bool {
	return strings.Contains(string(data), "PRIVATE KEY")
}

func readPublicKey(privatePath string) string {
	for _, pubPath := range publicKeyPaths(privatePath) {
		data, err := os.ReadFile(pubPath)
		if err != nil {
			continue
		}
		text := strings.TrimSpace(string(data))
		if text != "" {
			return text
		}
	}
	return ""
}

func publicKeyPaths(privatePath string) []string {
	dir := filepath.Dir(privatePath)
	base := filepath.Base(privatePath)
	var paths []string
	seen := map[string]bool{}
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	add(privatePath + ".pub")
	if strings.HasSuffix(base, ".pem") {
		stem := strings.TrimSuffix(base, ".pem")
		add(filepath.Join(dir, stem+".pub"))
	}
	return paths
}

func derivePublicKeyFromPrivate(data []byte) string {
	if signer, err := ssh.ParsePrivateKey(data); err == nil {
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	}
	if key, err := ssh.ParseRawPrivateKey(data); err == nil {
		pub, err := ssh.NewPublicKey(key)
		if err == nil {
			return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
		}
	}
	return ""
}

// NewID erzeugt eine zufällige Hex-ID für Server-Einträge.
func NewID() (string, error) {
	return newID()
}

func newID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
