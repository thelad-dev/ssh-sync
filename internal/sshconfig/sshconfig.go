package sshconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/thelad-dev/ssh-sync/internal/store"
)

const (
	managedBegin = "# --- BEGIN ssh-sync (managed) ---"
	managedEnd   = "# --- END ssh-sync (managed) ---"
	ManagedBegin = managedBegin
	ManagedEnd   = managedEnd
)

type WriteResult struct {
	ConfigPath string
	KeyPaths   []string
	BackupPath string // gesetzt wenn beim ersten Sync config → config--bak
}

// Apply schreibt Keys und merged den managed Block in die ssh config.
func Apply(sshDir string, bundle *store.SyncBundle, decryptedKeys map[string][]byte) (*WriteResult, error) {
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return nil, err
	}

	identityFiles := map[string]string{}
	var keyPaths []string
	for _, id := range bundle.Identities {
		plain, ok := decryptedKeys[id.ID]
		if !ok {
			return nil, fmt.Errorf("entschlüsselter Key für Identity %q fehlt", id.Name)
		}
		filename := KeyFileBasename(id.Name)
		keyPath := filepath.Join(sshDir, filename)
		if err := writePrivateKey(keyPath, plain); err != nil {
			return nil, err
		}
		identityFiles[id.ID] = keyPath
		keyPaths = append(keyPaths, keyPath)
	}

	block := renderConfigBlock(bundle, identityFiles)
	configPath := filepath.Join(sshDir, "config")
	backupPath, err := mergeConfig(configPath, block)
	if err != nil {
		return nil, err
	}

	return &WriteResult{ConfigPath: configPath, KeyPaths: keyPaths, BackupPath: backupPath}, nil
}

func writePrivateKey(path string, data []byte) error {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return chmodPrivate(path)
}

func chmodPrivate(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	return os.Chmod(path, 0o600)
}

func renderConfigBlock(bundle *store.SyncBundle, identityFiles map[string]string) string {
	hostOrder := orderedHosts(bundle)
	var b strings.Builder
	b.WriteString(managedBegin)
	b.WriteString("\n")
	b.WriteString("# Nicht manuell bearbeiten - wird vom ssh-sync Agent ueberschrieben.\n")
	for _, h := range hostOrder {
		if err := ValidateHost(h); err != nil {
			continue
		}
		extra, err := NormalizeExtra(h.Extra)
		if err != nil {
			continue
		}
		b.WriteString("\nHost ")
		b.WriteString(h.Alias)
		b.WriteString("\n")
		b.WriteString("  HostName ")
		b.WriteString(h.HostName)
		b.WriteString("\n")
		if h.Port != 0 && h.Port != 22 {
			b.WriteString(fmt.Sprintf("  Port %d\n", h.Port))
		}
		if h.User != "" {
			b.WriteString("  User ")
			b.WriteString(h.User)
			b.WriteString("\n")
		}
		if h.IdentityID != nil {
			if p, ok := identityFiles[*h.IdentityID]; ok {
				b.WriteString("  IdentityFile ")
				b.WriteString(filepath.ToSlash(p))
				b.WriteString("\n")
			}
		}
		if h.IdentitiesOnly {
			b.WriteString("  IdentitiesOnly yes\n")
		}
		if h.ProxyJump != "" {
			b.WriteString("  ProxyJump ")
			b.WriteString(h.ProxyJump)
			b.WriteString("\n")
		}
		if extra != "" {
			for _, line := range strings.Split(extra, "\n") {
				b.WriteString("  ")
				b.WriteString(line)
				b.WriteString("\n")
			}
		}
	}
	b.WriteString(managedEnd)
	b.WriteString("\n")
	return b.String()
}

func orderedHosts(bundle *store.SyncBundle) []store.Host {
	hosts := make([]store.Host, len(bundle.Hosts))
	copy(hosts, bundle.Hosts)
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].SortOrder != hosts[j].SortOrder {
			return hosts[i].SortOrder < hosts[j].SortOrder
		}
		return hosts[i].Alias < hosts[j].Alias
	})
	return hosts
}

func configBackupPath(configPath string) string {
	return configPath + "--bak"
}

// mergeConfig schreibt nur den managed Block. Beim ersten Mal mit vorhandener config
// wird diese einmalig nach config--bak gesichert (bestehende Host-Einträge bleiben dort).
func mergeConfig(path, managedBlock string) (backupPath string, err error) {
	var existing string
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
	} else {
		existing = string(data)
	}

	if strings.TrimSpace(existing) != "" {
		bak := configBackupPath(path)
		if _, statErr := os.Stat(bak); os.IsNotExist(statErr) {
			if err := os.WriteFile(bak, []byte(existing), 0o600); err != nil {
				return "", err
			}
			if err := chmodPrivate(bak); err != nil {
				return "", err
			}
			backupPath = bak
		}
	}

	if err := os.WriteFile(path, []byte(managedBlock), 0o600); err != nil {
		return backupPath, err
	}
	return backupPath, chmodPrivate(path)
}

func sanitizeFilename(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "identity"
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('_')
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
