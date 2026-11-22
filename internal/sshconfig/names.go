package sshconfig

import (
	"path/filepath"
	"strings"
)

// NormalizeIdentityName wandelt Key-Dateinamen in einen stabilen Identity-Namen um.
// id_rsa.pem → id_rsa, ~/.ssh/foo_id → foo
func NormalizeIdentityName(pathOrName string) string {
	base := filepath.Base(strings.TrimSpace(pathOrName))
	base = strings.TrimSuffix(base, ".pub")
	for _, ext := range []string{".pem", ".key", ".ppk"} {
		if strings.HasSuffix(base, ext) {
			base = strings.TrimSuffix(base, ext)
			break
		}
	}
	if strings.HasSuffix(base, "_id") {
		base = strings.TrimSuffix(base, "_id")
	}
	// Legacy: früher id_rsa.pem → Dateiname id_rsa_pem_id
	if strings.HasSuffix(base, "_pem") {
		base = strings.TrimSuffix(base, "_pem")
	}
	base = strings.TrimSpace(base)
	if base == "" || base == "." {
		return "imported"
	}
	return base
}

// KeyFileBasename Dateiname unter ~/.ssh für einen synchronisierten Private Key.
func KeyFileBasename(identityName string) string {
	return sanitizeFilename(NormalizeIdentityName(identityName))
}

// IdentityNameCandidates liefert mögliche Namen zum Abgleich eines IdentityFile-Pfads.
func IdentityNameCandidates(identityFile string) []string {
	if identityFile == "" {
		return nil
	}
	base := filepath.Base(strings.Trim(identityFile, "\"'"))
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	add(NormalizeIdentityName(base))
	add(strings.TrimSuffix(base, ".pub"))
	add(base)
	if strings.HasSuffix(base, "_id") {
		add(strings.TrimSuffix(base, "_id"))
	}
	return out
}
