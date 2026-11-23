package sshconfig

import (
	"path/filepath"
	"strings"
)

// hostPatternsMatch folgt den OpenSSH-Host-Regeln: ein positiv passendes Muster
// reicht; ein negativ passendes Muster (!pat) verwirft den ganzen Host-Eintrag.
func hostPatternsMatch(patterns []string, name string) bool {
	if len(patterns) == 0 || name == "" {
		return false
	}
	matched := false
	for _, raw := range patterns {
		pat := strings.TrimSpace(raw)
		if pat == "" {
			continue
		}
		neg := false
		if strings.HasPrefix(pat, "!") {
			neg = true
			pat = pat[1:]
		}
		if pat == "" {
			continue
		}
		if openSSHHostPatternMatch(pat, name) {
			if neg {
				return false
			}
			matched = true
		}
	}
	return matched
}

// openSSHHostPatternMatch: * und ? wie OpenSSH/fnmatch auf Hostnamen (ohne '/').
func openSSHHostPatternMatch(pattern, name string) bool {
	if pattern == name {
		return true
	}
	ok, err := filepath.Match(pattern, name)
	return err == nil && ok
}

func isCatchAllStar(patterns []string) bool {
	positives := 0
	for _, raw := range patterns {
		pat := strings.TrimSpace(raw)
		if pat == "" || strings.HasPrefix(pat, "!") {
			continue
		}
		positives++
		if pat != "*" {
			return false
		}
	}
	return positives == 1
}

// localHostStanza ist ein Host-Block ausserhalb des managed Bereichs.
type localHostStanza struct {
	patterns        []string
	hasIdentityFile bool
}

// parseLocalHostStanzas liest Host-Bloecke aus dem lokalen Config-Teil
// (managed Block bereits entfernt). Match-Bloecke werden ignoriert.
func parseLocalHostStanzas(content string) []localHostStanza {
	var out []localHostStanza
	var cur *localHostStanza
	flush := func() {
		if cur == nil || len(cur.patterns) == 0 {
			cur = nil
			return
		}
		out = append(out, *cur)
		cur = nil
	}
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := splitDirective(line)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "host":
			flush()
			pats := strings.Fields(val)
			if len(pats) == 0 {
				cur = nil
				continue
			}
			cur = &localHostStanza{patterns: pats}
		case "match":
			flush()
			cur = nil
		case "identityfile":
			if cur != nil && val != "" {
				cur.hasIdentityFile = true
			}
		}
	}
	flush()
	return out
}

// localHostPolicy entscheidet, ob ein Server-Alias im managed Block fehlen
// oder ohne IdentityFile geschrieben werden soll.
type localHostPolicy struct {
	skipEntire    bool
	omitIdentity  bool
	skippedAlias  string // gesetzt wenn skipEntire
}

func policyForAlias(stanzas []localHostStanza, alias string) localHostPolicy {
	var p localHostPolicy
	starIdentity := false
	for _, s := range stanzas {
		if !hostPatternsMatch(s.patterns, alias) {
			continue
		}
		if isCatchAllStar(s.patterns) {
			if s.hasIdentityFile {
				starIdentity = true
			}
			continue
		}
		p.skipEntire = true
		p.skippedAlias = alias
		return p
	}
	if starIdentity {
		p.omitIdentity = true
	}
	return p
}
