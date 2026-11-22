package sshconfig

import (
	"path/filepath"
	"strconv"
	"strings"
)

// ParsedHost ist ein aus einer ssh config gelesener Host-Block.
type ParsedHost struct {
	Alias          string
	HostName       string
	User           string
	Port           int
	IdentityFile   string
	ProxyJump      string
	IdentitiesOnly bool
}

// Parse liest Host-Blöcke aus einer ssh config. Wildcard-Aliase und der managed Block werden übersprungen.
func Parse(content string) []ParsedHost {
	content = stripManagedBlock(content)
	var hosts []ParsedHost
	var current *ParsedHost

	flush := func() {
		if current == nil || current.Alias == "" {
			return
		}
		if current.HostName == "" {
			current.HostName = current.Alias
		}
		if current.Port == 0 {
			current.Port = 22
		}
		hosts = append(hosts, *current)
		current = nil
	}

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := splitDirective(line)
		if !ok {
			continue
		}
		lower := strings.ToLower(key)
		switch lower {
		case "host":
			flush()
			alias := strings.Fields(val)[0]
			if alias == "*" || strings.ContainsAny(alias, "*?") {
				current = nil
				continue
			}
			current = &ParsedHost{Alias: alias, Port: 22}
		case "hostname":
			if current != nil {
				current.HostName = val
			}
		case "user":
			if current != nil {
				current.User = val
			}
		case "port":
			if current != nil {
				if p, err := strconv.Atoi(val); err == nil {
					current.Port = p
				}
			}
		case "identityfile":
			if current != nil {
				current.IdentityFile = expandHome(val)
			}
		case "proxyjump":
			if current != nil {
				current.ProxyJump = val
			}
		case "identitiesonly":
			if current != nil {
				current.IdentitiesOnly = parseBoolDirective(val)
			}
		}
	}
	flush()
	return hosts
}

// StripManagedBlock entfernt den verwalteten Block aus einer ssh config.
func StripManagedBlock(content string) string {
	return stripManagedBlock(content)
}

func stripManagedBlock(content string) string {
	begin := strings.Index(content, managedBegin)
	if begin < 0 {
		return content
	}
	end := strings.Index(content, managedEnd)
	if end < 0 || end < begin {
		return content[:begin]
	}
	end += len(managedEnd)
	rest := content[end:]
	if strings.HasPrefix(rest, "\r\n") {
		rest = rest[2:]
	} else if strings.HasPrefix(rest, "\n") {
		rest = rest[1:]
	}
	return content[:begin] + rest
}

// ManagedIdentityFiles listet IdentityFile-Pfade aus dem managed Block.
func ManagedIdentityFiles(content string) []string {
	begin := strings.Index(content, managedBegin)
	if begin < 0 {
		return nil
	}
	end := strings.Index(content, managedEnd)
	if end < 0 || end < begin {
		return nil
	}
	block := content[begin : end+len(managedEnd)]
	var files []string
	for _, line := range strings.Split(block, "\n") {
		key, val, ok := splitDirective(strings.TrimSpace(line))
		if ok && strings.EqualFold(key, "IdentityFile") && val != "" {
			files = append(files, val)
		}
	}
	return files
}

func splitDirective(line string) (string, string, bool) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", "", false
	}
	key := parts[0]
	val := strings.TrimSpace(line[len(parts[0]):])
	val = strings.Trim(val, "\"")
	return key, val, true
}

func expandHome(path string) string {
	path = strings.Trim(path, "\"")
	if strings.HasPrefix(path, "~/") {
		return filepath.Join("$HOME", path[2:])
	}
	return path
}

func parseBoolDirective(val string) bool {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "yes", "true", "1", "on":
		return true
	default:
		return false
	}
}

// IdentityNameFromPath leitet einen Anzeigenamen aus einem Key-Pfad ab.
func IdentityNameFromPath(path string) string {
	return NormalizeIdentityName(path)
}
