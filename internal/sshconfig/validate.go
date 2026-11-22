package sshconfig

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/thelad-dev/ssh-sync/internal/store"
)

var (
	aliasPattern     = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	hostNamePattern  = regexp.MustCompile(`^[A-Za-z0-9._:%\-\[\]]+$`)
	userPattern      = regexp.MustCompile(`^[A-Za-z0-9._\-]+$`)
	proxyJumpPattern = regexp.MustCompile(`^(?:[A-Za-z0-9._\-]+@)?[A-Za-z0-9._:%\-\[\]]+(?::[0-9]{1,5})?$`)
)

// Extra-Direktiven, die vom Server kommen duerfen.
var allowedExtraDirectives = map[string]bool{
	"serveraliveinterval": true,
	"serveralivecountmax": true,
	"connecttimeout":      true,
	"compression":         true,
	"addkeystoagent":      true,
	"localforward":        true,
	"remoteforward":       true,
	"dynamicforward":      true,
	"forwardagent":        true,
}

var forbiddenExtraDirectives = map[string]bool{
	"proxycommand":         true,
	"localcommand":         true,
	"permitlocalcommand":   true,
	"match":                true,
	"host":                 true,
	"include":              true,
	"knownhostscommand":    true,
	"identityagent":        true,
	"certificatefile":      true,
	"pkcs11provider":       true,
	"securitykeyprovider":  true,
	"userknownhostsfile":   true,
	"stricthostkeychecking": true,
	"identityfile":         true,
	"controlpath":          true,
	"proxyjump":            true,
	"hostname":             true,
	"user":                 true,
	"port":                 true,
	"identitiesonly":       true,
}

// ValidateHostFields prueft Host-Felder gegen Einschleusung und Allowlist.
func ValidateHostFields(alias, hostName, user, proxyJump, extra string) error {
	if err := rejectControlChars("alias", alias); err != nil {
		return err
	}
	if err := rejectControlChars("host_name", hostName); err != nil {
		return err
	}
	if err := rejectControlChars("user", user); err != nil {
		return err
	}
	if err := rejectControlChars("proxy_jump", proxyJump); err != nil {
		return err
	}
	if strings.ContainsRune(extra, 0) {
		return fmt.Errorf("extra enthaelt Steuerzeichen")
	}
	if strings.TrimSpace(alias) == "" || !aliasPattern.MatchString(alias) {
		return fmt.Errorf("alias ungueltig")
	}
	if strings.TrimSpace(hostName) == "" || !hostNamePattern.MatchString(hostName) {
		return fmt.Errorf("host_name ungueltig")
	}
	if user != "" && !userPattern.MatchString(user) {
		return fmt.Errorf("user ungueltig")
	}
	if err := validateProxyJump(proxyJump); err != nil {
		return err
	}
	if _, err := NormalizeExtra(extra); err != nil {
		return err
	}
	return nil
}

// ValidateHost prueft ein Store-Host-Objekt.
func ValidateHost(h store.Host) error {
	return ValidateHostFields(h.Alias, h.HostName, h.User, h.ProxyJump, h.Extra)
}

func validateProxyJump(proxyJump string) error {
	proxyJump = strings.TrimSpace(proxyJump)
	if proxyJump == "" {
		return nil
	}
	for _, part := range strings.Split(proxyJump, ",") {
		part = strings.TrimSpace(part)
		if part == "" || !proxyJumpPattern.MatchString(part) {
			return fmt.Errorf("proxy_jump ungueltig")
		}
		if i := strings.LastIndex(part, ":"); i >= 0 && !strings.Contains(part[i:], "]") {
			port := part[i+1:]
			if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("proxy_jump port ungueltig")
			}
		}
	}
	return nil
}

// NormalizeExtra parst Extra-Zeilen, filtert gegen Allowlist und liefert kanonischen Text.
func NormalizeExtra(extra string) (string, error) {
	extra = strings.TrimSpace(extra)
	if extra == "" {
		return "", nil
	}
	if strings.Contains(extra, managedBegin) || strings.Contains(extra, managedEnd) {
		return "", fmt.Errorf("extra enthaelt managed Marker")
	}
	var out []string
	for _, line := range strings.Split(extra, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := splitDirective(line)
		if !ok {
			return "", fmt.Errorf("extra Zeile ungueltig")
		}
		lower := strings.ToLower(key)
		if forbiddenExtraDirectives[lower] || !allowedExtraDirectives[lower] {
			return "", fmt.Errorf("extra Direktive nicht erlaubt: %s", key)
		}
		if err := rejectControlChars("extra-value", val); err != nil {
			return "", err
		}
		if strings.ContainsAny(val, "\r\n\x00") {
			return "", fmt.Errorf("extra Wert ungueltig")
		}
		if lower == "forwardagent" {
			v := strings.ToLower(strings.TrimSpace(val))
			if v != "no" && v != "false" && v != "0" {
				return "", fmt.Errorf("ForwardAgent nur no erlaubt")
			}
			val = "no"
		}
		out = append(out, key+" "+val)
	}
	return strings.Join(out, "\n"), nil
}

func rejectControlChars(field, value string) error {
	if strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("%s enthaelt Steuerzeichen", field)
	}
	return nil
}
