package releaseverify

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// CheckServerURL enforces HTTPS unless insecure is set or the host is loopback.
func CheckServerURL(raw string, insecure bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("Server-URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("Server-URL unvollständig")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if insecure || isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("http:// nur mit --insecure oder gegen Loopback erlaubt")
	default:
		return fmt.Errorf("unbekanntes URL-Schema %q", u.Scheme)
	}
}

func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// SanitizeInstallBaseURL validates Host / forwarded proto for install script bases (N3).
func SanitizeInstallBaseURL(scheme, host string) (string, error) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme == "" {
		scheme = "https"
	}
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("ungültiges Schema")
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("Host fehlt")
	}
	// Reject shell metacharacters and whitespace (N3).
	if strings.ContainsAny(host, "$`\\\"'\n\r\t ;|&<>(){}!") {
		return "", fmt.Errorf("Host enthält unerlaubte Zeichen")
	}
	// Hostname or host:port only.
	h := host
	if strings.HasPrefix(h, "[") {
		// IPv6 [addr]:port
		end := strings.IndexByte(h, ']')
		if end < 0 {
			return "", fmt.Errorf("ungültiger Host")
		}
	} else if i := strings.LastIndexByte(h, ':'); i >= 0 {
		port := h[i+1:]
		for _, c := range port {
			if c < '0' || c > '9' {
				return "", fmt.Errorf("ungültiger Port")
			}
		}
		h = h[:i]
	}
	if h == "" {
		return "", fmt.Errorf("Host fehlt")
	}
	return scheme + "://" + host, nil
}
