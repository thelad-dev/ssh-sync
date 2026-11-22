package sshconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thelad-dev/ssh-sync/internal/store"
)

func TestValidateHostFieldsRejectsInjection(t *testing.T) {
	cases := []struct {
		name      string
		alias     string
		hostName  string
		user      string
		proxyJump string
		extra     string
	}{
		{"newline hostname", "db", "db.example\nProxyCommand sh -c id", "", "", ""},
		{"proxycommand extra", "db", "db.example", "", "", "ProxyCommand sh -c id"},
		{"match extra", "db", "db.example", "", "", "Match exec touch /tmp/x"},
		{"end marker extra", "db", "db.example", "", "", managedEnd + "\nHost evil"},
		{"wildcard alias", "*", "db.example", "", "", ""},
		{"space alias", "db web", "db.example", "", "", ""},
		{"include extra", "db", "db.example", "", "", "Include /etc/ssh/ssh_config"},
		{"localcommand", "db", "db.example", "", "", "LocalCommand touch /tmp/x"},
		{"bad proxyjump", "db", "db.example", "", "jump; rm -rf /", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateHostFields(tc.alias, tc.hostName, tc.user, tc.proxyJump, tc.extra); err == nil {
				t.Fatalf("erwartete Ablehnung fuer %s", tc.name)
			}
		})
	}
}

func TestValidateHostFieldsAllowsSafeExtra(t *testing.T) {
	err := ValidateHostFields("db", "db.example", "deploy", "bastion.example:22", "ServerAliveInterval 30\nForwardAgent no")
	if err != nil {
		t.Fatal(err)
	}
}

func TestRenderConfigBlockDropsHostileHosts(t *testing.T) {
	id := "id1"
	bundle := &store.SyncBundle{
		Hosts: []store.Host{
			{
				Alias:      "db",
				HostName:   "db.example",
				User:       "deploy",
				Port:       22,
				IdentityID: &id,
				Extra:      "ProxyCommand sh -c 'id > /tmp/pwned'\nPermitLocalCommand yes\nLocalCommand touch /tmp/lc",
			},
			{
				Alias:    "web",
				HostName: "web.example\nProxyCommand sh -c 'echo PWNED'",
				User:     "www",
			},
			{
				Alias:    "ok",
				HostName: "ok.example",
				User:     "me",
				Extra:    "ServerAliveInterval 15",
			},
			{
				Alias: "evil-marker",
				HostName: "evil.example",
				Extra:    managedEnd + "\nHost sneaky\n  IdentityFile /etc/ssl/private/server.key",
			},
		},
	}
	identityFiles := map[string]string{id: "/tmp/id_ed25519"}
	block := renderConfigBlock(bundle, identityFiles)

	if strings.Contains(strings.ToLower(block), "proxycommand") {
		t.Fatalf("ProxyCommand darf nicht geschrieben werden:\n%s", block)
	}
	if strings.Contains(strings.ToLower(block), "localcommand") {
		t.Fatalf("LocalCommand darf nicht geschrieben werden:\n%s", block)
	}
	if strings.Contains(strings.ToLower(block), "match ") {
		t.Fatalf("Match darf nicht geschrieben werden:\n%s", block)
	}
	if strings.Count(block, managedEnd) != 1 {
		t.Fatalf("managed END darf nur einmal vorkommen:\n%s", block)
	}
	if !strings.Contains(block, "Host ok") {
		t.Fatalf("sichere Hosts muessen bleiben:\n%s", block)
	}
	if strings.Contains(block, "Host db") || strings.Contains(block, "Host web") || strings.Contains(block, "Host evil-marker") {
		t.Fatalf("ungueltige Hosts muessen entfallen:\n%s", block)
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config")
	if err := os.WriteFile(configPath, []byte(block), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed := Parse(block)
	for _, h := range parsed {
		if h.Alias == "sneaky" || strings.Contains(h.IdentityFile, "/etc/ssl/private") {
			t.Fatalf("Parse darf keine eingeschleusten Hosts liefern: %+v", h)
		}
	}
}
