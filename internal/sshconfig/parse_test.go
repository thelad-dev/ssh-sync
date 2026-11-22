package sshconfig

import "testing"

func TestParseSSHConfig(t *testing.T) {
	input := `
Host myserver
  HostName 10.0.0.5
  User admin
  Port 2222
  IdentityFile ~/.ssh/myserver_id

Host *
  ForwardAgent yes
`
	hosts := Parse(input)
	if len(hosts) != 1 {
		t.Fatalf("erwartet 1 Host, got %d", len(hosts))
	}
	h := hosts[0]
	if h.Alias != "myserver" || h.HostName != "10.0.0.5" || h.User != "admin" || h.Port != 2222 {
		t.Fatalf("unexpected host: %+v", h)
	}
}

func TestParseSkipsManagedBlock(t *testing.T) {
	input := managedBegin + "\nHost managed\n  HostName x\n" + managedEnd + "\nHost real\n  HostName y\n"
	hosts := Parse(input)
	if len(hosts) != 1 || hosts[0].Alias != "real" {
		t.Fatalf("managed block nicht übersprungen: %+v", hosts)
	}
}
