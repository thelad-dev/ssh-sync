package sshconfig

import "testing"

func TestNormalizeIdentityName(t *testing.T) {
	cases := map[string]string{
		"id_rsa.pem":           "id_rsa",
		"~/.ssh/id_rsa.pem":    "id_rsa",
		"id_ed25519":           "id_ed25519",
		"id_rsa_pem_id":        "id_rsa",
		"myserver_id":          "myserver",
		"deploy.key":           "deploy",
		"id_rsa.pem.pub":       "id_rsa",
	}
	for in, want := range cases {
		if got := NormalizeIdentityName(in); got != want {
			t.Errorf("NormalizeIdentityName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestKeyFileBasename(t *testing.T) {
	if got := KeyFileBasename("id_rsa.pem"); got != "id_rsa" {
		t.Fatalf("got %q", got)
	}
}

func TestIdentityNameCandidates(t *testing.T) {
	c := IdentityNameCandidates("~/.ssh/id_rsa.pem")
	if len(c) == 0 || c[0] != "id_rsa" {
		t.Fatalf("candidates: %v", c)
	}
}
