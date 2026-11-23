package sshconfig

import "testing"

func TestHostPatternsMatchNegationAndMulti(t *testing.T) {
	cases := []struct {
		pats []string
		name string
		want bool
	}{
		{[]string{"elitedesk"}, "elitedesk", true},
		{[]string{"elitedesk", "github.com"}, "github.com", true},
		{[]string{"elitedesk", "github.com"}, "dock", false},
		{[]string{"elite*"}, "elitedesk", true},
		{[]string{"dock", "pxmx", "!dock"}, "dock", false},
		{[]string{"dock", "pxmx", "!dock"}, "pxmx", true},
		{[]string{"*", "!negated"}, "negated", false},
		{[]string{"*", "!negated"}, "other", true},
		{[]string{"!negated", "*"}, "negated", false},
		{[]string{"*"}, "anything", true},
	}
	for _, tc := range cases {
		got := hostPatternsMatch(tc.pats, tc.name)
		if got != tc.want {
			t.Fatalf("patterns=%v name=%q: got %v want %v", tc.pats, tc.name, got, tc.want)
		}
	}
}

func TestIsCatchAllStar(t *testing.T) {
	if !isCatchAllStar([]string{"*"}) {
		t.Fatal("Host * muss Catch-All sein")
	}
	if !isCatchAllStar([]string{"*", "!local"}) {
		t.Fatal("* mit Negation bleibt Catch-All fuer Positiv-Muster")
	}
	if isCatchAllStar([]string{"*.lan"}) {
		t.Fatal("*.lan ist kein reines *")
	}
	if isCatchAllStar([]string{"a", "*"}) {
		t.Fatal("zusaetzliches Positiv-Muster ist kein reines *")
	}
}

func TestPolicyForAliasSkipsSpecificKeepsStar(t *testing.T) {
	stanzas := []localHostStanza{
		{patterns: []string{"elitedesk", "github.com"}, hasIdentityFile: true},
		{patterns: []string{"*"}, hasIdentityFile: false},
	}
	if !policyForAlias(stanzas, "elitedesk").skipEntire {
		t.Fatal("elitedesk muss uebersprungen werden")
	}
	pol := policyForAlias(stanzas, "only-server")
	if pol.skipEntire || pol.omitIdentity {
		t.Fatalf("Host * ohne IdentityFile darf only-server nicht aendern: %+v", pol)
	}
}

func TestPolicyForAliasStarWithIdentityOmitsIdentity(t *testing.T) {
	stanzas := []localHostStanza{
		{patterns: []string{"*"}, hasIdentityFile: true},
	}
	pol := policyForAlias(stanzas, "srv")
	if pol.skipEntire {
		t.Fatal("Host * mit IdentityFile darf managed Host nicht komplett streichen")
	}
	if !pol.omitIdentity {
		t.Fatal("IdentityFile muss im managed Host entfallen")
	}
}

func TestPolicyWildcardPatternCountsAsLocal(t *testing.T) {
	stanzas := []localHostStanza{
		{patterns: []string{"elite*"}, hasIdentityFile: true},
	}
	if !policyForAlias(stanzas, "elitedesk").skipEntire {
		t.Fatal("elite* muss elitedesk als lokal zaehlen")
	}
}
