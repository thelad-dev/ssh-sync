package sshconfig

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/keygen"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

func TestMergeConfigBackupAndManagedOnly(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config")
	existing := "Host local\n  HostName localhost\n  User me\n"
	if err := os.WriteFile(configPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	block := managedBegin + "\nHost new\n  HostName new.example\n" + managedEnd + "\n"
	bak, err := mergeConfigForTest(configPath, block)
	if err != nil {
		t.Fatal(err)
	}
	if bak == "" || !strings.Contains(filepath.Base(bak), configBakPrefix) {
		t.Fatalf("backup path: got %q", bak)
	}
	bakData, err := os.ReadFile(bak)
	if err != nil {
		t.Fatal(err)
	}
	if string(bakData) != existing {
		t.Fatalf("backup inhalt falsch:\n%s", bakData)
	}
	got, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(got), "Host local") {
		t.Fatal("Host local muss in config bleiben")
	}
	if !contains(string(got), managedBegin) || !contains(string(got), "Host new") {
		t.Fatalf("managed Block fehlt:\n%s", got)
	}
	if string(got) == block {
		t.Fatal("config darf nicht nur aus dem managed Block bestehen")
	}
}

func TestSpliceManagedBlockAppendsAtEnd(t *testing.T) {
	existing := "Host workstation\n  HostName 192.0.2.10\n  User me\n  IdentityFile /home/me/.ssh/id_ed25519\n\nHost github.com\n  HostName github.com\n  IdentityFile /home/me/.ssh/id_ed25519\n"
	block := managedBegin + "\nHost workstation\n  HostName 192.0.2.10\n  IdentityFile /home/me/.ssh/id_ed25519.ssh-sync\n" + managedEnd + "\n"
	got := spliceManagedBlock(existing, block)
	if !strings.HasPrefix(got, existing) {
		t.Fatalf("lokale Zeilen muessen bytegleich vor dem Block bleiben:\n%s", got)
	}
	beginIdx := strings.Index(got, managedBegin)
	if beginIdx < len(existing) {
		t.Fatalf("Block muss nach den lokalen Zeilen stehen, begin=%d existingLen=%d", beginIdx, len(existing))
	}
	if !strings.Contains(got[len(existing):], managedBegin) {
		t.Fatalf("managed Block fehlt am Ende:\n%s", got)
	}
}

func TestSpliceManagedBlockReplacesInPlace(t *testing.T) {
	prefix := "Host before\n  HostName a.example\n\n"
	oldBlock := managedBegin + "\nHost old\n  HostName old.example\n" + managedEnd + "\n"
	suffix := "\nHost after\n  HostName b.example\n"
	existing := prefix + oldBlock + suffix
	newBlock := managedBegin + "\nHost new\n  HostName new.example\n" + managedEnd + "\n"
	got := spliceManagedBlock(existing, newBlock)
	if !strings.HasPrefix(got, prefix) {
		t.Fatalf("Prefix vor dem Block muss bleiben:\n%s", got)
	}
	if !strings.HasSuffix(got, suffix) && !strings.Contains(got, "Host after") {
		t.Fatalf("Suffix nach dem Block muss bleiben:\n%s", got)
	}
	if contains(got, "Host old") {
		t.Fatal("alter managed Host muss ersetzt sein")
	}
	if !contains(got, "Host new") {
		t.Fatal("neuer managed Host fehlt")
	}
	// Block bleibt in der Mitte: before vor BEGIN, after nach END.
	beforeIdx := strings.Index(got, "Host before")
	beginIdx := strings.Index(got, managedBegin)
	afterIdx := strings.Index(got, "Host after")
	if !(beforeIdx < beginIdx && beginIdx < afterIdx) {
		t.Fatalf("Block muss in der Mitte bleiben: before=%d begin=%d after=%d", beforeIdx, beginIdx, afterIdx)
	}
}

func TestIdentityFileOrderAlternateAfterPrimary(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, "id_ed25519")
	alt := primary + keyConflictSuffix
	if err := os.WriteFile(primary, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	order := identityFileOrder(alt)
	if len(order) != 2 || order[0] != primary || order[1] != alt {
		t.Fatalf("erwartet [primary, alt], got %#v", order)
	}
	orderOnly := identityFileOrder(primary)
	if len(orderOnly) != 1 || orderOnly[0] != primary {
		t.Fatalf("ohne Ausweichdatei nur primary: %#v", orderOnly)
	}
	missingPrimary := filepath.Join(dir, "missing") + keyConflictSuffix
	orderMissing := identityFileOrder(missingPrimary)
	if len(orderMissing) != 1 || orderMissing[0] != missingPrimary {
		t.Fatalf("ohne lokale Datei nur Ausweichdatei: %#v", orderMissing)
	}
}

func TestMergeConfigPreservesLocalAndReplacesBlock(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config")
	existing := managedBegin + "\nHost old\n  HostName old.example\n" + managedEnd + "\n\nHost local\n  HostName localhost\n"
	if err := os.WriteFile(configPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	block := managedBegin + "\nHost new\n  HostName new.example\n" + managedEnd + "\n"
	if _, err := mergeConfigForTest(configPath, block); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	if contains(s, "Host old") {
		t.Fatal("alter managed Host muss ersetzt sein")
	}
	if !contains(s, "Host new") {
		t.Fatal("neuer managed Host fehlt")
	}
	if !contains(s, "Host local") {
		t.Fatal("lokaler Host local muss bleiben")
	}
}

func TestMergeConfigBackupOnEachChange(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config")
	if err := os.WriteFile(configPath, []byte("Host a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	block1 := managedBegin + "\nHost one\n" + managedEnd + "\n"
	bak1, err := mergeConfigForTest(configPath, block1)
	if err != nil {
		t.Fatal(err)
	}
	if bak1 == "" {
		t.Fatal("erste Aenderung braucht Backup")
	}
	time.Sleep(1100 * time.Millisecond) // UTC-Sekundenstempel
	block2 := managedBegin + "\nHost two\n" + managedEnd + "\n"
	bak2, err := mergeConfigForTest(configPath, block2)
	if err != nil {
		t.Fatal(err)
	}
	if bak2 == "" || bak2 == bak1 {
		t.Fatalf("zweite Aenderung braucht neues Backup: %q vs %q", bak2, bak1)
	}
	entries, _ := os.ReadDir(dir)
	var baks int
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), configBakPrefix) {
			baks++
		}
	}
	if baks < 2 {
		t.Fatalf("erwartet >=2 Backups, got %d", baks)
	}
}

func TestMergeConfigLeavesLegacyBakAlone(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config")
	legacy := configPath + "--bak"
	if err := os.WriteFile(configPath, []byte("Host cur\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte("Host original-backup\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	block := managedBegin + "\n" + managedEnd + "\n"
	if _, err := mergeConfigForTest(configPath, block); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(legacy)
	if string(got) != "Host original-backup\n" {
		t.Fatal("bestehendes config--bak darf nicht ueberschrieben werden")
	}
}

func TestApplyPrivateKeyConflictUsesAlternate(t *testing.T) {
	dir := t.TempDir()
	local, err := keygen.Generate(keygen.TypeEd25519, "local")
	if err != nil {
		t.Fatal(err)
	}
	server, err := keygen.Generate(keygen.TypeEd25519, "server")
	if err != nil {
		t.Fatal(err)
	}
	primary := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(primary, local.PrivatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(primary+".pub", []byte(local.PublicLine), 0o644); err != nil {
		t.Fatal(err)
	}
	localFP, _ := PrivateKeyFingerprint(local.PrivatePEM)
	serverFP, _ := PrivateKeyFingerprint(server.PrivatePEM)

	id := "i1"
	bundle := &store.SyncBundle{
		Identities: []store.Identity{{ID: id, Name: "id_ed25519"}},
		Hosts:      []store.Host{{ID: "h1", Alias: "srv", HostName: "example", IdentityID: &id}},
	}
	// Managed Block schon da, damit kein NeedsConfirm-DryRun greift.
	existing := managedBegin + "\n" + managedEnd + "\nHost local\n  HostName localhost\n"
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Apply(dir, bundle, map[string][]byte{id: server.PrivatePEM}, ApplyOptions{AllowFirstWrite: true})
	if err != nil {
		t.Fatal(err)
	}
	gotPrimary, _ := os.ReadFile(primary)
	if PrivateKeyMustFP(t, gotPrimary) != localFP {
		t.Fatal("lokaler Private Key wurde ueberschrieben")
	}
	alt := primary + keyConflictSuffix
	gotAlt, err := os.ReadFile(alt)
	if err != nil {
		t.Fatal(err)
	}
	if PrivateKeyMustFP(t, gotAlt) != serverFP {
		t.Fatal("Ausweichdatei hat falschen Fingerabdruck")
	}
	cfg, _ := os.ReadFile(filepath.Join(dir, "config"))
	cfgStr := string(cfg)
	if !contains(cfgStr, "Host local") {
		t.Fatal("Host local muss bleiben")
	}
	if !contains(cfgStr, filepath.ToSlash(alt)) && !contains(cfgStr, alt) {
		t.Fatalf("IdentityFile sollte auf Ausweichdatei zeigen:\n%s", cfg)
	}
	primIF := "IdentityFile " + filepath.ToSlash(primary)
	altIF := "IdentityFile " + filepath.ToSlash(alt)
	primIdx := strings.Index(cfgStr, primIF)
	altIdx := strings.Index(cfgStr, altIF)
	if primIdx < 0 || altIdx < 0 || primIdx > altIdx {
		t.Fatalf("lokale Datei muss vor Ausweichdatei stehen:\n%s", cfg)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("erwartet Warnung bei Kollision")
	}
}

func TestApplyPreservesLocalSSHEffectiveOrder(t *testing.T) {
	dir := t.TempDir()
	local, err := keygen.Generate(keygen.TypeEd25519, "local")
	if err != nil {
		t.Fatal(err)
	}
	server, err := keygen.Generate(keygen.TypeEd25519, "server")
	if err != nil {
		t.Fatal(err)
	}
	primary := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(primary, local.PrivatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	existing := "" +
		"Host workstation\n" +
		"  HostName 192.0.2.20\n" +
		"  User me\n" +
		"  Port 22\n" +
		"  IdentityFile " + filepath.ToSlash(primary) + "\n" +
		"\n" +
		"Host github.com\n" +
		"  HostName github.com\n" +
		"  User git\n" +
		"  IdentityFile " + filepath.ToSlash(primary) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	id := "i1"
	bundle := &store.SyncBundle{
		Identities: []store.Identity{{ID: id, Name: "id_ed25519"}},
		Hosts: []store.Host{
			{ID: "h1", Alias: "workstation", HostName: "192.0.2.20", User: "me", IdentityID: &id},
			{ID: "h2", Alias: "github.com", HostName: "github.com", User: "git", IdentityID: &id},
			{ID: "h3", Alias: "only-managed", HostName: "192.0.2.99", User: "sync", IdentityID: &id},
		},
	}
	beforeEff := map[string]sshEffective{}
	for _, alias := range []string{"workstation", "github.com"} {
		beforeEff[alias] = parseSSHEffective(existing, alias)
	}
	if _, err := Apply(dir, bundle, map[string][]byte{id: server.PrivatePEM}, ApplyOptions{AllowFirstWrite: true}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	gotStr := string(got)
	if !strings.HasPrefix(gotStr, existing) {
		t.Fatalf("lokale Config muss bytegleich vor dem Block bleiben:\n%s", gotStr)
	}
	alt := primary + keyConflictSuffix
	for _, alias := range []string{"workstation", "github.com"} {
		after := parseSSHEffective(gotStr, alias)
		before := beforeEff[alias]
		if after.HostName != before.HostName || after.User != before.User || after.Port != before.Port {
			t.Fatalf("%s: hostname/user/port geaendert: before=%+v after=%+v", alias, before, after)
		}
		if len(after.IdentityFiles) != len(before.IdentityFiles) {
			t.Fatalf("%s: IdentityFile-Menge geaendert: before=%v after=%v", alias, before.IdentityFiles, after.IdentityFiles)
		}
		for i := range before.IdentityFiles {
			if after.IdentityFiles[i] != before.IdentityFiles[i] {
				t.Fatalf("%s: IdentityFile-Reihenfolge geaendert: before=%v after=%v", alias, before.IdentityFiles, after.IdentityFiles)
			}
		}
		if strings.Contains(gotStr[strings.Index(gotStr, managedBegin):], "Host "+alias+"\n") {
			t.Fatalf("%s darf nicht im managed Block stehen", alias)
		}
	}
	only := parseSSHEffective(gotStr, "only-managed")
	if only.HostName != "192.0.2.99" || only.User != "sync" {
		t.Fatalf("only-managed falsch: %+v", only)
	}
	if len(only.IdentityFiles) < 2 || only.IdentityFiles[0] != filepath.ToSlash(primary) || only.IdentityFiles[1] != filepath.ToSlash(alt) {
		t.Fatalf("only-managed IdentityFile-Reihenfolge: %v", only.IdentityFiles)
	}
}

func TestApplySameKeyLeavesFile(t *testing.T) {
	dir := t.TempDir()
	kp, err := keygen.Generate(keygen.TypeEd25519, "same")
	if err != nil {
		t.Fatal(err)
	}
	primary := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(primary, ensureTrailingNewline(kp.PrivatePEM), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(primary)
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(managedBegin+"\n"+managedEnd+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id := "i1"
	bundle := &store.SyncBundle{
		Identities: []store.Identity{{ID: id, Name: "id_ed25519"}},
	}
	time.Sleep(10 * time.Millisecond)
	res, err := Apply(dir, bundle, map[string][]byte{id: kp.PrivatePEM}, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(primary)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("gleicher Schluessel darf Datei nicht neu schreiben")
	}
	if res.DryRun {
		t.Fatal("mit managed Block kein DryRun")
	}
}

func TestApplyDryRunWritesNothing(t *testing.T) {
	dir := t.TempDir()
	existing := "Host local\n  HostName localhost\n"
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	kp, _ := keygen.Generate(keygen.TypeEd25519, "x")
	id := "i1"
	bundle := &store.SyncBundle{
		Identities: []store.Identity{{ID: id, Name: "id_ed25519"}},
		Hosts:      []store.Host{{ID: "h1", Alias: "srv", HostName: "ex", IdentityID: &id}},
	}
	res, err := Apply(dir, bundle, map[string][]byte{id: kp.PrivatePEM}, ApplyOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.DryRun || !res.NeedsConfirm {
		t.Fatalf("DryRun/NeedsConfirm: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(dir, "id_ed25519")); !os.IsNotExist(err) {
		t.Fatal("DryRun darf keinen Key schreiben")
	}
	got, _ := os.ReadFile(filepath.Join(dir, "config"))
	if string(got) != existing {
		t.Fatal("DryRun darf config nicht aendern")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), configBakPrefix) {
			t.Fatal("DryRun darf kein Backup anlegen")
		}
	}
}

func TestApplyFirstRunNeedsConfirmWithoutAllow(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte("Host local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kp, _ := keygen.Generate(keygen.TypeEd25519, "x")
	id := "i1"
	bundle := &store.SyncBundle{Identities: []store.Identity{{ID: id, Name: "deploy"}}}
	res, err := Apply(dir, bundle, map[string][]byte{id: kp.PrivatePEM}, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.NeedsConfirm || !res.DryRun {
		t.Fatal("erster Lauf ohne AllowFirstWrite muss Trockenlauf sein")
	}
	if _, err := os.Stat(filepath.Join(dir, "deploy")); !os.IsNotExist(err) {
		t.Fatal("ohne --apply darf kein Key entstehen")
	}
}

func TestApplyNormalizationCollision(t *testing.T) {
	dir := t.TempDir()
	local, _ := keygen.Generate(keygen.TypeEd25519, "local")
	server, _ := keygen.Generate(keygen.TypeEd25519, "server")
	primary := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(primary, local.PrivatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(managedBegin+"\n"+managedEnd+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Server-Name id_ed25519_id normalisiert auf id_ed25519
	id := "i1"
	bundle := &store.SyncBundle{
		Identities: []store.Identity{{ID: id, Name: "id_ed25519_id"}},
	}
	_, err := Apply(dir, bundle, map[string][]byte{id: server.PrivatePEM}, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(primary)
	localFP, _ := PrivateKeyFingerprint(local.PrivatePEM)
	if PrivateKeyMustFP(t, got) != localFP {
		t.Fatal("Normalisierungs-Kollision darf lokalen Key nicht ueberschreiben")
	}
	if _, err := os.Stat(primary + keyConflictSuffix); err != nil {
		t.Fatal("Server-Key muss in Ausweichdatei landen")
	}
}

func TestPruneConfigBackupsKeepsLastTen(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 12; i++ {
		name := configBakPrefix + time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC).Format("20060102T150405Z")
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := pruneConfigBackups(dir, 10); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	var n int
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), configBakPrefix) {
			n++
		}
	}
	if n != 10 {
		t.Fatalf("keep 10: got %d", n)
	}
}

func mergeConfigForTest(path, managedBlock string) (string, error) {
	existing := ""
	if data, err := os.ReadFile(path); err == nil {
		existing = string(data)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	merged := spliceManagedBlock(existing, managedBlock)
	if merged == existing {
		return "", nil
	}
	bak, err := writeTimestampedConfigBackup(path, existing)
	if err != nil {
		return "", err
	}
	if err := pruneConfigBackups(filepath.Dir(path), configBakKeep); err != nil {
		return bak, err
	}
	if err := os.WriteFile(path, []byte(merged), 0o600); err != nil {
		return bak, err
	}
	return bak, chmodPrivate(path)
}

func PrivateKeyMustFP(t *testing.T, pem []byte) string {
	t.Helper()
	fp, err := PrivateKeyFingerprint(pem)
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

func contains(s, sub string) bool {
	return strings.Contains(s, sub)
}

// sshEffective mimics the parts of `ssh -G` we care about: first HostName/User/Port
// and the ordered IdentityFile list across all matching Host blocks.
type sshEffective struct {
	HostName      string
	User          string
	Port          string
	IdentityFiles []string
}

func parseSSHEffective(config, alias string) sshEffective {
	eff := sshEffective{Port: "22"}
	inMatch := false
	hostSet := false
	userSet := false
	portSet := false
	for _, raw := range strings.Split(config, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		key := strings.ToLower(fields[0])
		switch key {
		case "host":
			inMatch = false
			for _, pat := range fields[1:] {
				if hostPatternMatches(pat, alias) {
					inMatch = true
					break
				}
			}
		case "match":
			inMatch = false
		default:
			if !inMatch {
				continue
			}
			val := ""
			if len(fields) > 1 {
				val = strings.Join(fields[1:], " ")
			}
			switch key {
			case "hostname":
				if !hostSet {
					eff.HostName = val
					hostSet = true
				}
			case "user":
				if !userSet {
					eff.User = val
					userSet = true
				}
			case "port":
				if !portSet {
					eff.Port = val
					portSet = true
				}
			case "identityfile":
				eff.IdentityFiles = append(eff.IdentityFiles, val)
			}
		}
	}
	return eff
}

func hostPatternMatches(pattern, alias string) bool {
	if pattern == alias {
		return true
	}
	ok, err := filepath.Match(pattern, alias)
	return err == nil && ok
}

func TestRealSSHGPreservesLocalHosts(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh nicht im PATH")
	}
	dir := t.TempDir()
	local, err := keygen.Generate(keygen.TypeEd25519, "local")
	if err != nil {
		t.Fatal(err)
	}
	server, err := keygen.Generate(keygen.TypeEd25519, "server")
	if err != nil {
		t.Fatal(err)
	}
	rsaLocal, err := keygen.Generate(keygen.TypeRSA, "rsa-local")
	if err != nil {
		t.Fatal(err)
	}
	rsaServer, err := keygen.Generate(keygen.TypeRSA, "rsa-server")
	if err != nil {
		t.Fatal(err)
	}
	primary := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(primary, local.PrivatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	rsaPEM := filepath.Join(dir, "id_rsa.pem")
	if err := os.WriteFile(rsaPEM, rsaLocal.PrivatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "id_rsa"), rsaLocal.PrivatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	existing := strings.Join([]string{
		"Host workstation",
		"  HostName 192.0.2.20",
		"  User me",
		"  IdentityFile " + filepath.ToSlash(primary),
		"",
		"Host github.com",
		"  HostName github.com",
		"  User git",
		"  IdentityFile " + filepath.ToSlash(primary),
		"",
		"Host bastion",
		"  HostName 192.0.2.30",
		"  User root",
		"  IdentityFile " + filepath.ToSlash(rsaPEM),
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	before := map[string]string{}
	for _, h := range []string{"workstation", "github.com", "bastion"} {
		before[h] = realSSHG(t, dir, h)
	}
	idEd := "id-ed"
	idRSA := "id-rsa"
	bundle := &store.SyncBundle{
		Identities: []store.Identity{
			{ID: idEd, Name: "id_ed25519"},
			{ID: idRSA, Name: "id_rsa"},
		},
		Hosts: []store.Host{
			{ID: "h1", Alias: "workstation", HostName: "192.0.2.20", User: "me", IdentityID: &idEd},
			{ID: "h2", Alias: "github.com", HostName: "github.com", User: "git", IdentityID: &idEd},
			{ID: "h3", Alias: "bastion", HostName: "192.0.2.30", User: "root", IdentityID: &idRSA},
		},
	}
	if _, err := Apply(dir, bundle, map[string][]byte{
		idEd:  server.PrivatePEM,
		idRSA: rsaServer.PrivatePEM,
	}, ApplyOptions{AllowFirstWrite: true}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	gotStr := string(got)
	if !strings.HasPrefix(gotStr, existing) {
		t.Fatal("lokale Config muss bytegleich vor dem Block bleiben")
	}
	if strings.Index(gotStr, managedBegin) < len(existing) {
		t.Fatal("managed Block muss nach den lokalen Eintraegen stehen")
	}
	for _, h := range []string{"workstation", "github.com", "bastion"} {
		after := realSSHG(t, dir, h)
		if sshGField(before[h], "hostname") != sshGField(after, "hostname") ||
			sshGField(before[h], "user") != sshGField(after, "user") ||
			sshGField(before[h], "port") != sshGField(after, "port") {
			t.Fatalf("%s: hostname/user/port geaendert", h)
		}
		bif := sshGFields(before[h], "identityfile")
		aif := sshGFields(after, "identityfile")
		if len(bif) != len(aif) {
			t.Fatalf("%s: identityfile Menge %v -> %v", h, bif, aif)
		}
		for i := range bif {
			if bif[i] != aif[i] {
				t.Fatalf("%s: identityfile Reihenfolge %v -> %v", h, bif, aif)
			}
		}
	}
}

func TestApplySkipsLocalHostsListsDryRun(t *testing.T) {
	dir := t.TempDir()
	kp, err := keygen.Generate(keygen.TypeEd25519, "srv")
	if err != nil {
		t.Fatal(err)
	}
	primary := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(primary, kp.PrivatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	existing := strings.Join([]string{
		"Host elitedesk github.com",
		"  User me",
		"  IdentityFile " + filepath.ToSlash(primary),
		"",
		"Host dock pxmx !dock",
		"  User root",
		"  IdentityFile " + filepath.ToSlash(primary),
		"",
		"Host *",
		"  AddKeysToAgent yes",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	id := "i1"
	bundle := &store.SyncBundle{
		Identities: []store.Identity{{ID: id, Name: "id_ed25519"}},
		Hosts: []store.Host{
			{ID: "h1", Alias: "elitedesk", HostName: "10.0.0.1", User: "sync", IdentityID: &id},
			{ID: "h2", Alias: "github.com", HostName: "github.com", User: "git", IdentityID: &id},
			{ID: "h3", Alias: "dock", HostName: "10.0.0.2", User: "sync", IdentityID: &id},
			{ID: "h4", Alias: "pxmx", HostName: "10.0.0.3", User: "root", IdentityID: &id},
			{ID: "h5", Alias: "only-server", HostName: "10.0.0.9", User: "sync", IdentityID: &id},
		},
	}
	res, err := Apply(dir, bundle, map[string][]byte{id: kp.PrivatePEM}, ApplyOptions{DryRun: true, AllowFirstWrite: true})
	if err != nil {
		t.Fatal(err)
	}
	var skipLine string
	for _, p := range res.Plans {
		if strings.HasPrefix(p, "lokal definiert, uebersprungen:") {
			skipLine = p
			break
		}
	}
	if skipLine == "" {
		t.Fatalf("Skip-Liste fehlt in Plans: %v", res.Plans)
	}
	for _, want := range []string{"elitedesk", "github.com", "pxmx"} {
		if !strings.Contains(skipLine, want) {
			t.Fatalf("Skip-Liste ohne %s: %s", want, skipLine)
		}
	}
	if strings.Contains(skipLine, "dock") {
		t.Fatalf("dock ist lokal negiert und darf nicht als lokal definiert gelten: %s", skipLine)
	}
	if strings.Contains(skipLine, "only-server") {
		t.Fatalf("only-server darf nicht uebersprungen werden: %s", skipLine)
	}

	res2, err := Apply(dir, bundle, map[string][]byte{id: kp.PrivatePEM}, ApplyOptions{AllowFirstWrite: true})
	if err != nil {
		t.Fatal(err)
	}
	_ = res2
	got, err := os.ReadFile(filepath.Join(dir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	gotStr := string(got)
	managed := gotStr[strings.Index(gotStr, managedBegin):]
	for _, alias := range []string{"elitedesk", "github.com", "pxmx"} {
		if strings.Contains(managed, "Host "+alias+"\n") {
			t.Fatalf("%s darf nicht im managed Block stehen:\n%s", alias, managed)
		}
	}
	if !strings.Contains(managed, "Host dock\n") {
		t.Fatalf("dock (lokal negiert) muss im managed Block stehen:\n%s", managed)
	}
	if !strings.Contains(managed, "Host only-server\n") {
		t.Fatalf("only-server fehlt im managed Block:\n%s", managed)
	}
}

func TestApplyStarIdentityOmitsManagedIdentity(t *testing.T) {
	dir := t.TempDir()
	local, err := keygen.Generate(keygen.TypeEd25519, "local")
	if err != nil {
		t.Fatal(err)
	}
	server, err := keygen.Generate(keygen.TypeEd25519, "server")
	if err != nil {
		t.Fatal(err)
	}
	primary := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(primary, local.PrivatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	existing := "Host *\n  IdentityFile " + filepath.ToSlash(primary) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	id := "i1"
	bundle := &store.SyncBundle{
		Identities: []store.Identity{{ID: id, Name: "id_ed25519"}},
		Hosts: []store.Host{
			{ID: "h1", Alias: "only-server", HostName: "192.0.2.50", User: "sync", IdentityID: &id, IdentitiesOnly: true},
		},
	}
	if _, err := Apply(dir, bundle, map[string][]byte{id: server.PrivatePEM}, ApplyOptions{AllowFirstWrite: true}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	managed := string(got)[strings.Index(string(got), managedBegin):]
	if !strings.Contains(managed, "Host only-server\n") {
		t.Fatalf("Host muss bleiben:\n%s", managed)
	}
	if strings.Contains(strings.ToLower(managed), "identityfile") {
		t.Fatalf("IdentityFile darf bei Host * nicht im managed Block stehen:\n%s", managed)
	}
	if strings.Contains(strings.ToLower(managed), "identitiesonly") {
		t.Fatalf("IdentitiesOnly darf bei Host * nicht im managed Block stehen:\n%s", managed)
	}
	eff := parseSSHEffective(string(got), "only-server")
	if len(eff.IdentityFiles) != 1 || eff.IdentityFiles[0] != filepath.ToSlash(primary) {
		t.Fatalf("nur lokale IdentityFile erwartet: %v", eff.IdentityFiles)
	}
}

func TestRealSSHGVm88LikePreservesExactIdentityList(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh nicht im PATH")
	}
	dir := t.TempDir()
	local, err := keygen.Generate(keygen.TypeEd25519, "local")
	if err != nil {
		t.Fatal(err)
	}
	server, err := keygen.Generate(keygen.TypeEd25519, "server")
	if err != nil {
		t.Fatal(err)
	}
	rsaLocal, err := keygen.Generate(keygen.TypeRSA, "rsa-local")
	if err != nil {
		t.Fatal(err)
	}
	rsaServer, err := keygen.Generate(keygen.TypeRSA, "rsa-server")
	if err != nil {
		t.Fatal(err)
	}
	ed := filepath.Join(dir, "id_ed25519")
	rsa := filepath.Join(dir, "id_rsa")
	if err := os.WriteFile(ed, local.PrivatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rsa, rsaLocal.PrivatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	existing := strings.Join([]string{
		"Host elitedesk",
		"  HostName 192.0.2.11",
		"  User me",
		"  IdentityFile " + filepath.ToSlash(ed),
		"",
		"Host github.com",
		"  HostName github.com",
		"  User git",
		"  IdentityFile " + filepath.ToSlash(ed),
		"",
		"Host dock pxmx hass",
		"  User root",
		"  IdentityFile " + filepath.ToSlash(rsa),
		"",
		"Host *",
		"  AddKeysToAgent yes",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	hosts := []string{"elitedesk", "github.com", "dock", "pxmx", "hass"}
	before := map[string]string{}
	for _, h := range hosts {
		before[h] = realSSHG(t, dir, h)
	}
	idEd := "id-ed"
	idRSA := "id-rsa"
	bundle := &store.SyncBundle{
		Identities: []store.Identity{
			{ID: idEd, Name: "id_ed25519"},
			{ID: idRSA, Name: "id_rsa"},
		},
		Hosts: []store.Host{
			{ID: "h1", Alias: "elitedesk", HostName: "192.0.2.11", User: "me", IdentityID: &idEd},
			{ID: "h2", Alias: "github.com", HostName: "github.com", User: "git", IdentityID: &idEd},
			{ID: "h3", Alias: "dock", HostName: "192.0.2.21", User: "root", IdentityID: &idRSA},
			{ID: "h4", Alias: "pxmx", HostName: "192.0.2.22", User: "root", IdentityID: &idRSA},
			{ID: "h5", Alias: "hass", HostName: "192.0.2.23", User: "root", IdentityID: &idRSA},
			{ID: "h6", Alias: "fresh-server", HostName: "192.0.2.99", User: "sync", IdentityID: &idEd},
		},
	}
	res, err := Apply(dir, bundle, map[string][]byte{
		idEd:  server.PrivatePEM,
		idRSA: rsaServer.PrivatePEM,
	}, ApplyOptions{AllowFirstWrite: true})
	if err != nil {
		t.Fatal(err)
	}
	skipOK := false
	for _, p := range res.Plans {
		if strings.HasPrefix(p, "lokal definiert, uebersprungen:") &&
			strings.Contains(p, "elitedesk") &&
			strings.Contains(p, "github.com") &&
			strings.Contains(p, "dock") {
			skipOK = true
			break
		}
	}
	if !skipOK {
		t.Fatalf("Skip-Liste unvollstaendig: %v", res.Plans)
	}
	for _, h := range hosts {
		after := realSSHG(t, dir, h)
		if sshGField(before[h], "hostname") != sshGField(after, "hostname") ||
			sshGField(before[h], "user") != sshGField(after, "user") ||
			sshGField(before[h], "port") != sshGField(after, "port") {
			t.Fatalf("%s: hostname/user/port geaendert", h)
		}
		bif := sshGFields(before[h], "identityfile")
		aif := sshGFields(after, "identityfile")
		if len(bif) != len(aif) {
			t.Fatalf("%s: identityfile Menge %v -> %v", h, bif, aif)
		}
		for i := range bif {
			if bif[i] != aif[i] {
				t.Fatalf("%s: identityfile %v -> %v", h, bif, aif)
			}
		}
	}
	fresh := realSSHG(t, dir, "fresh-server")
	if sshGField(fresh, "hostname") != "192.0.2.99" || sshGField(fresh, "user") != "sync" {
		t.Fatalf("fresh-server falsch: %s", fresh)
	}
	if len(sshGFields(fresh, "identityfile")) == 0 {
		t.Fatal("fresh-server braucht IdentityFile aus dem managed Block")
	}
}

func realSSHG(t *testing.T, sshDir, host string) string {
	t.Helper()
	cmd := exec.Command("ssh", "-F", filepath.Join(sshDir, "config"), "-G", host)
	cmd.Env = append(os.Environ(), "HOME="+filepath.Dir(sshDir))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh -G %s: %v\n%s", host, err, out)
	}
	return string(out)
}

func sshGField(g, key string) string {
	for _, line := range strings.Split(g, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], key) {
			return strings.Join(fields[1:], " ")
		}
	}
	return ""
}

func sshGFields(g, key string) []string {
	var out []string
	for _, line := range strings.Split(g, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], key) {
			out = append(out, strings.Join(fields[1:], " "))
		}
	}
	return out
}
