package sshconfig

import (
	"os"
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
	if !contains(string(cfg), "Host local") {
		t.Fatal("Host local muss bleiben")
	}
	if !contains(string(cfg), filepath.ToSlash(alt)) && !contains(string(cfg), alt) {
		t.Fatalf("IdentityFile sollte auf Ausweichdatei zeigen:\n%s", cfg)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("erwartet Warnung bei Kollision")
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
