package sshconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMergeConfigBackupAndManagedOnly(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config")
	existing := "Host local\n  HostName localhost\n  User me\n"
	if err := os.WriteFile(configPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	block := managedBegin + "\nHost new\n  HostName new.example\n" + managedEnd + "\n"
	bak, err := mergeConfig(configPath, block)
	if err != nil {
		t.Fatal(err)
	}
	if bak != configPath+"--bak" {
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
	if string(got) != block {
		t.Fatalf("config soll nur managed sein:\n%s", got)
	}
	if contains(string(got), "Host local") {
		t.Fatal("alte Hosts dürfen nicht in config bleiben")
	}
}

func TestMergeConfigSkipsBackupIfExists(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config")
	bakPath := configPath + "--bak"
	original := "Host old\n"
	backup := "Host original-backup\n"
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bakPath, []byte(backup), 0o600); err != nil {
		t.Fatal(err)
	}

	block := managedBegin + "\n" + managedEnd + "\n"
	bak, err := mergeConfig(configPath, block)
	if err != nil {
		t.Fatal(err)
	}
	if bak != "" {
		t.Fatal("backup soll nicht erneut geschrieben werden")
	}
	bakData, _ := os.ReadFile(bakPath)
	if string(bakData) != backup {
		t.Fatal("bestehendes config--bak darf nicht überschrieben werden")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
