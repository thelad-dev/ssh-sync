package store

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSyncBundleSendsAllHostsToEveryDevice(t *testing.T) {
	st, err := Open(t.TempDir() + "/sync.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now()
	_ = st.UpsertHost(Host{ID: "h1", Alias: "a", HostName: "a.example", Port: 22, CreatedAt: now, UpdatedAt: now})
	_ = st.UpsertHost(Host{ID: "h2", Alias: "b", HostName: "b.example", Port: 22, CreatedAt: now, UpdatedAt: now})
	_ = st.CreateDevice(Device{ID: "d1", Name: "laptop", TokenHash: "x", CreatedAt: now})

	bundle, err := st.SyncBundleForDevice("d1")
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Hosts) != 2 {
		t.Fatalf("erwartet alle Hosts, got %d", len(bundle.Hosts))
	}
}

func TestDocsDoNotClaimProfileFiltering(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(readme)
	banned := []string{
		"Profile steuern, welche Hosts",
		"Profil anlegen",
		"Pflicht für Sync",
	}
	for _, b := range banned {
		if strings.Contains(text, b) {
			t.Fatalf("README enthaelt veraltete Profil-Aussage: %q", b)
		}
	}
	anleitung, err := os.ReadFile(filepath.Join(root, "docs/ANLEITUNG.md"))
	if err != nil {
		t.Fatal(err)
	}
	a := string(anleitung)
	if strings.Contains(a, "Ohne **Profil**") {
		t.Fatal("ANLEITUNG behauptet noch Pflicht-Profile")
	}
	if !strings.Contains(a, "Profil-/Geraetetrennung") {
		t.Fatal("ANLEITUNG soll klaeren, dass Profile fehlen")
	}
}
