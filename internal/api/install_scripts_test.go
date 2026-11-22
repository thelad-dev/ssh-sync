package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestBaseURLRejectsShellMetacharacters(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/install/linux.sh", nil)
	req.Host = "x$(id)"
	if _, err := requestBaseURL(req); err == nil {
		t.Fatal("expected reject")
	}
}

func TestLinuxInstallScriptWithShBashZsh(t *testing.T) {
	// Ed25519-Installer-Pfad ist durch Sigstore ersetzt; vollstaendige
	// Installer-Tests folgen im Installer-Worker (Worker I).
	t.Skip("wartet auf Sigstore-Installer (Worker I)")
}

func TestWindowsInstallScriptHandlerSemantics(t *testing.T) {
	base := "https://portal.example"
	ts := httptest.NewServer(InstallScriptsHandler())
	t.Cleanup(ts.Close)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/install/windows.ps1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "portal.example"
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)

	mustContain := []string{
		`Join-Path $env:LOCALAPPDATA "Programs\ssh-sync"`,
		`Join-Path $InstallDir "ssh-sync.exe"`,
		"$env:SSH_SYNC_URL",
		"Remove-LegacySshSyncTask",
		"Install-SshSyncWindowsService",
		"Dienst-Installation uebersprungen (keine Administrator-Rechte)",
		"manifest.json",
		"CF-Access-Client-Id",
		base,
	}
	for _, want := range mustContain {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q", want)
		}
	}
}
