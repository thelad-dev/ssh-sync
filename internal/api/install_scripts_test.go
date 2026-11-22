package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thelad-dev/ssh-sync/internal/releaseverify"
)

func TestRequestBaseURLRejectsShellMetacharacters(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/install/linux.sh", nil)
	req.Host = "x$(id)"
	if _, err := requestBaseURL(req); err == nil {
		t.Fatal("expected reject")
	}
}

func TestLinuxInstallScriptWithShBashZsh(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := releaseverify.PublicKey
	releaseverify.PublicKey = pub
	t.Cleanup(func() { releaseverify.PublicKey = old })

	payload := make([]byte, 2048)
	for i := range payload {
		payload[i] = byte('B')
	}
	sum := sha256.Sum256(payload)
	m := releaseverify.Manifest{
		Version: "1.0.0",
		Assets: map[string]string{
			"ssh-sync-linux-amd64": hex.EncodeToString(sum[:]),
			"ssh-sync-linux-arm64": hex.EncodeToString(sum[:]),
		},
	}
	canon, sig, err := releaseverify.SignManifest(m, priv)
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	home := filepath.Join(root, "home")
	binDir := filepath.Join(root, "bin")
	installDir := filepath.Join(home, ".local", "bin")
	serviceDir := filepath.Join(home, ".config", "systemd", "user")
	assetDir := filepath.Join(root, "assets")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(assetDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "manifest.json"), canon, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "manifest.sig"), sig, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "ssh-sync-linux-amd64"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "ssh-sync-linux-arm64"), payload, 0o644); err != nil {
		t.Fatal(err)
	}

	fakeCurl := filepath.Join(binDir, "curl")
	curlScript := `#!/bin/sh
dest=""
url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) dest="$2"; shift 2 ;;
    -H|--header|-fsSL) shift ;;
    http*|https*) url="$1"; shift ;;
    *) shift ;;
  esac
done
if [ -z "$dest" ] || [ -z "$url" ]; then exit 1; fi
name=$(basename "$url")
src="` + assetDir + `/$name"
cp "$src" "$dest"
exit 0
`
	if err := os.WriteFile(fakeCurl, []byte(curlScript), 0o755); err != nil {
		t.Fatal(err)
	}
	fakeSystemctl := filepath.Join(binDir, "systemctl")
	if err := os.WriteFile(fakeSystemctl, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	script := LinuxInstallScript("http://127.0.0.1:9")
	scriptPath := filepath.Join(root, "install.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	pathEnv := binDir + ":/usr/bin:/bin"
	if p := os.Getenv("PATH"); p != "" {
		pathEnv = binDir + ":" + p
	}
	env := append(os.Environ(),
		"PATH="+pathEnv,
		"HOME="+home,
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
		"INSTALL_DIR="+installDir,
	)

	ran := 0
	for _, shell := range []string{"sh", "bash", "zsh"} {
		if _, err := exec.LookPath(shell); err != nil {
			t.Logf("%s nicht verfügbar, übersprungen", shell)
			continue
		}
		_ = os.RemoveAll(installDir)
		_ = os.RemoveAll(serviceDir)
		cmd := exec.Command(shell, scriptPath)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: exit %v\n%s", shell, err, out)
		}
		ran++
	}
	if ran == 0 {
		t.Fatal("kein Shell verfügbar")
	}

	if _, err := os.Stat(filepath.Join(installDir, "ssh-sync")); err != nil {
		t.Fatalf("binary fehlt: %v", err)
	}
}

func TestWindowsInstallScriptHandlerSemantics(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := releaseverify.PublicKey
	releaseverify.PublicKey = pub
	t.Cleanup(func() { releaseverify.PublicKey = old })

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
		"BEGIN PUBLIC KEY",
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
