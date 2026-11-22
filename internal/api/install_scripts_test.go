package api

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const goldenPortalBase = "https://portal.example"

func TestRequestBaseURLRejectsShellMetacharacters(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/install/linux.sh", nil)
	req.Host = "x$(id)"
	if _, err := requestBaseURL(req); err == nil {
		t.Fatal("expected reject")
	}
}

func TestLinuxInstallScriptGolden(t *testing.T) {
	assertGolden(t, filepath.Join("testdata", "install-linux.sh.golden"), LinuxInstallScript(goldenPortalBase))
}

func TestWindowsInstallScriptGolden(t *testing.T) {
	assertGolden(t, filepath.Join("testdata", "install-windows.ps1.golden"), windowsInstallScript(goldenPortalBase))
}

func assertGolden(t *testing.T, path, got string) {
	t.Helper()
	wantBytes, err := os.ReadFile(path)
	update := os.Getenv("UPDATE_GOLDEN") == "1"
	if err != nil {
		if update && os.IsNotExist(err) {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			t.Log("golden angelegt")
			return
		}
		t.Fatalf("golden lesen: %v", err)
	}
	want := string(wantBytes)
	if got == want {
		return
	}
	if update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("golden aktualisiert")
		return
	}
	t.Fatalf("weicht von Golden ab (UPDATE_GOLDEN=1 zum Aktualisieren)\n--- got len %d want len %d ---\n%s",
		len(got), len(want), firstDiff(want, got))
}

func TestLinuxInstallScriptContainsSigstoreContract(t *testing.T) {
	script := LinuxInstallScript(goldenPortalBase)
	mustContain := []string{
		"cosign verify-blob",
		"--unsicher-nur-pruefsumme",
		"manifest.json.sigstore.json",
		"SHA256SUMS",
		"https://token.actions.githubusercontent.com",
		"token.actions.githubusercontent.com",
		"thelad-dev/ssh-sync",
		defaultReleaseBase,
		"ssh-sync-darwin-arm64",
		"Nicht: curl | sh",
	}
	mustNot := []string{
		"BEGIN PUBLIC KEY",
		"manifest.sig",
		"openssl pkeyutl",
		"release.pub",
	}
	for _, want := range mustContain {
		if !strings.Contains(script, want) {
			t.Fatalf("fehlt %q", want)
		}
	}
	for _, bad := range mustNot {
		if strings.Contains(script, bad) {
			t.Fatalf("unerwuenscht %q", bad)
		}
	}
}

func TestLinuxInstallScriptShellcheck(t *testing.T) {
	if _, err := exec.LookPath("shellcheck"); err != nil {
		t.Skip("shellcheck nicht installiert")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "install-linux.sh")
	if err := os.WriteFile(path, []byte(LinuxInstallScript(goldenPortalBase)), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("shellcheck", "-s", "sh", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shellcheck: %v\n%s", err, out)
	}
}

func TestWindowsInstallScriptPwshParse(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh nicht installiert")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "install-windows.ps1")
	if err := os.WriteFile(path, []byte(windowsInstallScript(goldenPortalBase)), 0o644); err != nil {
		t.Fatal(err)
	}
	// Parser-only: ScriptBlock aus Datei, nicht ausfuehren.
	cmd := exec.Command(pwsh, "-NoProfile", "-Command",
		"$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('"+path+"', [ref]$null, [ref]$e); if($e){$e|ForEach-Object{$_.ToString()}; exit 1}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pwsh parse: %v\n%s", err, out)
	}
}

func TestLinuxInstallScriptUnsicherPath(t *testing.T) {
	payload := make([]byte, 2048)
	for i := range payload {
		payload[i] = byte('B')
	}
	sum := sha256.Sum256(payload)
	hashHex := hex.EncodeToString(sum[:])

	root := t.TempDir()
	home := filepath.Join(root, "home")
	binDir := filepath.Join(root, "bin")
	installDir := filepath.Join(home, ".local", "bin")
	assetDir := filepath.Join(root, "assets")
	for _, d := range []string{binDir, assetDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	manifest := `{"assets":{"ssh-sync-linux-amd64":"` + hashHex + `","ssh-sync-linux-arm64":"` + hashHex + `"},"version":"1.0.0"}`
	sums := hashHex + "  ssh-sync-linux-amd64\n" + hashHex + "  ssh-sync-linux-arm64\n"
	bundle := `{"dummy":"bundle"}`
	for name, body := range map[string]string{
		"manifest.json":               manifest,
		"manifest.json.sigstore.json": bundle,
		"SHA256SUMS":                  sums,
		"ssh-sync-linux-amd64":        string(payload),
		"ssh-sync-linux-arm64":        string(payload),
	} {
		if err := os.WriteFile(filepath.Join(assetDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
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
		"SSH_SYNC_RELEASE_URL=http://127.0.0.1:9/rel",
		"SSH_SYNC_ALLOW_INSECURE=1",
	)

	// Ohne cosign und ohne Schalter: Abbruch.
	cmd := exec.Command("sh", scriptPath)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("erwartet Abbruch ohne cosign, got ok\n%s", out)
	}
	if !strings.Contains(string(out), "cosign fehlt") {
		t.Fatalf("erwartet cosign-Hinweis, got:\n%s", out)
	}

	ran := 0
	for _, shell := range []string{"sh", "bash", "zsh"} {
		if _, err := exec.LookPath(shell); err != nil {
			t.Logf("%s nicht verfuegbar, uebersprungen", shell)
			continue
		}
		_ = os.RemoveAll(installDir)
		cmd := exec.Command(shell, scriptPath, "--unsicher-nur-pruefsumme")
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: exit %v\n%s", shell, err, out)
		}
		ran++
	}
	if ran == 0 {
		t.Fatal("kein Shell verfuegbar")
	}
	if _, err := os.Stat(filepath.Join(installDir, "ssh-sync")); err != nil {
		t.Fatalf("binary fehlt: %v", err)
	}
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
		"manifest.json.sigstore.json",
		"UnsicherNurPruefsumme",
		"cosign verify-blob",
		"CF-Access-Client-Id",
		base,
		defaultReleaseBase,
	}
	mustNot := []string{"BEGIN PUBLIC KEY", "manifest.sig", "openssl pkeyutl"}
	for _, want := range mustContain {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q", want)
		}
	}
	for _, bad := range mustNot {
		if strings.Contains(script, bad) {
			t.Fatalf("unerwuenscht %q", bad)
		}
	}
}

func firstDiff(want, got string) string {
	n := len(want)
	if len(got) < n {
		n = len(got)
	}
	i := 0
	for i < n && want[i] == got[i] {
		i++
	}
	start := i - 40
	if start < 0 {
		start = 0
	}
	endW := i + 80
	if endW > len(want) {
		endW = len(want)
	}
	endG := i + 80
	if endG > len(got) {
		endG = len(got)
	}
	return "at " + strconv.Itoa(i) + "\nwant: " + want[start:endW] + "\ngot:  " + got[start:endG]
}
