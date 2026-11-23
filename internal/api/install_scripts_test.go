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
		"Vertrauensmodell",
		"COSIGN_PIN_VERSION=",
		cosignPinnedVersion,
		cosignPin("linux-amd64"),
		"cosign-Bootstrap: SHA-256 stimmt nicht",
		"github.com/sigstore/cosign/releases/download",
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

func TestCosignBootstrapPinsFormat(t *testing.T) {
	if !strings.HasPrefix(cosignPinnedVersion, "v") {
		t.Fatalf("Version muss mit v beginnen: %q", cosignPinnedVersion)
	}
	rest := strings.TrimPrefix(cosignPinnedVersion, "v")
	parts := strings.Split(rest, ".")
	if len(parts) != 3 {
		t.Fatalf("Version erwartet vMAJOR.MINOR.PATCH, got %q", cosignPinnedVersion)
	}
	for _, p := range parts {
		if p == "" {
			t.Fatalf("leeres Versionssegment in %q", cosignPinnedVersion)
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				t.Fatalf("Versionssegment nicht numerisch in %q", cosignPinnedVersion)
			}
		}
	}
	required := []string{"linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64", "windows-amd64"}
	for _, key := range required {
		h, ok := cosignBootstrapSHA256[key]
		if !ok {
			t.Fatalf("fehlender Pin-Schluessel %q", key)
		}
		if len(h) != 64 {
			t.Fatalf("%s: Hash-Laenge %d, erwartet 64", key, len(h))
		}
		for _, c := range h {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				t.Fatalf("%s: Hash nicht klein-hex: %q", key, h)
			}
		}
	}
	if len(cosignBootstrapSHA256) != len(required) {
		t.Fatalf("unerwartete Extra-Pins: %#v", cosignBootstrapSHA256)
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

	// Ohne cosign und ohne Schalter: Bootstrap scheitert (kein Asset), klarer Abbruch.
	cmd := exec.Command("sh", scriptPath)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("erwartet Abbruch ohne cosign/Bootstrap, got ok\n%s", out)
	}
	gotOut := string(out)
	if !strings.Contains(gotOut, "cosign-Bootstrap") && !strings.Contains(gotOut, "Download fehlgeschlagen") {
		t.Fatalf("erwartet Bootstrap-/Offline-Hinweis, got:\n%s", gotOut)
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
		"verify-blob",
		"CosignPinVersion",
		"Vertrauensmodell",
		"CF-Access-Client-Id",
		base,
		defaultReleaseBase,
		cosignPinnedVersion,
		cosignPin("windows-amd64"),
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

func TestLinuxInstallScriptCosignRejectsSHA256SUMSFallback(t *testing.T) {
	// Manifest-Digest A, SHA256SUMS-Digest B (passend zur Binary): Cosign-Pfad muss A nutzen und scheitern.
	payload := make([]byte, 2048)
	for i := range payload {
		payload[i] = byte('B')
	}
	sumB := sha256.Sum256(payload)
	hashB := hex.EncodeToString(sumB[:])
	hashA := strings.Repeat("a", 64)

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
	// Eingeruecktes mkmanifest-Format: filename und sha256 auf getrennten Zeilen.
	manifest := `{
  "version": "1.0.0",
  "artifacts": [
    {
      "platform": "linux-amd64",
      "filename": "ssh-sync-linux-amd64",
      "sha256": "` + hashA + `",
      "size": 2048
    }
  ]
}
`
	sums := hashB + "  ssh-sync-linux-amd64\n"
	for name, body := range map[string]string{
		"manifest.json":               manifest,
		"manifest.json.sigstore.json": `{"dummy":"bundle"}`,
		"SHA256SUMS":                  sums,
		"ssh-sync-linux-amd64":        string(payload),
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
	fakeCosign := filepath.Join(binDir, "cosign")
	if err := os.WriteFile(fakeCosign, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
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

	cmd := exec.Command("sh", scriptPath)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("erwartet Abbruch bei Manifest-Digest A vs Binary B, got ok\n%s", out)
	}
	got := string(out)
	if !strings.Contains(got, "SHA-256 stimmt nicht") && !strings.Contains(got, "fehlt im signierten Manifest") {
		t.Fatalf("erwartet Hash-Mismatch gegen Manifest, got:\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(installDir, "ssh-sync")); err == nil {
		t.Fatal("binary darf bei Digest-Mismatch nicht installiert werden")
	}
}

func TestLinuxInstallScriptCosignAcceptsMkmanifestFormat(t *testing.T) {
	payload := make([]byte, 2048)
	for i := range payload {
		payload[i] = byte('D')
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
	manifest := `{
  "version": "1.0.0",
  "artifacts": [
    {
      "platform": "linux-amd64",
      "filename": "ssh-sync-linux-amd64",
      "sha256": "` + hashHex + `",
      "size": 2048
    }
  ]
}
`
	for name, body := range map[string]string{
		"manifest.json":               manifest,
		"manifest.json.sigstore.json": `{"dummy":"bundle"}`,
		"SHA256SUMS":                  strings.Repeat("0", 64) + "  ssh-sync-linux-amd64\n",
		"ssh-sync-linux-amd64":        string(payload),
	} {
		if err := os.WriteFile(filepath.Join(assetDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{
		"curl":      "#!/bin/sh\ndest=\"\"; url=\"\"; while [ $# -gt 0 ]; do case \"$1\" in -o) dest=\"$2\"; shift 2;; -H|--header|-fsSL) shift;; http*|https*) url=\"$1\"; shift;; *) shift;; esac; done; cp \"" + assetDir + "/$(basename \"$url\")\" \"$dest\"\n",
		"cosign":    "#!/bin/sh\nexit 0\n",
		"systemctl": "#!/bin/sh\nexit 1\n",
	} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	scriptPath := filepath.Join(root, "install.sh")
	if err := os.WriteFile(scriptPath, []byte(LinuxInstallScript("http://127.0.0.1:9")), 0o755); err != nil {
		t.Fatal(err)
	}

	ran := 0
	for _, impl := range []string{"mawk", "gawk"} {
		awkPath, err := exec.LookPath(impl)
		if err != nil {
			t.Logf("%s nicht verfuegbar, uebersprungen", impl)
			continue
		}
		implDir := filepath.Join(root, "awk-"+impl)
		if err := os.MkdirAll(implDir, 0o755); err != nil {
			t.Fatal(err)
		}
		wrapper := "#!/bin/sh\nexec " + awkPath + " \"$@\"\n"
		if err := os.WriteFile(filepath.Join(implDir, "awk"), []byte(wrapper), 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.RemoveAll(installDir)
		pathEnv := implDir + ":" + binDir + ":/usr/bin:/bin"
		if p := os.Getenv("PATH"); p != "" {
			pathEnv = implDir + ":" + binDir + ":" + p
		}
		cmd := exec.Command("sh", scriptPath)
		cmd.Env = append(os.Environ(),
			"PATH="+pathEnv,
			"HOME="+home,
			"INSTALL_DIR="+installDir,
			"SSH_SYNC_RELEASE_URL=http://127.0.0.1:9/rel",
			"SSH_SYNC_ALLOW_INSECURE=1",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: erwartet Erfolg mit mkmanifest-Format, got %v\n%s", impl, err, out)
		}
		if _, err := os.Stat(filepath.Join(installDir, "ssh-sync")); err != nil {
			t.Fatalf("%s: binary fehlt: %v\n%s", impl, err, out)
		}
		ran++
	}
	if ran == 0 {
		t.Fatal("weder mawk noch gawk verfuegbar")
	}
}

func TestLinuxInstallScriptCosignRequiresManifestDigest(t *testing.T) {
	payload := make([]byte, 2048)
	for i := range payload {
		payload[i] = byte('C')
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
	// Manifest ohne Eintrag fuer das Asset; SHA256SUMS hat den passenden Hash.
	manifest := `{"version":"1.0.0","artifacts":[{"platform":"linux-arm64","filename":"ssh-sync-linux-arm64","sha256":"` + hashHex + `","size":1}]}`
	sums := hashHex + "  ssh-sync-linux-amd64\n"
	for name, body := range map[string]string{
		"manifest.json":               manifest,
		"manifest.json.sigstore.json": `{}`,
		"SHA256SUMS":                  sums,
		"ssh-sync-linux-amd64":        string(payload),
	} {
		if err := os.WriteFile(filepath.Join(assetDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{
		"curl":      "#!/bin/sh\ndest=\"\"; url=\"\"; while [ $# -gt 0 ]; do case \"$1\" in -o) dest=\"$2\"; shift 2;; -H|--header|-fsSL) shift;; http*|https*) url=\"$1\"; shift;; *) shift;; esac; done; cp \"" + assetDir + "/$(basename \"$url\")\" \"$dest\"\n",
		"cosign":    "#!/bin/sh\nexit 0\n",
		"systemctl": "#!/bin/sh\nexit 1\n",
	} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	scriptPath := filepath.Join(root, "install.sh")
	if err := os.WriteFile(scriptPath, []byte(LinuxInstallScript("http://127.0.0.1:9")), 0o755); err != nil {
		t.Fatal(err)
	}
	pathEnv := binDir + ":/usr/bin:/bin"
	if p := os.Getenv("PATH"); p != "" {
		pathEnv = binDir + ":" + p
	}
	cmd := exec.Command("sh", scriptPath)
	cmd.Env = append(os.Environ(),
		"PATH="+pathEnv,
		"HOME="+home,
		"INSTALL_DIR="+installDir,
		"SSH_SYNC_RELEASE_URL=http://127.0.0.1:9/rel",
		"SSH_SYNC_ALLOW_INSECURE=1",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("erwartet Abbruch ohne Manifest-Digest, got ok\n%s", out)
	}
	if !strings.Contains(string(out), "fehlt im signierten Manifest") {
		t.Fatalf("erwartet Manifest-Fehler, got:\n%s", out)
	}
}

func installScriptFakeEnv(t *testing.T, payload []byte, withCosign bool, pinHash string) (scriptPath, installDir, binDir, assetDir string, env []string) {
	t.Helper()
	sum := sha256.Sum256(payload)
	hashHex := hex.EncodeToString(sum[:])
	root := t.TempDir()
	home := filepath.Join(root, "home")
	binDir = filepath.Join(root, "bin")
	installDir = filepath.Join(home, ".local", "bin")
	assetDir = filepath.Join(root, "assets")
	for _, d := range []string{binDir, assetDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	manifest := `{"assets":{"ssh-sync-linux-amd64":"` + hashHex + `"},"version":"1.0.0"}`
	for name, body := range map[string]string{
		"manifest.json":               manifest,
		"manifest.json.sigstore.json": `{"dummy":"bundle"}`,
		"SHA256SUMS":                  hashHex + "  ssh-sync-linux-amd64\n",
		"ssh-sync-linux-amd64":        string(payload),
	} {
		if err := os.WriteFile(filepath.Join(assetDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	curlScript := `#!/bin/sh
dest=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) dest="$2"; shift 2 ;;
    -H|--header|-fsSL|-f|-s|-S|-L) shift ;;
    http*|https*) url="$1"; shift ;;
    *) shift ;;
  esac
done
[ -n "$dest" ] && [ -n "$url" ] || exit 1
src="` + assetDir + `/$(basename "$url")"
[ -f "$src" ] || exit 1
cp "$src" "$dest"
`
	if err := os.WriteFile(filepath.Join(binDir, "curl"), []byte(curlScript), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "systemctl"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if withCosign {
		if err := os.WriteFile(filepath.Join(binDir, "cosign"), []byte("#!/bin/sh\necho PATH_COSIGN_USED >&2\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	pins := map[string]string{
		"linux-amd64":   pinHash,
		"linux-arm64":   strings.Repeat("1", 64),
		"darwin-amd64":  strings.Repeat("2", 64),
		"darwin-arm64":  strings.Repeat("3", 64),
		"windows-amd64": strings.Repeat("4", 64),
	}
	script := linuxInstallScript("http://127.0.0.1:9", "v0.0.0-test", pins)
	scriptPath = filepath.Join(root, "install.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	pathEnv := binDir + ":/usr/bin:/bin"
	if p := os.Getenv("PATH"); p != "" {
		pathEnv = binDir + ":" + p
	}
	env = append(os.Environ(),
		"PATH="+pathEnv,
		"HOME="+home,
		"INSTALL_DIR="+installDir,
		"SSH_SYNC_RELEASE_URL=http://127.0.0.1:9/rel",
		"SSH_SYNC_ALLOW_INSECURE=1",
	)
	return scriptPath, installDir, binDir, assetDir, env
}

func TestLinuxInstallScriptBootstrapWrongHash(t *testing.T) {
	payload := bytesFilled(2048, 'W')
	fakeCosign := []byte("#!/bin/sh\nexit 0\n")
	wrongPin := strings.Repeat("a", 64)
	scriptPath, installDir, _, assetDir, env := installScriptFakeEnv(t, payload, false, wrongPin)
	if err := os.WriteFile(filepath.Join(assetDir, "cosign-linux-amd64"), fakeCosign, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", scriptPath)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("erwartet Abbruch bei falschem cosign-Hash, got ok\n%s", out)
	}
	if !strings.Contains(string(out), "cosign-Bootstrap: SHA-256 stimmt nicht") {
		t.Fatalf("erwartet Hash-Abbruch, got:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(installDir, "ssh-sync")); err == nil {
		t.Fatal("binary darf bei Bootstrap-Hash-Mismatch nicht installiert werden")
	}
}

func TestLinuxInstallScriptBootstrapSuccess(t *testing.T) {
	payload := bytesFilled(2048, 'S')
	fakeCosign := []byte("#!/bin/sh\necho BOOTSTRAP_COSIGN_USED >&2\nexit 0\n")
	sum := sha256.Sum256(fakeCosign)
	pin := hex.EncodeToString(sum[:])
	scriptPath, installDir, _, assetDir, env := installScriptFakeEnv(t, payload, false, pin)
	if err := os.WriteFile(filepath.Join(assetDir, "cosign-linux-amd64"), fakeCosign, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", scriptPath)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("erwartet Erfolg mit Bootstrap-cosign: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "BOOTSTRAP_COSIGN_USED") {
		t.Fatalf("erwartet Bootstrap-cosign, got:\n%s", out)
	}
	if !strings.Contains(string(out), "lade gepinnte") {
		t.Fatalf("erwartet Bootstrap-Hinweis, got:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(installDir, "ssh-sync")); err != nil {
		t.Fatalf("binary fehlt: %v", err)
	}
}

func TestLinuxInstallScriptPrefersPathCosign(t *testing.T) {
	payload := bytesFilled(2048, 'P')
	// Pin passt zu keinem Asset; PATH-cosign muss greifen ohne Bootstrap-Download.
	scriptPath, installDir, _, _, env := installScriptFakeEnv(t, payload, true, strings.Repeat("f", 64))
	cmd := exec.Command("sh", scriptPath)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("erwartet Erfolg mit PATH-cosign: %v\n%s", err, out)
	}
	got := string(out)
	if !strings.Contains(got, "PATH_COSIGN_USED") {
		t.Fatalf("erwartet PATH-cosign, got:\n%s", got)
	}
	if strings.Contains(got, "lade gepinnte") {
		t.Fatalf("Bootstrap darf bei PATH-cosign nicht laufen:\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(installDir, "ssh-sync")); err != nil {
		t.Fatalf("binary fehlt: %v", err)
	}
}

func bytesFilled(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
