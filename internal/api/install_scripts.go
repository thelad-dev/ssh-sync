package api

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/thelad-dev/ssh-sync/internal/releaseverify"
)

// Standard-Release-Basis (GitHub latest). Identitaets-Strings fuer cosign stehen
// nur in den generierten Skripten und kanonisch in internal/releaseverify/identity.go.
const defaultReleaseBase = "https://github.com/thelad-dev/ssh-sync/releases/latest/download"

func InstallScriptsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		base, err := requestBaseURL(r)
		if err != nil {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/install/linux.sh":
			w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
			w.Header().Set("Content-Disposition", "inline; filename=install-linux.sh")
			if r.Method == http.MethodHead {
				return
			}
			_, _ = fmt.Fprint(w, linuxInstallScript(base))
		case "/install/windows.ps1":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Disposition", "inline; filename=install-windows.ps1")
			if r.Method == http.MethodHead {
				return
			}
			_, _ = fmt.Fprint(w, windowsInstallScript(base))
		case "/install/windows-service.ps1":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Disposition", "inline; filename=install-windows-service.ps1")
			if r.Method == http.MethodHead {
				return
			}
			_, _ = fmt.Fprint(w, windowsServiceInstallScript(base))
		default:
			http.NotFound(w, r)
		}
	})
}

func requestBaseURL(r *http.Request) (string, error) {
	if pub := strings.TrimSpace(os.Getenv("SSH_SYNC_PUBLIC_URL")); pub != "" {
		u, err := url.Parse(pub)
		if err != nil {
			return "", err
		}
		host := u.Host
		if u.Path != "" && u.Path != "/" {
			return "", fmt.Errorf("SSH_SYNC_PUBLIC_URL darf keinen Pfad haben")
		}
		return releaseverify.SanitizeInstallBaseURL(u.Scheme, host)
	}
	scheme := "https"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = strings.TrimSpace(strings.Split(proto, ",")[0])
	} else if r.TLS == nil {
		scheme = "http"
	}
	return releaseverify.SanitizeInstallBaseURL(scheme, r.Host)
}

func linuxInstallScript(base string) string {
	return LinuxInstallScript(base)
}

// LinuxInstallScript liefert den generierten POSIX-Installer (Linux und macOS).
func LinuxInstallScript(base string) string {
	return fmt.Sprintf(`#!/bin/sh
# ssh-sync  -  Linux/macOS Installer
# Empfohlen: Skript laden, lesen, dann ausfuehren. Nicht: curl | sh
#   curl -fsSL '%s/install/linux.sh' -o install-linux.sh
#   less install-linux.sh
#   sh install-linux.sh
# Optional ohne cosign (KEINE Herkunftspruefung):
#   sh install-linux.sh --unsicher-nur-pruefsumme
set -eu

PORTAL_URL="${SSH_SYNC_URL:-%s}"
RELEASE_BASE="${SSH_SYNC_RELEASE_URL:-%s}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
SERVICE_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
BIN_NAME="ssh-sync"
ALLOW_INSECURE="${SSH_SYNC_ALLOW_INSECURE:-0}"
UNSICHER_NUR_PRUEFSUMME=0
# Identitaet: kanonisch internal/releaseverify/identity.go
COSIGN_OIDC_ISSUER="https://token.actions.githubusercontent.com"
COSIGN_IDENTITY_REGEXP='^https://github\.com/thelad-dev/ssh-sync/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$'
GITHUB_REPO="https://github.com/thelad-dev/ssh-sync"

for arg in "$@"; do
  case "$arg" in
    --unsicher-nur-pruefsumme) UNSICHER_NUR_PRUEFSUMME=1 ;;
    -h|--help)
      echo "Usage: sh install-linux.sh [--unsicher-nur-pruefsumme]"
      echo "  Standard: cosign verify-blob gegen Sigstore (GitHub Actions Identitaet)."
      echo "  --unsicher-nur-pruefsumme: nur SHA-256 gegen SHA256SUMS (keine Herkunft)."
      exit 0
      ;;
    *)
      echo "Unbekanntes Argument: $arg (siehe --help)" >&2
      exit 1
      ;;
  esac
done

require_https_or_loopback() {
  url="$1"
  label="$2"
  case "$url" in
    https://*) ;;
    http://127.0.0.1:*|http://127.0.0.1|http://localhost:*|http://localhost) ;;
    http://*)
      if [ "$ALLOW_INSECURE" != "1" ]; then
        echo "$label: http:// nur mit SSH_SYNC_ALLOW_INSECURE=1 oder gegen Loopback." >&2
        exit 1
      fi
      ;;
    *)
      echo "$label muss https:// (oder Loopback-http) sein: $url" >&2
      exit 1
      ;;
  esac
}

require_https_or_loopback "$PORTAL_URL" "PORTAL_URL / SSH_SYNC_URL"
require_https_or_loopback "$RELEASE_BASE" "RELEASE_BASE / SSH_SYNC_RELEASE_URL"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$os" in
  linux)
    case "$arch" in
      x86_64|amd64)  ASSET="ssh-sync-linux-amd64" ;;
      aarch64|arm64) ASSET="ssh-sync-linux-arm64" ;;
      *) echo "Nicht unterstuetzte Architektur: $arch" >&2; exit 1 ;;
    esac
    ;;
  darwin)
    case "$arch" in
      x86_64|amd64)  ASSET="ssh-sync-darwin-amd64" ;;
      arm64|aarch64) ASSET="ssh-sync-darwin-arm64" ;;
      *) echo "Nicht unterstuetzte Architektur: $arch" >&2; exit 1 ;;
    esac
    ;;
  *)
    echo "Nicht unterstuetztes OS: $os (Linux/macOS)" >&2
    exit 1
    ;;
esac

mkdir -p "$INSTALL_DIR"
DEST="$INSTALL_DIR/$BIN_NAME"

if ! touch "$INSTALL_DIR/.write-test" 2>/dev/null; then
  echo "Schreiben in $INSTALL_DIR nicht moeglich." >&2
  exit 1
fi
rm -f "$INSTALL_DIR/.write-test"

if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  echo "sha256sum oder shasum erforderlich" >&2
  exit 1
fi

file_sha256() {
  f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print tolower($1)}'
  else
    shasum -a 256 "$f" | awk '{print tolower($1)}'
  fi
}

curl_fetch() {
  url="$1"
  dest="$2"
  if command -v curl >/dev/null 2>&1; then
    set -- curl -fsSL
    [ -n "${CF_ACCESS_CLIENT_ID:-}" ] && set -- "$@" -H "CF-Access-Client-Id: ${CF_ACCESS_CLIENT_ID}"
    [ -n "${CF_ACCESS_CLIENT_SECRET:-}" ] && set -- "$@" -H "CF-Access-Client-Secret: ${CF_ACCESS_CLIENT_SECRET}"
    "$@" "$url" -o "$dest"
  elif command -v wget >/dev/null 2>&1; then
    if [ -n "${CF_ACCESS_CLIENT_ID:-}" ]; then
      wget -q --header="CF-Access-Client-Id: ${CF_ACCESS_CLIENT_ID}" \
        --header="CF-Access-Client-Secret: ${CF_ACCESS_CLIENT_SECRET}" \
        -O "$dest" "$url"
    else
      wget -q -O "$dest" "$url"
    fi
  else
    echo "curl oder wget erforderlich" >&2
    exit 1
  fi
}

hash_from_manifest() {
  # Unterstuetzt {"assets":{"name":"hex"}} und {"assets":[{"filename":"name","sha256":"hex"},...]}
  asset="$1"
  man="$2"
  h="$(sed -n "s/.*\"${asset}\"[[:space:]]*:[[:space:]]*\"\\([0-9a-fA-F]\\{64\\}\\)\".*/\\1/p" "$man" | tr 'A-F' 'a-f' | head -n1)"
  if [ -n "$h" ]; then
    printf '%%s' "$h"
    return 0
  fi
  h="$(awk -v a="$asset" '
    BEGIN { IGNORECASE=0 }
    {
      line=$0
      if (index(line, a) == 0) next
      if (match(line, /"sha256"[[:space:]]*:[[:space:]]*"[0-9a-fA-F]{64}"/)) {
        s = substr(line, RSTART, RLENGTH)
        sub(/^.*"sha256"[[:space:]]*:[[:space:]]*"/, "", s)
        sub(/".*$/, "", s)
        print tolower(s)
        exit
      }
    }
  ' "$man")"
  printf '%%s' "$h"
}

hash_from_sums() {
  asset="$1"
  sums="$2"
  awk -v a="$asset" 'tolower($2)==tolower(a) || $2==("./" a) { print tolower($1); exit }' "$sums"
}

print_cosign_install_help() {
  echo "" >&2
  echo "cosign fehlt. Herkunftspruefung (Sigstore) braucht cosign." >&2
  echo "Installation (Beispiele):" >&2
  echo "  Linux:  https://docs.sigstore.dev/cosign/system_config/installation/" >&2
  echo "          oder: go install github.com/sigstore/cosign/v2/cmd/cosign@latest" >&2
  echo "  macOS:  brew install cosign" >&2
  echo "" >&2
  echo "Manuelle Pruefung nach Download von Release-Artefakten:" >&2
  echo "  cosign verify-blob \\" >&2
  echo "    --bundle manifest.json.sigstore.json \\" >&2
  echo "    --certificate-identity-regexp '$COSIGN_IDENTITY_REGEXP' \\" >&2
  echo "    --certificate-oidc-issuer $COSIGN_OIDC_ISSUER \\" >&2
  echo "    manifest.json" >&2
  echo "" >&2
  echo "Ohne cosign nur mit explizitem Schalter (KEINE Herkunftspruefung):" >&2
  echo "  sh install-linux.sh --unsicher-nur-pruefsumme" >&2
}

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/ssh-sync-install.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

MANIFEST="$WORKDIR/manifest.json"
BUNDLE="$WORKDIR/manifest.json.sigstore.json"
SUMS="$WORKDIR/SHA256SUMS"
BIN="$WORKDIR/$ASSET"

echo "-> Lade Release-Artefakte von $RELEASE_BASE"
curl_fetch "$RELEASE_BASE/manifest.json" "$MANIFEST"
curl_fetch "$RELEASE_BASE/manifest.json.sigstore.json" "$BUNDLE"
curl_fetch "$RELEASE_BASE/SHA256SUMS" "$SUMS"
curl_fetch "$RELEASE_BASE/$ASSET" "$BIN"

if command -v cosign >/dev/null 2>&1; then
  echo "-> Pruefe Sigstore-Bundle mit cosign (GitHub Actions Identitaet)"
  if ! cosign verify-blob \
    --bundle "$BUNDLE" \
    --certificate-identity-regexp "$COSIGN_IDENTITY_REGEXP" \
    --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
    "$MANIFEST"; then
    echo "Sigstore-Verifikation fehlgeschlagen" >&2
    exit 1
  fi
  WANT_HASH="$(hash_from_manifest "$ASSET" "$MANIFEST")"
  if [ -z "$WANT_HASH" ]; then
    WANT_HASH="$(hash_from_sums "$ASSET" "$SUMS")"
  fi
  if [ -z "$WANT_HASH" ]; then
    echo "Hash fuer $ASSET fehlt in Manifest und SHA256SUMS" >&2
    exit 1
  fi
  GOT_HASH="$(file_sha256 "$BIN")"
  if [ "$GOT_HASH" != "$WANT_HASH" ]; then
    echo "SHA-256 stimmt nicht (got $GOT_HASH want $WANT_HASH)" >&2
    exit 1
  fi
elif [ "$UNSICHER_NUR_PRUEFSUMME" = "1" ]; then
  echo "WARNUNG: cosign fehlt. Nur SHA-256 gegen SHA256SUMS aus demselben Release." >&2
  echo "WARNUNG: Keine Herkunftspruefung (Sigstore/GitHub-Identitaet). Nur mit --unsicher-nur-pruefsumme." >&2
  echo "Repo-Referenz: $GITHUB_REPO" >&2
  WANT_HASH="$(hash_from_sums "$ASSET" "$SUMS")"
  if [ -z "$WANT_HASH" ]; then
    echo "Hash fuer $ASSET fehlt in SHA256SUMS" >&2
    exit 1
  fi
  GOT_HASH="$(file_sha256 "$BIN")"
  if [ "$GOT_HASH" != "$WANT_HASH" ]; then
    echo "SHA-256 stimmt nicht (got $GOT_HASH want $WANT_HASH)" >&2
    exit 1
  fi
else
  print_cosign_install_help
  exit 1
fi

SIZE="$(wc -c <"$BIN" | tr -d ' ')"
if [ "$SIZE" -lt 1024 ]; then
  echo "Download zu klein ($SIZE Bytes)" >&2
  exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl --user stop ssh-sync.service 2>/dev/null || true
fi

chmod +x "$BIN"
if ! mv "$BIN" "$DEST"; then
  echo "Konnte $DEST nicht schreiben." >&2
  exit 1
fi

if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
  echo "-> Hinweis: $INSTALL_DIR ist nicht in PATH"
fi

systemd_user() {
  systemctl --user "$@" 2>/dev/null
}

if [ "$os" = "linux" ] && command -v systemctl >/dev/null 2>&1; then
  mkdir -p "$SERVICE_DIR"
  cat >"$SERVICE_DIR/ssh-sync.service" <<UNIT
[Unit]
Description=ssh-sync Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$DEST daemon
Restart=on-failure
RestartSec=15

[Install]
WantedBy=default.target
UNIT
  if systemd_user daemon-reload && systemd_user enable ssh-sync.service; then
    echo "-> systemd user service installiert und aktiviert (start nach unlock)"
  else
    echo "-> Hinweis: systemd user service konnte nicht aktiviert werden."
  fi
elif [ "$os" = "linux" ]; then
  echo "-> systemd nicht gefunden  -  Daemon manuell: $DEST daemon"
else
  echo "-> macOS: Daemon manuell starten: $DEST daemon"
fi

echo ""
echo "Fertig. Naechste Schritte:"
echo "  1. Im Portal: $PORTAL_URL -> Geraete -> Config kopieren"
echo "  2. Nach ~/.config/ssh-sync/config.json"
echo "  3. $BIN_NAME unlock && systemctl --user start ssh-sync   # Linux mit systemd"
echo ""
echo "Updates: $BIN_NAME update   (Client prueft Sigstore-Manifest)"
`, base, base, defaultReleaseBase)
}

func windowsInstallScript(base string) string {
	return fmt.Sprintf(`# ssh-sync  -  Windows Installer (PowerShell)
# Empfohlen: Skript speichern, lesen, dann ausfuehren. Nicht: irm | iex
#   Invoke-WebRequest -Uri '%s/install/windows.ps1' -OutFile install-windows.ps1
#   notepad install-windows.ps1
#   powershell -File install-windows.ps1
# Optional ohne cosign (KEINE Herkunftspruefung):
#   powershell -File install-windows.ps1 -UnsicherNurPruefsumme
param(
  [switch]$UnsicherNurPruefsumme
)
$ErrorActionPreference = "Stop"
%s
$PortalUrl = if ($env:SSH_SYNC_URL) { $env:SSH_SYNC_URL } else { "%s" }
$ReleaseBase = if ($env:SSH_SYNC_RELEASE_URL) { $env:SSH_SYNC_RELEASE_URL } else { "%s" }
$AllowInsecure = $env:SSH_SYNC_ALLOW_INSECURE -eq "1"
# Identitaet: kanonisch internal/releaseverify/identity.go
$CosignOidcIssuer = "https://token.actions.githubusercontent.com"
$CosignIdentityRegexp = '^https://github\.com/thelad-dev/ssh-sync/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$'
$GithubRepo = "https://github.com/thelad-dev/ssh-sync"

function Assert-HttpsOrLoopback([string]$Url, [string]$Label) {
  if ($Url -match '^https://') { return }
  if ($Url -match '^http://(127\.0\.0\.1|localhost)(:|$)') { return }
  if ($Url -match '^http://') {
    if (-not $AllowInsecure) { throw "${Label}: http:// nur mit SSH_SYNC_ALLOW_INSECURE=1 oder Loopback" }
    return
  }
  throw "$Label muss https:// (oder Loopback-http) sein: $Url"
}

Assert-HttpsOrLoopback $PortalUrl "PORTAL_URL / SSH_SYNC_URL"
Assert-HttpsOrLoopback $ReleaseBase "RELEASE_BASE / SSH_SYNC_RELEASE_URL"

$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\ssh-sync"
$ZipPath = Join-Path $env:TEMP "ssh-sync-windows-amd64.zip"
$ExePath = Join-Path $InstallDir "ssh-sync.exe"
$Work = Join-Path $env:TEMP ("ssh-sync-install-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $Work | Out-Null

$Headers = @{}
if ($env:CF_ACCESS_CLIENT_ID) { $Headers["CF-Access-Client-Id"] = $env:CF_ACCESS_CLIENT_ID }
if ($env:CF_ACCESS_CLIENT_SECRET) { $Headers["CF-Access-Client-Secret"] = $env:CF_ACCESS_CLIENT_SECRET }

$Asset = "ssh-sync-windows-amd64.zip"
$Manifest = Join-Path $Work "manifest.json"
$Bundle = Join-Path $Work "manifest.json.sigstore.json"
$Sums = Join-Path $Work "SHA256SUMS"

Write-Host "-> Lade Release-Artefakte von $ReleaseBase"
Invoke-WebRequest -Uri "$ReleaseBase/manifest.json" -OutFile $Manifest -Headers $Headers
Invoke-WebRequest -Uri "$ReleaseBase/manifest.json.sigstore.json" -OutFile $Bundle -Headers $Headers
Invoke-WebRequest -Uri "$ReleaseBase/SHA256SUMS" -OutFile $Sums -Headers $Headers
Invoke-WebRequest -Uri "$ReleaseBase/$Asset" -OutFile $ZipPath -Headers $Headers

function Get-FileSha256([string]$Path) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  $bytes = [System.IO.File]::ReadAllBytes($Path)
  return (-join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }))
}

function Get-HashFromManifest([string]$AssetName, [string]$ManifestPath) {
  $json = Get-Content -Raw $ManifestPath
  if ($json -match [regex]::Escape('"' + $AssetName + '"') + '\s*:\s*"([0-9a-fA-F]{64})"') {
    return $Matches[1].ToLowerInvariant()
  }
  $rx = '"filename"\s*:\s*"' + [regex]::Escape($AssetName) + '"[\s\S]*?"sha256"\s*:\s*"([0-9a-fA-F]{64})"'
  if ($json -match $rx) {
    return $Matches[1].ToLowerInvariant()
  }
  $rx2 = '"sha256"\s*:\s*"([0-9a-fA-F]{64})"[\s\S]*?"filename"\s*:\s*"' + [regex]::Escape($AssetName) + '"'
  if ($json -match $rx2) {
    return $Matches[1].ToLowerInvariant()
  }
  return $null
}

function Get-HashFromSums([string]$AssetName, [string]$SumsPath) {
  foreach ($line in Get-Content $SumsPath) {
    if ($line -match '^([0-9a-fA-F]{64})\s+(\S+)$') {
      $name = $Matches[2].TrimStart('.', '/', '\')
      if ($name -eq $AssetName) { return $Matches[1].ToLowerInvariant() }
    }
  }
  return $null
}

$cosign = Get-Command cosign -ErrorAction SilentlyContinue
if ($null -ne $cosign) {
  Write-Host "-> Pruefe Sigstore-Bundle mit cosign (GitHub Actions Identitaet)"
  & cosign verify-blob --bundle $Bundle --certificate-identity-regexp $CosignIdentityRegexp --certificate-oidc-issuer $CosignOidcIssuer $Manifest
  if ($LASTEXITCODE -ne 0) { throw "Sigstore-Verifikation fehlgeschlagen" }
  $want = Get-HashFromManifest $Asset $Manifest
  if (-not $want) { $want = Get-HashFromSums $Asset $Sums }
  if (-not $want) { throw "Hash fuer $Asset fehlt in Manifest und SHA256SUMS" }
  $got = Get-FileSha256 $ZipPath
  if ($got -ne $want) { throw "SHA-256 stimmt nicht (got $got want $want)" }
} elseif ($UnsicherNurPruefsumme) {
  Write-Host "WARNUNG: cosign fehlt. Nur SHA-256 gegen SHA256SUMS. Keine Herkunftspruefung." -ForegroundColor Yellow
  Write-Host "Repo-Referenz: $GithubRepo" -ForegroundColor Yellow
  $want = Get-HashFromSums $Asset $Sums
  if (-not $want) { throw "Hash fuer $Asset fehlt in SHA256SUMS" }
  $got = Get-FileSha256 $ZipPath
  if ($got -ne $want) { throw "SHA-256 stimmt nicht (got $got want $want)" }
} else {
  Write-Host ""
  Write-Host "cosign fehlt. Herkunftspruefung (Sigstore) braucht cosign." -ForegroundColor Red
  Write-Host "Installation (Beispiele):"
  Write-Host "  winget install sigstore.cosign"
  Write-Host "  oder: https://docs.sigstore.dev/cosign/system_config/installation/"
  Write-Host ""
  Write-Host "Manuelle Pruefung:"
  Write-Host "  cosign verify-blob --bundle manifest.json.sigstore.json --certificate-identity-regexp '$CosignIdentityRegexp' --certificate-oidc-issuer $CosignOidcIssuer manifest.json"
  Write-Host ""
  Write-Host "Ohne cosign nur mit: powershell -File install-windows.ps1 -UnsicherNurPruefsumme"
  throw "cosign erforderlich (oder -UnsicherNurPruefsumme)"
}

Expand-Archive -Path $ZipPath -DestinationPath $InstallDir -Force
Remove-Item $ZipPath -Force
Remove-Item -Recurse -Force $Work

$Extracted = Join-Path $InstallDir "ssh-sync-windows-amd64.exe"
if (Test-Path $Extracted) {
  Move-Item -Force $Extracted $ExePath
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$InstallDir*") {
  [Environment]::SetEnvironmentVariable("Path", "$userPath;$InstallDir", "User")
  $env:Path = "$env:Path;$InstallDir"
}

$ServiceName = "ssh-sync"
Remove-LegacySshSyncTask
$serviceOk = Install-SshSyncWindowsService -ExePath $ExePath

Write-Host ""
Write-Host "Fertig. Binary: $ExePath"
Write-Host "Portal: $PortalUrl"
Write-Host "Updates: ssh-sync.exe update"
`, base, windowsServiceInstallHelper(), base, defaultReleaseBase)
}

func windowsServiceInstallScript(base string) string {
	return fmt.Sprintf(`# ssh-sync  -  Windows-Dienst installieren (nur Service, Binary muss existieren)
# PowerShell als Administrator:
#   powershell -File windows-service.ps1
$ErrorActionPreference = "Stop"
%s
$ExePath = Join-Path $env:LOCALAPPDATA "Programs\ssh-sync\ssh-sync.exe"
if (-not (Test-Path $ExePath)) {
  throw "ssh-sync.exe nicht gefunden unter $ExePath  -  zuerst Windows-Installer ausfuehren"
}

$null = Install-SshSyncWindowsService -ExePath $ExePath
Write-Host ""
Write-Host "Fertig. Naechste Schritte:"
Write-Host "  ssh-sync.exe unlock"
Write-Host "  ssh-sync.exe service start"
`, windowsServiceInstallHelper())
}

func windowsServiceInstallHelper() string {
	return `
function Remove-LegacySshSyncTask {
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'SilentlyContinue'
  Stop-ScheduledTask -TaskName 'ssh-sync' -ErrorAction SilentlyContinue | Out-Null
  cmd.exe /c 'schtasks /End /TN ssh-sync 2>nul' | Out-Null
  cmd.exe /c 'schtasks /Delete /TN ssh-sync /F 2>nul' | Out-Null
  $ErrorActionPreference = $prev
}

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal $id
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-SshSyncWindowsService {
  param([Parameter(Mandatory = $true)][string]$ExePath)

  $domainUser = "$env:USERDOMAIN\$env:USERNAME"

  if (-not (Test-IsAdmin)) {
    Write-Host "-> Dienst-Installation uebersprungen (keine Administrator-Rechte)" -ForegroundColor Yellow
    Write-Host "  Spaeter: ssh-sync.exe service install --user $domainUser"
    return $false
  }

  Write-Host "-> Windows-Dienst installieren (Konto: $domainUser)"
  Write-Host "  Anmeldedialog: Windows-Passwort fuer Dienst-Konto (nicht ssh-sync Master-Passwort)"

  $cred = Get-Credential -UserName $domainUser -Message "Windows-Passwort fuer ssh-sync Dienst"
  if ($null -eq $cred) {
    Write-Host "-> Abgebrochen" -ForegroundColor Yellow
    return $false
  }
  $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password)
  try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $plain | & $ExePath service install --user $domainUser --password-stdin
  } finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    $plain = $null
  }
  if ($LASTEXITCODE -eq 0) {
    Write-Host "-> Dienst ssh-sync installiert" -ForegroundColor Green
    return $true
  }

  Write-Host "-> Dienst-Installation fehlgeschlagen" -ForegroundColor Yellow
  Write-Host "  Manuell: ssh-sync.exe service repair --user $domainUser"
  return $false
}
`
}
