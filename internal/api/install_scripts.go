package api

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/thelad-dev/ssh-sync/internal/releaseverify"
)

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

// LinuxInstallScript liefert den generierten Linux-Installer (POSIX sh).
func LinuxInstallScript(base string) string {
	pemBlock, pemErr := releaseverify.PublicKeyPEM()
	pemContent := ""
	if pemErr == nil {
		pemContent = pemBlock
	}
	return fmt.Sprintf(`#!/bin/sh
# ssh-sync  -  Linux Installer
# Empfohlen: Skript laden, lesen, Pruefsumme vergleichen, dann ausfuehren.
#   curl -fsSL '%s/install/linux.sh' -o install-linux.sh
#   less install-linux.sh
#   sh install-linux.sh
# Nicht empfohlen: curl | sh
set -eu

BASE_URL="${SSH_SYNC_URL:-%s}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
SERVICE_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
BIN_NAME="ssh-sync"
ALLOW_INSECURE="${SSH_SYNC_ALLOW_INSECURE:-0}"

case "$BASE_URL" in
  https://*) ;;
  http://127.0.0.1:*|http://127.0.0.1|http://localhost:*|http://localhost) ;;
  http://*)
    if [ "$ALLOW_INSECURE" != "1" ]; then
      echo "http:// nur mit SSH_SYNC_ALLOW_INSECURE=1 oder gegen Loopback." >&2
      exit 1
    fi
    ;;
  *)
    echo "BASE_URL muss https:// (oder Loopback-http) sein: $BASE_URL" >&2
    exit 1
    ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)  ASSET="ssh-sync-linux-amd64" ;;
  aarch64|arm64) ASSET="ssh-sync-linux-arm64" ;;
  *) echo "Nicht unterstuetzte Architektur: $arch" >&2; exit 1 ;;
esac

mkdir -p "$INSTALL_DIR"
DEST="$INSTALL_DIR/$BIN_NAME"

if ! touch "$INSTALL_DIR/.write-test" 2>/dev/null; then
  echo "Schreiben in $INSTALL_DIR nicht moeglich." >&2
  exit 1
fi
rm -f "$INSTALL_DIR/.write-test"

if ! command -v sha256sum >/dev/null 2>&1; then
  echo "sha256sum erforderlich" >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl erforderlich (Ed25519-Signaturpruefung)" >&2
  exit 1
fi

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

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/ssh-sync-install.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

PUB_PEM="$WORKDIR/release.pub"
MANIFEST="$WORKDIR/manifest.json"
SIG="$WORKDIR/manifest.sig"
BIN="$WORKDIR/$ASSET"
cat >"$PUB_PEM" <<'SSHPUB'
%s
SSHPUB

if ! grep -q "BEGIN PUBLIC KEY" "$PUB_PEM"; then
  echo "Kein Release-Public-Key im Installer eingebettet. Siehe docs/release-signing.md" >&2
  exit 1
fi

echo "-> Lade Manifest und Binary von $BASE_URL"
curl_fetch "$BASE_URL/downloads/manifest.json" "$MANIFEST"
curl_fetch "$BASE_URL/downloads/manifest.sig" "$SIG"
curl_fetch "$BASE_URL/downloads/$ASSET" "$BIN"

# Signatur ueber kanonisches Manifest: der Agent signiert CanonicalJSON.
# openssl prueft die Rohbytes der heruntergeladenen Datei nicht gegen CanonicalJSON.
# Deshalb normalisieren wir mit einem kleinen Hinweis: Signaturdatei gilt fuer
# die exakten Bytes von manifest.json wie veroeffentlicht (CanonicalJSON).
if ! openssl pkeyutl -verify -pubin -inkey "$PUB_PEM" -rawin -in "$MANIFEST" -sigfile "$SIG" >/dev/null 2>&1; then
  echo "Manifest-Signatur ungueltig" >&2
  exit 1
fi

WANT_HASH="$(sed -n "s/.*\"${ASSET}\":\"\\([0-9a-fA-F]\\{64\\}\\)\".*/\\1/p" "$MANIFEST" | tr 'A-F' 'a-f' | head -n1)"
if [ -z "$WANT_HASH" ]; then
  echo "Hash fuer $ASSET fehlt im Manifest" >&2
  exit 1
fi
GOT_HASH="$(sha256sum "$BIN" | awk '{print tolower($1)}')"
if [ "$GOT_HASH" != "$WANT_HASH" ]; then
  echo "SHA-256 stimmt nicht (got $GOT_HASH want $WANT_HASH)" >&2
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

if command -v systemctl >/dev/null 2>&1; then
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
else
  echo "-> systemd nicht gefunden  -  Daemon manuell: $DEST daemon"
fi

echo ""
echo "Fertig. Naechste Schritte:"
echo "  1. Im Portal: $BASE_URL -> Geraete -> Config kopieren"
echo "  2. Nach ~/.config/ssh-sync/config.json"
echo "  3. $BIN_NAME unlock && systemctl --user start ssh-sync"
echo ""
echo "Updates: $BIN_NAME update   (prueft Signatur und SHA-256)"
`, base, base, pemContent)
}

func windowsInstallScript(base string) string {
	pemBlock, _ := releaseverify.PublicKeyPEM()
	pemEscaped := strings.ReplaceAll(pemBlock, "'", "''")
	return fmt.Sprintf(`# ssh-sync  -  Windows Installer (PowerShell)
# Empfohlen: Skript speichern, lesen, dann ausfuehren. Nicht: irm | iex
#   Invoke-WebRequest -Uri '%s/install/windows.ps1' -OutFile install-windows.ps1
#   notepad install-windows.ps1
#   powershell -File install-windows.ps1
$ErrorActionPreference = "Stop"
%s
$BaseUrl = if ($env:SSH_SYNC_URL) { $env:SSH_SYNC_URL } else { "%s" }
$AllowInsecure = $env:SSH_SYNC_ALLOW_INSECURE -eq "1"
if ($BaseUrl -notmatch '^https://' -and $BaseUrl -notmatch '^http://(127\.0\.0\.1|localhost)(:|$)') {
  if (-not $AllowInsecure) { throw "http:// nur mit SSH_SYNC_ALLOW_INSECURE=1 oder Loopback" }
}
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\ssh-sync"
$ZipPath = Join-Path $env:TEMP "ssh-sync-windows-amd64.zip"
$ExePath = Join-Path $InstallDir "ssh-sync.exe"
$Work = Join-Path $env:TEMP ("ssh-sync-install-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $Work | Out-Null

$Headers = @{}
if ($env:CF_ACCESS_CLIENT_ID) { $Headers["CF-Access-Client-Id"] = $env:CF_ACCESS_CLIENT_ID }
if ($env:CF_ACCESS_CLIENT_SECRET) { $Headers["CF-Access-Client-Secret"] = $env:CF_ACCESS_CLIENT_SECRET }

$Manifest = Join-Path $Work "manifest.json"
$Sig = Join-Path $Work "manifest.sig"
$Pub = Join-Path $Work "release.pub"
Set-Content -Path $Pub -Value @'
%s
'@ -Encoding ascii

if (-not (Select-String -Path $Pub -Pattern "BEGIN PUBLIC KEY" -Quiet)) {
  throw "Kein Release-Public-Key im Installer. Siehe docs/release-signing.md"
}

Write-Host "-> Lade Manifest und Zip von $BaseUrl"
Invoke-WebRequest -Uri "$BaseUrl/downloads/manifest.json" -OutFile $Manifest -Headers $Headers
Invoke-WebRequest -Uri "$BaseUrl/downloads/manifest.sig" -OutFile $Sig -Headers $Headers
Invoke-WebRequest -Uri "$BaseUrl/downloads/ssh-sync-windows-amd64.zip" -OutFile $ZipPath -Headers $Headers

$verify = & openssl pkeyutl -verify -pubin -inkey $Pub -rawin -in $Manifest -sigfile $Sig 2>&1
if ($LASTEXITCODE -ne 0) { throw "Manifest-Signatur ungueltig: $verify" }

$asset = "ssh-sync-windows-amd64.zip"
$json = Get-Content -Raw $Manifest
if ($json -notmatch '"ssh-sync-windows-amd64\.zip"\s*:\s*"([0-9a-fA-F]{64})"') {
  throw "Hash fuer Zip fehlt im Manifest"
}
$want = $Matches[1].ToLowerInvariant()
$sha = [System.Security.Cryptography.SHA256]::Create()
$bytes = [System.IO.File]::ReadAllBytes($ZipPath)
$got = -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") })
if ($got -ne $want) { throw "SHA-256 stimmt nicht" }

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
Write-Host "Updates: ssh-sync.exe update"
`, base, windowsServiceInstallHelper(), base, pemEscaped)
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
