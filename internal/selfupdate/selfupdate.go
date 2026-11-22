package selfupdate

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/releaseverify"
	"github.com/thelad-dev/ssh-sync/internal/version"
)

// AssetName liefert den Download-Dateinamen fuer die aktuelle Plattform.
func AssetName() (string, error) {
	switch runtime.GOOS {
	case "linux":
		switch runtime.GOARCH {
		case "amd64":
			return "ssh-sync-linux-amd64", nil
		case "arm64":
			return "ssh-sync-linux-arm64", nil
		}
	case "windows":
		if runtime.GOARCH == "amd64" {
			return "ssh-sync-windows-amd64.exe", nil
		}
	case "darwin":
		switch runtime.GOARCH {
		case "amd64":
			return "ssh-sync-darwin-amd64", nil
		case "arm64":
			return "ssh-sync-darwin-arm64", nil
		}
	}
	return "", fmt.Errorf("kein Binary fuer %s/%s", runtime.GOOS, runtime.GOARCH)
}

type Options struct {
	ServerURL          string
	AccessClientID     string
	AccessClientSecret string
	DestPath           string // leer = aktuelles Executable
	Insecure           bool   // erlaubt http:// ausserhalb Loopback
	AllowDowngrade     bool
	CurrentVersion     string // leer = version.Agent
	HTTPClient         *http.Client
	// verifyManifest overrides Sigstore verification (tests in this package only).
	verifyManifest func(manifestBytes, bundleBytes []byte, currentVersion string, allowDowngrade bool) (*releaseverify.Manifest, error)
}

type Result struct {
	Asset      string
	DestPath   string
	Bytes      int64
	Version    string
	RolledBack bool
}

func Apply(opts Options) (*Result, error) {
	if strings.TrimSpace(opts.ServerURL) == "" {
		return nil, fmt.Errorf("Server-URL fehlt")
	}
	if err := releaseverify.CheckServerURL(opts.ServerURL, opts.Insecure); err != nil {
		return nil, err
	}
	asset, err := AssetName()
	if err != nil {
		return nil, err
	}

	dest, err := ResolveDestPath(opts.DestPath)
	if err != nil {
		return nil, err
	}

	cur := opts.CurrentVersion
	if cur == "" {
		cur = version.Agent
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 5 * time.Minute,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	base := strings.TrimRight(opts.ServerURL, "/")
	manifestBytes, err := fetchBytes(client, opts, base+"/downloads/"+releaseverify.ManifestName)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	bundleBytes, err := fetchBytes(client, opts, base+"/downloads/"+releaseverify.BundleName)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", releaseverify.BundleName, err)
	}

	verifyFn := opts.verifyManifest
	if verifyFn == nil {
		verifyFn = func(manifestBytes, bundleBytes []byte, currentVersion string, allowDowngrade bool) (*releaseverify.Manifest, error) {
			return releaseverify.VerifyManifestBundle(manifestBytes, bundleBytes, releaseverify.VerifyOpts{
				CurrentVersion: currentVersion,
				AllowDowngrade: allowDowngrade,
			})
		}
	}
	manifest, err := verifyFn(manifestBytes, bundleBytes, cur, opts.AllowDowngrade)
	if err != nil {
		return nil, err
	}

	destDir := filepath.Dir(dest)
	tmp, err := downloadAsset(client, opts, base, asset, destDir)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp)

	if err := releaseverify.VerifyAssetHash(manifest, asset, tmp); err != nil {
		return nil, err
	}

	info, err := os.Stat(tmp)
	if err != nil {
		return nil, err
	}
	if info.Size() < 1024 {
		return nil, fmt.Errorf("Download zu klein (%d Bytes)  -  evtl. HTML/Fehlerseite", info.Size())
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmp, 0o755); err != nil {
			return nil, err
		}
	}

	backup, err := replaceKeepBackup(dest, tmp)
	if err != nil {
		return nil, err
	}

	// Nach dem Ersetzen Hash der Zieldatei erneut pruefen; bei Fehler Rollback.
	if err := releaseverify.VerifyAssetHash(manifest, asset, dest); err != nil {
		if backup != "" {
			_ = restoreBackup(dest, backup)
			return &Result{Asset: asset, DestPath: dest, Bytes: info.Size(), Version: manifest.Version, RolledBack: true}, fmt.Errorf("Nachpruefung fehlgeschlagen, Rollback: %w", err)
		}
		return nil, err
	}
	if backup != "" {
		_ = os.Remove(backup)
	}

	return &Result{Asset: asset, DestPath: dest, Bytes: info.Size(), Version: manifest.Version}, nil
}

func fetchBytes(client *http.Client, opts Options, url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	setAccessHeaders(req, opts)
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, res.Status)
	}
	return io.ReadAll(res.Body)
}

func downloadAsset(client *http.Client, opts Options, base, asset, destDir string) (string, error) {
	url := base + "/downloads/" + asset
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	setAccessHeaders(req, opts)
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Download %s: %s", url, res.Status)
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(destDir, ".ssh-sync-update-*")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	if _, err := io.Copy(tmp, res.Body); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return "", err
	}
	return tmpPath, nil
}

func setAccessHeaders(req *http.Request, opts Options) {
	if opts.AccessClientID != "" && opts.AccessClientSecret != "" {
		req.Header.Set("CF-Access-Client-Id", opts.AccessClientID)
		req.Header.Set("CF-Access-Client-Secret", opts.AccessClientSecret)
	}
}

// replaceKeepBackup replaces dest with src and returns the backup path (dest+".old") if an old file existed.
func replaceKeepBackup(dest, src string) (backup string, err error) {
	if runtime.GOOS == "windows" {
		return replaceWindowsKeep(dest, src)
	}
	return replaceUnixKeep(dest, src)
}

func replaceWindowsKeep(dest, src string) (string, error) {
	backup := dest + ".old"
	_ = os.Remove(backup)
	hadOld := false
	if _, err := os.Stat(dest); err == nil {
		hadOld = true
		if err := os.Rename(dest, backup); err != nil {
			return "", fmt.Errorf("altes Binary nicht ersetzbar (Dienst stoppen?): %w", err)
		}
	}
	if err := os.Rename(src, dest); err != nil {
		if hadOld {
			_ = os.Rename(backup, dest)
		}
		return "", err
	}
	if hadOld {
		return backup, nil
	}
	return "", nil
}

func replaceUnixKeep(dest, src string) (string, error) {
	destDir := filepath.Clean(filepath.Dir(dest))
	if filepath.Clean(filepath.Dir(src)) != destDir {
		staged := filepath.Join(destDir, filepath.Base(src)+".staging")
		if err := os.Rename(src, staged); err != nil {
			if err := copyFile(staged, src); err != nil {
				return "", fmt.Errorf("staging: %w", err)
			}
			_ = os.Remove(src)
		}
		src = staged
	}

	backup := dest + ".old"
	_ = os.Remove(backup)
	hadOld := false
	if _, err := os.Stat(dest); err == nil {
		hadOld = true
		if err := os.Rename(dest, backup); err != nil {
			return "", fmt.Errorf("altes Binary umbenennen: %w (ssh-sync stoppen?)", err)
		}
	}
	if err := os.Rename(src, dest); err != nil {
		if hadOld {
			_ = os.Rename(backup, dest)
		}
		return "", err
	}
	if err := os.Chmod(dest, 0o755); err != nil {
		return "", err
	}
	if hadOld {
		return backup, nil
	}
	return "", nil
}

func restoreBackup(dest, backup string) error {
	_ = os.Remove(dest)
	return os.Rename(backup, dest)
}

// replaceUnix is kept for existing unit tests.
func replaceUnix(dest, src string) error {
	backup, err := replaceUnixKeep(dest, src)
	if err != nil {
		return err
	}
	if backup != "" {
		_ = os.Remove(backup)
	}
	return nil
}

func copyFile(dest, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
