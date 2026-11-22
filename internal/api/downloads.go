package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type DownloadInfo struct {
	File        string `json:"file"`
	Label       string `json:"label"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Size        int64  `json:"size"`
	DownloadURL string `json:"download_url"`
	Preferred   bool   `json:"preferred,omitempty"`
	Hint        string `json:"hint,omitempty"`
}

var downloadLabels = map[string]DownloadInfo{
	"ssh-sync-linux-amd64":       {Label: "Linux (64-bit Intel/AMD)", OS: "linux", Arch: "amd64", Preferred: true},
	"ssh-sync-linux-arm64":         {Label: "Linux (64-bit ARM)", OS: "linux", Arch: "arm64", Preferred: true},
	"ssh-sync-windows-amd64.exe":   {Label: "Windows (64-bit, .exe)", OS: "windows", Arch: "amd64"},
	"ssh-sync-windows-amd64.zip":   {Label: "Windows (64-bit, .zip)", OS: "windows", Arch: "amd64", Preferred: true, Hint: "Empfohlen für Chrome"},
	"ssh-sync-darwin-amd64":        {Label: "macOS (Intel)", OS: "darwin", Arch: "amd64", Preferred: true},
	"ssh-sync-darwin-arm64":        {Label: "macOS (Apple Silicon)", OS: "darwin", Arch: "arm64", Preferred: true},
}

// DownloadsHandler bedient /api/downloads und /downloads/{datei}.
func DownloadsHandler(dir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/downloads" {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			listDownloads(w, r, dir)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/downloads/")
		if name == "" || strings.Contains(name, "/") || strings.Contains(name, "..") {
			http.NotFound(w, r)
			return
		}
		if name == "manifest.json" || name == "manifest.sig" {
			serveDownloadFile(w, r, dir, name)
			return
		}
		if _, ok := downloadLabels[name]; !ok {
			http.NotFound(w, r)
			return
		}
		serveDownloadFile(w, r, dir, name)
	})
}

func serveDownloadFile(w http.ResponseWriter, r *http.Request, dir, name string) {
	path := filepath.Join(dir, name)
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", contentTypeFor(name))
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-cache")

	if r.Method == http.MethodHead {
		return
	}
	http.ServeFile(w, r, path)
}

func contentTypeFor(name string) string {
	switch {
	case name == "manifest.json":
		return "application/json"
	case name == "manifest.sig":
		return "application/octet-stream"
	case strings.HasSuffix(name, ".zip"):
		return "application/zip"
	case strings.HasSuffix(name, ".exe"):
		return "application/vnd.microsoft.portable-executable"
	default:
		return "application/octet-stream"
	}
}

func listDownloads(w http.ResponseWriter, r *http.Request, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		writeJSON(w, http.StatusOK, []DownloadInfo{})
		return
	}
	var out []DownloadInfo
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		meta, ok := downloadLabels[e.Name()]
		if !ok {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		meta.File = e.Name()
		meta.Size = info.Size()
		meta.DownloadURL = "/downloads/" + e.Name()
		out = append(out, meta)
	}
	if out == nil {
		out = []DownloadInfo{}
	}
	writeJSON(w, http.StatusOK, out)
}

func ResolveDownloadsDir(webDir, explicit string) string {
	if explicit != "" {
		return explicit
	}
	candidates := []string{
		filepath.Join(webDir, "..", "downloads"),
		"downloads",
		"/app/downloads",
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return filepath.Join(webDir, "..", "downloads")
}
