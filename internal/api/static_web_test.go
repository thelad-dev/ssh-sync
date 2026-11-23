package api

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestWebFileServerSetsCSP(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html></html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(WebFileServer(dir))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("unexpected CSP: %q", csp)
	}
	if strings.Contains(csp, "script-src") && strings.Contains(csp, "unsafe-inline") {
		// style-src darf unsafe-inline haben; script-src nicht.
		scriptPart := csp
		if i := strings.Index(csp, "script-src"); i >= 0 {
			scriptPart = csp[i:]
			if j := strings.Index(scriptPart, ";"); j >= 0 {
				scriptPart = scriptPart[:j]
			}
		}
		if strings.Contains(scriptPart, "unsafe-inline") {
			t.Fatalf("script-src must not allow unsafe-inline: %q", csp)
		}
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing X-Content-Type-Options")
	}
	if resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("missing Referrer-Policy")
	}
}

func TestWebFileServerImportmapHashMatchesCSP(t *testing.T) {
	webDir := repoWebDir(t)
	ts := httptest.NewServer(WebFileServer(webDir))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	csp := resp.Header.Get("Content-Security-Policy")
	assertInlineScriptsCoveredByCSP(t, body, csp)
	assertInlineStylesCoveredByCSP(t, body, csp)

	importmapBody := extractImportmapBody(t, body)
	sum := sha256.Sum256(importmapBody)
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if !strings.Contains(csp, want) {
		t.Fatalf("CSP missing importmap hash %s\nCSP: %s", want, csp)
	}
}

func TestWebFileServerInlineScriptHashTracksContent(t *testing.T) {
	dir := t.TempDir()
	html := `<!DOCTYPE html><html><body>
<script type="importmap">
{"imports":{"x":"./x.js"}}
</script>
<script type="module" src="app.js"></script>
</body></html>`
	path := filepath.Join(dir, "index.html")
	if err := os.WriteFile(path, []byte(html), 0o644); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(WebFileServer(dir))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	assertInlineScriptsCoveredByCSP(t, body, resp.Header.Get("Content-Security-Policy"))
}

func repoWebDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Join(filepath.Dir(file), "..", "..", "web")
	if _, err := os.Stat(filepath.Join(dir, "index.html")); err != nil {
		t.Fatalf("web/index.html not found at %s: %v", dir, err)
	}
	return dir
}

func extractImportmapBody(t *testing.T, html []byte) []byte {
	t.Helper()
	re := regexp.MustCompile(`(?is)<script\b[^>]*type=["']importmap["'][^>]*>(.*?)</script>`)
	m := re.FindSubmatch(html)
	if m == nil {
		t.Fatal("no importmap script in HTML")
	}
	return m[1]
}

func assertInlineScriptsCoveredByCSP(t *testing.T, html []byte, csp string) {
	t.Helper()
	scriptPart := cspDirective(csp, "script-src")
	if strings.Contains(scriptPart, "unsafe-inline") {
		t.Fatalf("script-src must not use unsafe-inline: %q", scriptPart)
	}
	re := regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`)
	srcAttr := regexp.MustCompile(`(?i)\bsrc\s*=`)
	matches := re.FindAllSubmatch(html, -1)
	var inlineCount int
	for _, m := range matches {
		if srcAttr.Match(m[1]) {
			continue
		}
		inlineCount++
		sum := sha256.Sum256(m[2])
		token := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		if !strings.Contains(scriptPart, token) {
			t.Fatalf("inline script hash %s missing from script-src %q", token, scriptPart)
		}
	}
	if inlineCount == 0 {
		t.Fatal("expected at least one inline script")
	}
}

func assertInlineStylesCoveredByCSP(t *testing.T, html []byte, csp string) {
	t.Helper()
	stylePart := cspDirective(csp, "style-src")
	re := regexp.MustCompile(`(?is)<style\b([^>]*)>(.*?)</style>`)
	matches := re.FindAllSubmatch(html, -1)
	if len(matches) == 0 {
		return
	}
	if strings.Contains(stylePart, "unsafe-inline") {
		return
	}
	for _, m := range matches {
		sum := sha256.Sum256(m[2])
		token := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		if !strings.Contains(stylePart, token) {
			t.Fatalf("inline style hash %s missing from style-src %q", token, stylePart)
		}
	}
}

func cspDirective(csp, name string) string {
	for _, part := range strings.Split(csp, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, name) {
			return part
		}
	}
	return ""
}
