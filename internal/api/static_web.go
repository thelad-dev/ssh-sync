package api

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// webCSPFmt: %s nimmt die zusaetzlichen script-src-Hashes auf (inkl. Leerzeichen-Prefix).
const webCSPFmt = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'%s; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"

var (
	inlineScriptTag = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`)
	scriptSrcAttr   = regexp.MustCompile(`(?i)\bsrc\s*=`)
)

// WebFileServer liefert das Portal; JS/CSS/HTML ohne Browser-Cache (vermeidet veraltete Module).
func WebFileServer(webDir string) http.Handler {
	fs := http.FileServer(http.Dir(webDir))
	indexPath := filepath.Join(webDir, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasSuffix(path, "_test.mjs") || strings.HasSuffix(path, "_test.js") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Security-Policy", buildWebCSP(indexPath))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		if path == "/" || strings.HasSuffix(path, ".html") || strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".css") {
			w.Header().Set("Cache-Control", "no-cache, must-revalidate")
		}
		fs.ServeHTTP(w, r)
	})
}

func buildWebCSP(indexPath string) string {
	return fmt.Sprintf(webCSPFmt, scriptSrcHashSuffix(indexPath))
}

func scriptSrcHashSuffix(indexPath string) string {
	hashes := inlineElementHashes(indexPath, inlineScriptTag, true)
	if len(hashes) == 0 {
		return ""
	}
	var b strings.Builder
	for _, h := range hashes {
		b.WriteString(" 'sha256-")
		b.WriteString(h)
		b.WriteByte('\'')
	}
	return b.String()
}

// inlineElementHashes liest indexPath und liefert Base64-SHA-256 der Inline-Tag-Inhalte.
// skipExternal: Script-Tags mit src-Attribut ueberspringen.
func inlineElementHashes(indexPath string, tagRE *regexp.Regexp, skipExternal bool) []string {
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return nil
	}
	matches := tagRE.FindAllSubmatch(data, -1)
	var out []string
	for _, m := range matches {
		if skipExternal && scriptSrcAttr.Match(m[1]) {
			continue
		}
		sum := sha256.Sum256(m[2])
		out = append(out, base64.StdEncoding.EncodeToString(sum[:]))
	}
	return out
}
