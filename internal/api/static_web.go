package api

import (
	"net/http"
	"strings"
)

const webCSP = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"

// WebFileServer liefert das Portal; JS/CSS/HTML ohne Browser-Cache (vermeidet veraltete Module).
func WebFileServer(webDir string) http.Handler {
	fs := http.FileServer(http.Dir(webDir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasSuffix(path, "_test.mjs") || strings.HasSuffix(path, "_test.js") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Security-Policy", webCSP)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		if path == "/" || strings.HasSuffix(path, ".html") || strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".css") {
			w.Header().Set("Cache-Control", "no-cache, must-revalidate")
		}
		fs.ServeHTTP(w, r)
	})
}
