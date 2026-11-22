package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/api"
	"github.com/thelad-dev/ssh-sync/internal/auth"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	dbPath := flag.String("db", "data/ssh-sync.db", "SQLite database path")
	webDir := flag.String("web", "web", "static web root")
	downloadsDir := flag.String("downloads", "", "Agent-Binaries (Standard: ../downloads oder /app/downloads)")
	flag.Parse()

	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o755); err != nil {
		log.Fatal(err)
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	secret, err := auth.JWTSecret(filepath.Dir(*dbPath))
	if err != nil {
		log.Fatal(err)
	}

	if strings.TrimSpace(os.Getenv("SSH_SYNC_SETUP_TOKEN")) == "" {
		log.Print("Hinweis: SSH_SYNC_SETUP_TOKEN ist nicht gesetzt  -  Ersteinrichtung ist ohne Token moeglich (N15)")
	}

	srv := api.NewServer(st, secret)
	dlDir := api.ResolveDownloadsDir(*webDir, *downloadsDir)
	if err := os.MkdirAll(dlDir, 0o755); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/", srv.Handler())
	mux.Handle("/api/downloads", api.DownloadsHandler(dlDir))
	mux.Handle("/downloads/", api.DownloadsHandler(dlDir))
	mux.Handle("/install/", api.InstallScriptsHandler())
	mux.Handle("/", api.WebFileServer(*webDir))

	server := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("ssh-sync API auf %s (DB: %s)", *addr, *dbPath)
	log.Fatal(server.ListenAndServe())
}
