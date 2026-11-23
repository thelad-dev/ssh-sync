package sshconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/store"
)

const (
	managedBegin = "# --- BEGIN ssh-sync (managed) ---"
	managedEnd   = "# --- END ssh-sync (managed) ---"
	ManagedBegin = managedBegin
	ManagedEnd   = managedEnd

	keyConflictSuffix = ".ssh-sync"
	configBakPrefix   = "config.ssh-sync-bak-"
	configBakKeep     = 10
)

// ApplyOptions steuert Trockenlauf und den ersten Schreibvorgang.
type ApplyOptions struct {
	// DryRun plant Aenderungen ohne Dateien zu schreiben.
	DryRun bool
	// AllowFirstWrite erlaubt Schreiben, wenn noch kein managed Block existiert.
	// Fehlt das Flag und es gibt keinen Block, wird nur geplant (NeedsConfirm).
	AllowFirstWrite bool
}

type WriteResult struct {
	ConfigPath        string
	KeyPaths          []string
	BackupPath        string // letzte zeitgestempelte Sicherung, falls geschrieben
	Warnings          []string
	Plans             []string // geplante bzw. ausgefuehrte Aktionen
	SkippedIdentities []string // z.B. "id_ed25519-git (Passphrase)"
	DryRun            bool
	NeedsConfirm      bool // true: erster Lauf ohne AllowFirstWrite, nichts geschrieben
}

// HasManagedBlock meldet, ob ~/.ssh/config schon den verwalteten Block enthaelt.
func HasManagedBlock(sshDir string) bool {
	data, err := os.ReadFile(filepath.Join(sshDir, "config"))
	if err != nil {
		return false
	}
	s := string(data)
	return strings.Contains(s, managedBegin) && strings.Contains(s, managedEnd)
}

// Apply schreibt Keys sicher und merged den managed Block in die vorhandene ssh config.
func Apply(sshDir string, bundle *store.SyncBundle, decryptedKeys map[string][]byte, opts ApplyOptions) (*WriteResult, error) {
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return nil, err
	}

	for _, id := range bundle.Identities {
		if err := ValidateKeyBasename(id.Name); err != nil {
			return nil, err
		}
	}

	first := !HasManagedBlock(sshDir)
	dry := opts.DryRun || (first && !opts.AllowFirstWrite)

	result := &WriteResult{
		ConfigPath:   filepath.Join(sshDir, "config"),
		DryRun:       dry,
		NeedsConfirm: first && !opts.AllowFirstWrite,
	}

	identityFiles := map[string]string{}
	var keyPaths []string
	var skipped []string

	for _, id := range bundle.Identities {
		plain, ok := decryptedKeys[id.ID]
		if !ok {
			return nil, fmt.Errorf("entschlüsselter Key für Identity %q fehlt", id.Name)
		}
		filename := KeyFileBasename(id.Name)
		decision, err := planPrivateKey(sshDir, filename, plain)
		if err != nil {
			return nil, fmt.Errorf("identity %q: %w", id.Name, err)
		}
		result.Warnings = append(result.Warnings, decision.Warnings...)
		result.Plans = append(result.Plans, decision.Plan)
		if decision.Skipped {
			label := id.Name
			if decision.SkipReason != "" {
				label = id.Name + " (" + decision.SkipReason + ")"
			}
			skipped = append(skipped, label)
		}
		if decision.Path == "" {
			continue
		}
		if !dry && decision.Write {
			if err := writePrivateKey(decision.Path, plain); err != nil {
				return nil, fmt.Errorf("identity %q schreiben: %w", id.Name, err)
			}
		}
		identityFiles[id.ID] = decision.Path
		keyPaths = append(keyPaths, decision.Path)
	}
	result.KeyPaths = keyPaths
	result.SkippedIdentities = skipped
	if n := len(skipped); n > 0 {
		word := "Identity"
		if n != 1 {
			word = "Identities"
		}
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"%d %s uebersprungen: %s", n, word, strings.Join(skipped, ", "),
		))
	}

	block := renderConfigBlock(bundle, identityFiles)
	configPath := result.ConfigPath
	existing := ""
	if data, err := os.ReadFile(configPath); err == nil {
		existing = string(data)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	merged := spliceManagedBlock(existing, block)
	configChanged := merged != existing
	if configChanged {
		result.Plans = append(result.Plans, fmt.Sprintf("config: managed Block einfuegen/ersetzen (Host local und sonstige lokale Eintraege bleiben)"))
	} else {
		result.Plans = append(result.Plans, "config: unveraendert")
	}

	if !dry && configChanged {
		bak, err := writeTimestampedConfigBackup(configPath, existing)
		if err != nil {
			return nil, err
		}
		result.BackupPath = bak
		if err := pruneConfigBackups(filepath.Dir(configPath), configBakKeep); err != nil {
			return nil, err
		}
		if err := os.WriteFile(configPath, []byte(merged), 0o600); err != nil {
			return nil, err
		}
		if err := chmodPrivate(configPath); err != nil {
			return nil, err
		}
	}

	return result, nil
}

type keyDecision struct {
	Path       string
	Write      bool
	Plan       string
	Warnings   []string
	Skipped    bool
	SkipReason string // z.B. "Passphrase", "unlesbar"
}

func planPrivateKey(sshDir, basename string, serverPEM []byte) (*keyDecision, error) {
	serverFP, protected, err := inspectPrivateKey(serverPEM)
	if err != nil {
		reason := "unlesbar"
		if protected {
			reason = "Passphrase"
		}
		return &keyDecision{
			Plan:       fmt.Sprintf("key %s: uebersprungen (%s)", basename, reason),
			Warnings:   []string{fmt.Sprintf("WARNUNG: Identity %s uebersprungen (%s): %v", basename, reason, err)},
			Skipped:    true,
			SkipReason: reason,
		}, nil
	}
	if protected {
		return planPassphraseProtectedKey(sshDir, basename, serverFP)
	}

	primary := filepath.Join(sshDir, basename)
	alternate := primary + keyConflictSuffix

	dec := &keyDecision{}

	if _, err := os.Stat(primary); os.IsNotExist(err) {
		dec.Path = primary
		dec.Write = true
		dec.Plan = fmt.Sprintf("key %s: neu anlegen (fp %s)", basename, serverFP)
		return dec, nil
	} else if err != nil {
		return nil, err
	}

	warnPubMismatch(primary, &dec.Warnings)

	existingFP, err := filePrivateKeyFingerprint(primary)
	if err == nil && existingFP == serverFP {
		dec.Path = primary
		dec.Write = false
		dec.Plan = fmt.Sprintf("key %s: unveraendert (gleicher Fingerabdruck %s)", basename, serverFP)
		return dec, nil
	}

	msg := fmt.Sprintf(
		"WARNUNG: vorhandener Private Key %s weicht ab (lokal %s, server %s) - nicht ueberschrieben",
		primary, fpOrErr(existingFP, err), serverFP,
	)
	dec.Warnings = append(dec.Warnings, msg)

	if _, err := os.Stat(alternate); os.IsNotExist(err) {
		dec.Path = alternate
		dec.Write = true
		dec.Plan = fmt.Sprintf("key %s: Kollision -> schreibe %s (fp %s)", basename, filepath.Base(alternate), serverFP)
		return dec, nil
	} else if err != nil {
		return nil, err
	}

	warnPubMismatch(alternate, &dec.Warnings)

	altFP, altErr := filePrivateKeyFingerprint(alternate)
	if altErr == nil && altFP == serverFP {
		dec.Path = alternate
		dec.Write = false
		dec.Plan = fmt.Sprintf("key %s: Ausweichdatei %s schon passend (fp %s)", basename, filepath.Base(alternate), serverFP)
		return dec, nil
	}

	dec.Warnings = append(dec.Warnings, fmt.Sprintf(
		"WARNUNG: Ausweichdatei %s weicht ebenfalls ab (lokal %s, server %s) - nicht ueberschrieben, IdentityFile ausgelassen",
		alternate, fpOrErr(altFP, altErr), serverFP,
	))
	dec.Plan = fmt.Sprintf("key %s: uebersprungen (Kollision an %s und %s)", basename, basename, filepath.Base(alternate))
	dec.Path = ""
	dec.Write = false
	dec.Skipped = true
	dec.SkipReason = "Kollision"
	return dec, nil
}

// planPassphraseProtectedKey schreibt die Server-PEM nie; lokaler Key bleibt unberuehrt.
// Bei gleichem Fingerabdruck bleibt IdentityFile auf der lokalen Datei.
func planPassphraseProtectedKey(sshDir, basename, serverFP string) (*keyDecision, error) {
	primary := filepath.Join(sshDir, basename)
	dec := &keyDecision{SkipReason: "Passphrase"}

	if _, err := os.Stat(primary); os.IsNotExist(err) {
		dec.Skipped = true
		dec.Plan = fmt.Sprintf("key %s: uebersprungen (Passphrase)", basename)
		dec.Warnings = []string{fmt.Sprintf(
			"WARNUNG: Identity %s passphrase-geschuetzt - nicht geschrieben (lokal fehlt)", basename,
		)}
		return dec, nil
	} else if err != nil {
		return nil, err
	}

	warnPubMismatch(primary, &dec.Warnings)

	existingFP, err := filePrivateKeyFingerprint(primary)
	if err == nil && existingFP == serverFP {
		dec.Path = primary
		dec.Write = false
		dec.SkipReason = ""
		dec.Plan = fmt.Sprintf(
			"key %s: unveraendert (Passphrase-Server-Key, gleicher Fingerabdruck %s)", basename, serverFP,
		)
		return dec, nil
	}

	dec.Skipped = true
	dec.Path = ""
	dec.Write = false
	dec.Plan = fmt.Sprintf("key %s: uebersprungen (Passphrase)", basename)
	dec.Warnings = append(dec.Warnings, fmt.Sprintf(
		"WARNUNG: Identity %s passphrase-geschuetzt - lokal unberuehrt (%s), nicht geschrieben",
		basename, fpOrErr(existingFP, err),
	))
	return dec, nil
}

func fpOrErr(fp string, err error) string {
	if err != nil {
		return "unlesbar:" + err.Error()
	}
	return fp
}

func writePrivateKey(path string, data []byte) error {
	data = ensureTrailingNewline(data)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return chmodPrivate(path)
}

func chmodPrivate(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	return os.Chmod(path, 0o600)
}

func renderConfigBlock(bundle *store.SyncBundle, identityFiles map[string]string) string {
	hostOrder := orderedHosts(bundle)
	var b strings.Builder
	b.WriteString(managedBegin)
	b.WriteString("\n")
	b.WriteString("# Nicht manuell bearbeiten - wird vom ssh-sync Agent ueberschrieben.\n")
	for _, h := range hostOrder {
		if err := ValidateHost(h); err != nil {
			continue
		}
		extra, err := NormalizeExtra(h.Extra)
		if err != nil {
			continue
		}
		b.WriteString("\nHost ")
		b.WriteString(h.Alias)
		b.WriteString("\n")
		b.WriteString("  HostName ")
		b.WriteString(h.HostName)
		b.WriteString("\n")
		if h.Port != 0 && h.Port != 22 {
			b.WriteString(fmt.Sprintf("  Port %d\n", h.Port))
		}
		if h.User != "" {
			b.WriteString("  User ")
			b.WriteString(h.User)
			b.WriteString("\n")
		}
		if h.IdentityID != nil {
			if p, ok := identityFiles[*h.IdentityID]; ok {
				b.WriteString("  IdentityFile ")
				b.WriteString(filepath.ToSlash(p))
				b.WriteString("\n")
			}
		}
		if h.IdentitiesOnly {
			b.WriteString("  IdentitiesOnly yes\n")
		}
		if h.ProxyJump != "" {
			b.WriteString("  ProxyJump ")
			b.WriteString(h.ProxyJump)
			b.WriteString("\n")
		}
		if extra != "" {
			for _, line := range strings.Split(extra, "\n") {
				b.WriteString("  ")
				b.WriteString(line)
				b.WriteString("\n")
			}
		}
	}
	b.WriteString(managedEnd)
	b.WriteString("\n")
	return b.String()
}

func orderedHosts(bundle *store.SyncBundle) []store.Host {
	hosts := make([]store.Host, len(bundle.Hosts))
	copy(hosts, bundle.Hosts)
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].SortOrder != hosts[j].SortOrder {
			return hosts[i].SortOrder < hosts[j].SortOrder
		}
		return hosts[i].Alias < hosts[j].Alias
	})
	return hosts
}

// spliceManagedBlock ersetzt den managed Block oder fuegt ihn am Anfang ein.
// Lokale Eintraege ausserhalb der Marker bleiben erhalten.
func spliceManagedBlock(existing, managedBlock string) string {
	beginIdx := strings.Index(existing, managedBegin)
	endIdx := strings.Index(existing, managedEnd)
	if beginIdx >= 0 && endIdx > beginIdx {
		end := endIdx + len(managedEnd)
		rest := existing[end:]
		if strings.HasPrefix(rest, "\r\n") {
			rest = rest[2:]
		} else if strings.HasPrefix(rest, "\n") {
			rest = rest[1:]
		}
		prefix := existing[:beginIdx]
		return prefix + managedBlock + rest
	}
	if strings.TrimSpace(existing) == "" {
		return managedBlock
	}
	// Erster Einfuegevorgang: Block oben, lokale Hosts darunter bleiben.
	if !strings.HasSuffix(existing, "\n") {
		existing += "\n"
	}
	return managedBlock + "\n" + existing
}

func writeTimestampedConfigBackup(configPath, content string) (string, error) {
	if strings.TrimSpace(content) == "" {
		return "", nil
	}
	dir := filepath.Dir(configPath)
	stamp := time.Now().UTC().Format("20060102T150405Z")
	bak := filepath.Join(dir, configBakPrefix+stamp)
	// Kollision in derselben Sekunde: Suffix anhaengen.
	if _, err := os.Stat(bak); err == nil {
		bak = bak + "-1"
	}
	if err := os.WriteFile(bak, []byte(content), 0o600); err != nil {
		return "", err
	}
	if err := chmodPrivate(bak); err != nil {
		return "", err
	}
	return bak, nil
}

func pruneConfigBackups(sshDir string, keep int) error {
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), configBakPrefix) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) <= keep {
		return nil
	}
	for _, name := range names[:len(names)-keep] {
		if err := os.Remove(filepath.Join(sshDir, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func sanitizeFilename(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "identity"
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('_')
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
