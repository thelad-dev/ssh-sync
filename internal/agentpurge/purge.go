package agentpurge

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/agentconfig"
	"github.com/thelad-dev/ssh-sync/internal/agentservice"
	"github.com/thelad-dev/ssh-sync/internal/selfupdate"
	"github.com/thelad-dev/ssh-sync/internal/sshconfig"
)

// Options steuert den Geraete-Purge (Geraet abgeben).
type Options struct {
	ManagedOnly bool
	ConfigPath  string
	SSHDir      string
	SkipBinary  bool
	BackupDir   string
}

var protectedSSHNames = map[string]struct{}{
	"authorized_keys": {},
	"known_hosts":     {},
	"known_hosts.old": {},
}

// Execute entfernt ssh-sync-Daten vom Geraet. Reihenfolge: Dienst deinstallieren, Wipe, Config/Keyring, Binary.
func Execute(opts Options) error {
	cfgPath := opts.ConfigPath
	if cfgPath == "" {
		var err error
		cfgPath, err = agentconfig.DefaultPath()
		if err != nil {
			return err
		}
	}

	sshDir := opts.SSHDir
	if sshDir == "" {
		if cfg, err := agentconfig.Load(cfgPath); err == nil {
			sshDir = cfg.ResolveSSHDir()
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			sshDir = filepath.Join(home, ".ssh")
		}
	}

	_ = agentservice.Uninstall()

	if opts.ManagedOnly {
		backupDir := opts.BackupDir
		if backupDir == "" {
			// Neben ~/.ssh ablegen, nicht unter dem Config-Verzeichnis (wird danach entfernt).
			backupDir = filepath.Join(filepath.Dir(sshDir), ".ssh-sync-purge-backup-"+time.Now().UTC().Format("20060102T150405Z"))
		}
		if err := backupManaged(sshDir, backupDir); err != nil {
			return err
		}
		if err := wipeManagedOnly(sshDir); err != nil {
			return err
		}
	} else if err := wipeSSHDir(sshDir); err != nil {
		return err
	}

	configDir := filepath.Dir(cfgPath)
	if err := os.RemoveAll(configDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("config-Verzeichnis entfernen: %w", err)
	}

	if !opts.SkipBinary {
		if err := removeSelfBinary(); err != nil {
			return err
		}
	}
	return nil
}

func wipeSSHDir(sshDir string) error {
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if _, protect := protectedSSHNames[e.Name()]; protect {
			continue
		}
		path := filepath.Join(sshDir, e.Name())
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("%s entfernen: %w", path, err)
		}
	}
	return nil
}

func wipeManagedOnly(sshDir string) error {
	configPath := filepath.Join(sshDir, "config")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	content := string(data)
	for _, idFile := range sshconfig.ManagedIdentityFiles(content) {
		path := expandSSHPath(sshDir, idFile)
		base := filepath.Base(path)
		if _, protect := protectedSSHNames[base]; protect {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("managed key %s entfernen: %w", path, err)
		}
	}
	remaining := strings.TrimSpace(sshconfig.StripManagedBlock(content))
	if remaining == "" {
		if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else if !strings.HasSuffix(remaining, "\n") {
		remaining += "\n"
		if err := os.WriteFile(configPath, []byte(remaining), 0o600); err != nil {
			return err
		}
	} else if err := os.WriteFile(configPath, []byte(remaining), 0o600); err != nil {
		return err
	}
	return nil
}

func backupManaged(sshDir, backupDir string) error {
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return fmt.Errorf("purge-backup anlegen: %w", err)
	}
	configPath := filepath.Join(sshDir, "config")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.WriteFile(filepath.Join(backupDir, "config.managed"), data, 0o600); err != nil {
		return err
	}
	for _, idFile := range sshconfig.ManagedIdentityFiles(string(data)) {
		src := expandSSHPath(sshDir, idFile)
		base := filepath.Base(src)
		if _, protect := protectedSSHNames[base]; protect {
			continue
		}
		raw, err := os.ReadFile(src)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if err := os.WriteFile(filepath.Join(backupDir, base), raw, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func expandSSHPath(sshDir, identityFile string) string {
	path := strings.Trim(strings.TrimSpace(identityFile), "\"'")
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[2:])
	}
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(sshDir, path)
}

func removeSelfBinary() error {
	dest, err := selfupdate.ResolveDestPath("")
	if err != nil {
		return err
	}
	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("binary entfernen (%s): %w", dest, err)
	}
	return nil
}
