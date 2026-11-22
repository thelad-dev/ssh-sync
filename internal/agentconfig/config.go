package agentconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	ServerURL          string `json:"server_url"`
	DeviceID           string `json:"device_id"`
	JWT                string `json:"jwt"`
	SSHDir             string `json:"ssh_dir,omitempty"`
	AccessClientID     string `json:"access_client_id,omitempty"`
	AccessClientSecret string `json:"access_client_secret,omitempty"`
	PollIntervalSec    int    `json:"poll_interval_sec,omitempty"`
}

func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".config", "ssh-sync")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("%s: %w (Kommas zwischen Feldern, kein Komma nach letztem Feld, nur doppelte Anführungszeichen)", path, err)
	}
	cfg.ServerURL = strings.TrimSpace(cfg.ServerURL)
	cfg.DeviceID = strings.TrimSpace(cfg.DeviceID)
	cfg.JWT = strings.TrimSpace(cfg.JWT)
	cfg.AccessClientID = strings.TrimSpace(cfg.AccessClientID)
	cfg.AccessClientSecret = strings.TrimSpace(cfg.AccessClientSecret)
	return &cfg, nil
}

func Save(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func (c *Config) ResolveSSHDir() string {
	if c.SSHDir != "" {
		return c.SSHDir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh")
}
