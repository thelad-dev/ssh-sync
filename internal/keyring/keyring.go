package keyring

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	zkeyring "github.com/zalando/go-keyring"
)

const (
	service           = "ssh-sync"
	masterFileName    = ".master-key"
	masterPasswordEnv = "SSH_SYNC_MASTER_PASSWORD"
	keyringTimeout    = 3 * time.Second
)

func SetMasterPassword(password string) error {
	if preferFileStorage() {
		return writeMasterFile(password)
	}
	user := currentUser()
	if err := keyringSet(user, password); err == nil {
		_ = deleteMasterFile()
		return nil
	}
	return writeMasterFile(password)
}

func GetMasterPassword() (string, error) {
	if pw := strings.TrimSpace(os.Getenv(masterPasswordEnv)); pw != "" {
		return pw, nil
	}
	if pw, err := readMasterFile(); err == nil && pw != "" {
		return pw, nil
	}
	if pw, err := readLegacyMasterFile(); err == nil && pw != "" {
		_ = writeMasterFile(pw)
		return pw, nil
	}
	if preferFileStorage() {
		return "", fmt.Errorf("master-passwort nicht gespeichert - zuerst: ssh-sync unlock")
	}
	user := currentUser()
	if pw, err := keyringGet(user); err == nil && pw != "" {
		return pw, nil
	}
	if pw, err := legacyKeyringGet(user); err == nil && pw != "" {
		_ = keyringSet(user, pw)
		return pw, nil
	}
	return "", fmt.Errorf("master-passwort nicht gespeichert - zuerst: ssh-sync unlock")
}

// ResolveMasterPassword nutzt zuerst den gespeicherten Wert (Keyring / .master-key / Env).
// Fehlt er und isTerminal ist true, wird prompt aufgerufen. Sonst klare Fehlermeldung.
// prompt darf das Passwort weder loggen noch ausgeben.
func ResolveMasterPassword(isTerminal bool, prompt func(label string) (string, error)) (string, error) {
	if pw, err := GetMasterPassword(); err == nil && pw != "" {
		return pw, nil
	}
	if isTerminal && prompt != nil {
		pw, err := prompt("Master-Passwort:")
		if err != nil {
			return "", fmt.Errorf("Passwort lesen fehlgeschlagen: %w", err)
		}
		if strings.TrimSpace(pw) == "" {
			return "", fmt.Errorf("master-passwort nicht gespeichert - zuerst: ssh-sync unlock")
		}
		return pw, nil
	}
	return "", fmt.Errorf("master-passwort nicht gespeichert - zuerst: ssh-sync unlock")
}

const legacyService = "ssh-profile-syncer"

// LegacyMasterFilePath is the .master-key path of ssh-profile-syncer.
func LegacyMasterFilePath(home string) string {
	return filepath.Join(home, ".config", "ssh-profile-syncer", masterFileName)
}

func legacyMasterFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return LegacyMasterFilePath(home), nil
}

func readLegacyMasterFile() (string, error) {
	path, err := legacyMasterFilePath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func legacyKeyringGet(user string) (string, error) {
	var pw string
	err := withKeyringTimeout(func() error {
		var err error
		pw, err = zkeyring.Get(legacyService, user)
		return err
	})
	return pw, err
}

func DeleteMasterPassword() error {
	user := currentUser()
	_ = keyringDelete(user)
	return deleteMasterFile()
}

// preferFileStorage überspringt GNOME/libsecret — per SSH hängt Unlock oft am
// D-Bus-Prompt, der nur auf der lokalen Konsole sichtbar ist.
func preferFileStorage() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SSH_SYNC_KEYRING"))) {
	case "file":
		return true
	case "keyring", "gnome", "secret":
		return false
	}
	return os.Getenv("SSH_TTY") != ""
}

func keyringSet(user, password string) error {
	return withKeyringTimeout(func() error {
		return zkeyring.Set(service, user, password)
	})
}

func keyringGet(user string) (string, error) {
	var pw string
	err := withKeyringTimeout(func() error {
		var err error
		pw, err = zkeyring.Get(service, user)
		return err
	})
	return pw, err
}

func keyringDelete(user string) error {
	return withKeyringTimeout(func() error {
		return zkeyring.Delete(service, user)
	})
}

func withKeyringTimeout(fn func() error) error {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(keyringTimeout):
		return fmt.Errorf("keyring-Zugriff Zeitüberschreitung (kein GUI-Prompt per SSH?)")
	}
}

func masterFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "ssh-sync", masterFileName), nil
}

func writeMasterFile(password string) error {
	path, err := masterFilePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(password), 0o600); err != nil {
		return fmt.Errorf("keyring und datei-fallback fehlgeschlagen: %w", err)
	}
	return nil
}

func readMasterFile() (string, error) {
	path, err := masterFilePath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func deleteMasterFile() error {
	path, err := masterFilePath()
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	home, _ := os.UserHomeDir()
	return filepath.Base(home)
}
