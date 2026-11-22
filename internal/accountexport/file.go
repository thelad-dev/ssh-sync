package accountexport

import (
	"fmt"
	"os"
)

// WriteFile schreibt das Archiv mit Rechte 0600.
func WriteFile(path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("Pfad fehlt")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_EXCL, 0o600)
	if err != nil {
		// Existierende Datei: ueberschreiben, Rechte nachziehen.
		if !os.IsExist(err) {
			return err
		}
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	return f.Sync()
}

// ReadFile liest mit Groessenlimit.
func ReadFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > MaxArchiveBytes {
		return nil, fmt.Errorf("Archiv zu gross (%d Bytes, Limit %d)", fi.Size(), MaxArchiveBytes)
	}
	return os.ReadFile(path)
}
