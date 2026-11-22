package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOpenSetsOwnerOnlyModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix modes")
	}
	dir := t.TempDir()
	// Start with a too-open parent to prove Open tightens it.
	wide := filepath.Join(dir, "data")
	if err := os.MkdirAll(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(wide, "ssh-sync.db")
	st, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	info, err := os.Stat(wide)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("data dir mode=%o want owner-only", info.Mode().Perm())
	}
	dbInfo, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if dbInfo.Mode().Perm()&0o077 != 0 {
		t.Fatalf("db mode=%o want owner-only", dbInfo.Mode().Perm())
	}
	for _, side := range []string{dbPath + "-wal", dbPath + "-shm"} {
		si, err := os.Stat(side)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		if si.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s mode=%o want owner-only", side, si.Mode().Perm())
		}
	}
}
