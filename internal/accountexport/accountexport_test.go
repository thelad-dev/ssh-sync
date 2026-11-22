package accountexport

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/auth"
	"github.com/thelad-dev/ssh-sync/internal/crypto"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

func testPayload(t *testing.T, password string) (Payload, string) {
	t.Helper()
	salt := bytes.Repeat([]byte{0x42}, crypto.SaltLen)
	keys := crypto.DeriveKeys(password, salt)
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	enc, err := crypto.EncryptIdentity(keys, id, "ssh-ed25519 AAAA", []byte("PRIVATE"))
	if err != nil {
		t.Fatal(err)
	}
	p := Payload{
		KDFSalt:    hex.EncodeToString(salt),
		AuthScheme: store.AuthSchemeV1,
		Identities: []IdentityEntry{{
			ID: id, Name: "laptop", PublicKey: "ssh-ed25519 AAAA",
			EncryptedPrivateKey: enc, Comment: "c",
		}},
		Hosts: []HostEntry{{
			ID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Alias: "box",
			HostName: "box.example", User: "root", Port: 22,
			IdentityID: &id, Extra: "ServerAliveInterval 30",
		}},
		Devices:  []DeviceEntry{{Name: "laptop"}},
		Settings: map[string]string{"cf_access_client_id": "cid"},
		Metadata: map[string]string{"generator": "test"},
	}
	return p, password
}

func TestRoundTripSealOpen(t *testing.T) {
	p, pw := testPayload(t, "master-password-12")
	raw, err := Seal(pw, p)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Open(pw, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(env.Payload.Identities) != 1 || env.Payload.Hosts[0].Alias != "box" {
		t.Fatalf("payload mismatch: %+v", env.Payload)
	}
}

func TestRejectWrongPassword(t *testing.T) {
	p, pw := testPayload(t, "master-password-12")
	raw, err := Seal(pw, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open("wrong-password-xx", raw); err == nil {
		t.Fatal("erwartet Fehler bei falschem Passwort")
	}
}

func TestRejectTamperedArchive(t *testing.T) {
	p, pw := testPayload(t, "master-password-12")
	raw, err := Seal(pw, p)
	if err != nil {
		t.Fatal(err)
	}
	mut := bytes.Replace(raw, []byte("box.example"), []byte("evil.example"), 1)
	if _, err := Open(pw, mut); err == nil {
		t.Fatal("erwartet Integritaetsfehler")
	}
}

func TestRejectDuplicatePayload(t *testing.T) {
	p, pw := testPayload(t, "master-password-12")
	raw, err := Seal(pw, p)
	if err != nil {
		t.Fatal(err)
	}
	evil := `{"kdf_salt":"` + p.KDFSalt + `","auth_scheme":"auth_v1","identities":[],"hosts":[],"devices":[],"settings":{"x":"evil"}}`
	cut := bytes.LastIndexByte(raw, '}')
	dup := append(append([]byte{}, raw[:cut]...), []byte(`,"payload":`+evil+`}`)...)
	if _, err := Open(pw, dup); err == nil || !strings.Contains(err.Error(), "genau ein payload") {
		t.Fatalf("erwartet Ablehnung doppelter payload, got %v", err)
	}
	uni := append(append([]byte{}, raw[:cut]...), []byte(`,"\u0070ayload":`+evil+`}`)...)
	if _, err := Open(pw, uni); err == nil || !strings.Contains(err.Error(), "genau ein payload") {
		t.Fatalf("erwartet Ablehnung unicode-payload, got %v", err)
	}
}

func TestRejectFutureSchema(t *testing.T) {
	p, pw := testPayload(t, "master-password-12")
	raw, err := Seal(pw, p)
	if err != nil {
		t.Fatal(err)
	}
	mut := bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":99`), 1)
	if _, err := Open(pw, mut); err == nil || !strings.Contains(err.Error(), "neuer") {
		t.Fatalf("erwartet Versionsfehler, got %v", err)
	}
}

func TestRejectProxyCommand(t *testing.T) {
	p, _ := testPayload(t, "master-password-12")
	p.Hosts[0].Extra = "ProxyCommand curl evil"
	if err := ValidatePayload(&p); err == nil {
		t.Fatal("ProxyCommand muss abgelehnt werden")
	}
}

func TestApplyRoundTripFreshAccount(t *testing.T) {
	pw := "master-password-12"
	p, _ := testPayload(t, pw)
	salt, _ := hex.DecodeString(p.KDFSalt)
	keys := crypto.DeriveKeys(pw, salt)

	dir := t.TempDir()
	src, err := store.Open(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	hash, _ := auth.HashPassword(hex.EncodeToString(keys.AuthKey))
	if err := src.CreateUserWithScheme(hash, salt, store.AuthSchemeV1); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_ = src.UpsertIdentity(store.Identity{
		ID: p.Identities[0].ID, Name: p.Identities[0].Name,
		PublicKey: p.Identities[0].PublicKey, EncryptedPrivateKey: p.Identities[0].EncryptedPrivateKey,
		Comment: "c", CreatedAt: now, UpdatedAt: now,
	})
	_ = src.UpsertHost(store.Host{
		ID: p.Hosts[0].ID, Alias: p.Hosts[0].Alias, HostName: p.Hosts[0].HostName,
		User: "root", Port: 22, IdentityID: p.Hosts[0].IdentityID, Extra: p.Hosts[0].Extra,
		CreatedAt: now, UpdatedAt: now,
	})
	_ = src.SetSetting("cf_access_client_id", "cid")
	ids, _ := src.ListIdentities()
	hosts, _ := src.ListHosts()
	devs, _ := src.ListDevices()
	settings, _ := src.ListSettings()
	payload := FromStore(ids, hosts, devs, salt, store.AuthSchemeV1, settings)
	raw, err := Seal(pw, payload)
	if err != nil {
		t.Fatal(err)
	}

	dst, err := store.Open(filepath.Join(dir, "dst.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	hash2, _ := auth.HashPassword(hex.EncodeToString(keys.AuthKey))
	if err := dst.CreateUserWithScheme(hash2, salt, store.AuthSchemeV1); err != nil {
		t.Fatal(err)
	}
	env, err := Open(pw, raw)
	if err != nil {
		t.Fatal(err)
	}
	dry, err := Apply(dst, env.Payload, ApplyOptions{Mode: ModeReplace, DryRun: true})
	if err != nil || dry.IdentitiesUpserted != 1 {
		t.Fatalf("dry-run: %+v err=%v", dry, err)
	}
	rep, err := Apply(dst, env.Payload, ApplyOptions{Mode: ModeReplace, DryRun: false})
	if err != nil {
		t.Fatal(err)
	}
	gotIDs, _ := dst.ListIdentities()
	gotHosts, _ := dst.ListHosts()
	if len(gotIDs) != 1 || gotIDs[0].EncryptedPrivateKey != p.Identities[0].EncryptedPrivateKey {
		t.Fatalf("identity mismatch: %+v / report %+v", gotIDs, rep)
	}
	if len(gotHosts) != 1 || gotHosts[0].Alias != "box" {
		t.Fatalf("hosts mismatch: %+v", gotHosts)
	}
	plain, err := crypto.DecryptIdentity(keys, gotIDs[0].ID, gotIDs[0].PublicKey, gotIDs[0].EncryptedPrivateKey)
	if err != nil || string(plain) != "PRIVATE" {
		t.Fatalf("decrypt after import: %v %q", err, plain)
	}
}

func TestEmptyAccountExport(t *testing.T) {
	salt := bytes.Repeat([]byte{0x11}, crypto.SaltLen)
	p := FromStore(nil, nil, nil, salt, store.AuthSchemeV1, nil)
	raw, err := Seal("master-password-12", p)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Open("master-password-12", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(env.Payload.Identities) != 0 {
		t.Fatal("expected empty")
	}
}

func TestLargeAccount(t *testing.T) {
	pw := "master-password-12"
	salt := bytes.Repeat([]byte{0x33}, crypto.SaltLen)
	keys := crypto.DeriveKeys(pw, salt)
	p := Payload{
		KDFSalt: hex.EncodeToString(salt), AuthScheme: store.AuthSchemeV1,
		Settings: map[string]string{}, Metadata: map[string]string{},
	}
	for i := 0; i < 200; i++ {
		id := hex.EncodeToString(bytes.Repeat([]byte{byte(i)}, 16))
		enc, _ := crypto.EncryptIdentity(keys, id, "ssh-ed25519 AAAA", []byte("PRIVATE"))
		p.Identities = append(p.Identities, IdentityEntry{
			ID: id, Name: "id-" + id[:8], PublicKey: "ssh-ed25519 AAAA", EncryptedPrivateKey: enc,
		})
		hid := hex.EncodeToString(bytes.Repeat([]byte{byte(255 - i)}, 16))
		p.Hosts = append(p.Hosts, HostEntry{
			ID: hid, Alias: "h" + id[:8], HostName: "h.example", User: "u", Port: 22, IdentityID: &id,
		})
	}
	raw, err := Seal(pw, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(pw, raw); err != nil {
		t.Fatal(err)
	}
}

func TestWriteFileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.json")
	if err := WriteFile(path, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("erwartete 0600, got %o", fi.Mode().Perm())
	}
}
