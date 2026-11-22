package api

import (
	"testing"
	"time"

	"github.com/thelad-dev/ssh-sync/internal/auth"
	"github.com/thelad-dev/ssh-sync/internal/store"
)

func TestRemapImportIdentityID(t *testing.T) {
	importID := "client-generated"
	mapped := remapImportIdentityID(&importID, map[string]string{
		"client-generated": "server-existing",
	})
	if mapped == nil || *mapped != "server-existing" {
		t.Fatalf("expected server-existing, got %v", mapped)
	}
	if remapImportIdentityID(nil, nil) != nil {
		t.Fatal("nil import id should stay nil")
	}
	if remapImportIdentityID(&importID, map[string]string{}) != nil {
		t.Fatal("unknown import id should become nil")
	}
}

func TestAgentImportSkipExistingRemapsIdentityFK(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	hash, err := auth.HashPassword("test-master-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(hash, []byte("test-salt")); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	if err := st.UpsertIdentity(store.Identity{
		ID:                  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Name:                "id_rsa",
		PublicKey:           "ssh-rsa AAA",
		EncryptedPrivateKey: "enc",
		CreatedAt:           now,
		UpdatedAt:           now,
	}); err != nil {
		t.Fatal(err)
	}

	importID := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	hostID := "cccccccccccccccccccccccccccccccc"

	req := agentImportRequest{
		Password:     "test-master-password",
		SkipExisting: true,
		Identities: []agentImportIdentity{{
			ID:                  importID,
			Name:                "id_rsa",
			PublicKey:           "ssh-rsa AAA",
			EncryptedPrivateKey: "enc2",
		}},
		Hosts: []agentImportHost{{
			ID:         hostID,
			Alias:      "devbox",
			HostName:   "devbox.example",
			User:       "deploy",
			Port:       22,
			IdentityID: &importID,
		}},
	}

	identityIDMap := map[string]string{}
	existingByName := map[string]store.Identity{}
	if list, err := st.ListIdentities(); err != nil {
		t.Fatal(err)
	} else {
		for _, i := range list {
			existingByName[i.Name] = i
		}
	}

	for _, id := range req.Identities {
		existing, ok := existingByName[id.Name]
		if !ok {
			t.Fatal("expected existing identity")
		}
		identityIDMap[id.ID] = existing.ID
	}

	resolved := remapImportIdentityID(req.Hosts[0].IdentityID, identityIDMap)
	if resolved == nil || *resolved != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("expected existing identity id, got %v", resolved)
	}

	if err := st.UpsertHost(store.Host{
		ID:         hostID,
		Alias:      "devbox",
		HostName:   "devbox.example",
		User:       "deploy",
		Port:       22,
		IdentityID: resolved,
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("upsert host with remapped identity: %v", err)
	}
}
