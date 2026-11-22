package agentsync

import (
	"fmt"

	"github.com/thelad-dev/ssh-sync/internal/agentconfig"
	"github.com/thelad-dev/ssh-sync/internal/client"
	"github.com/thelad-dev/ssh-sync/internal/crypto"
	"github.com/thelad-dev/ssh-sync/internal/releaseverify"
	"github.com/thelad-dev/ssh-sync/internal/sshconfig"
)

type PullResult struct {
	Hosts        int
	Keys         int
	Config       string
	ConfigBackup string
	KeyPaths     []string
}

func Pull(cfg *agentconfig.Config, master string) (*PullResult, error) {
	if err := releaseverify.CheckServerURL(cfg.ServerURL, false); err != nil {
		return nil, err
	}
	api := client.New(cfg.ServerURL, cfg.JWT)
	api.AccessClientID = cfg.AccessClientID
	api.AccessClientSecret = cfg.AccessClientSecret

	salt, err := api.KDFSalt()
	if err != nil {
		return nil, fmt.Errorf("kdf-salt: %w", err)
	}
	keys := crypto.DeriveKeys(master, salt)

	bundle, err := api.Sync()
	if err != nil {
		return nil, fmt.Errorf("sync: %w", err)
	}

	decrypted := map[string][]byte{}
	for _, id := range bundle.Identities {
		plain, err := crypto.DecryptIdentity(keys, id.ID, id.PublicKey, id.EncryptedPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("identity %q: %w", id.Name, err)
		}
		decrypted[id.ID] = plain
	}

	sshDir := cfg.ResolveSSHDir()
	applied, err := sshconfig.Apply(sshDir, bundle, decrypted)
	if err != nil {
		return nil, err
	}

	return &PullResult{
		Hosts:        len(bundle.Hosts),
		Keys:         len(bundle.Identities),
		Config:       applied.ConfigPath,
		ConfigBackup: applied.BackupPath,
		KeyPaths:     applied.KeyPaths,
	}, nil
}
