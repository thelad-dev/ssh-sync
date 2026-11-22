package releaseverify

import (
	_ "embed"
	"fmt"
	"sync"

	"github.com/sigstore/sigstore-go/pkg/root"
)

//go:embed trusted_root.json
var embeddedTrustedRootJSON []byte

var (
	trustedRootOnce sync.Once
	trustedRoot     *root.TrustedRoot
	trustedRootErr  error
)

// EmbeddedTrustedRoot returns the Sigstore public-good trusted root embedded in the binary.
// Online TUF refresh is optional and not required for offline verification.
func EmbeddedTrustedRoot() (*root.TrustedRoot, error) {
	trustedRootOnce.Do(func() {
		trustedRoot, trustedRootErr = root.NewTrustedRootFromJSON(embeddedTrustedRootJSON)
		if trustedRootErr != nil {
			trustedRootErr = fmt.Errorf("eingebetteter Trusted Root: %w", trustedRootErr)
		}
	})
	return trustedRoot, trustedRootErr
}
