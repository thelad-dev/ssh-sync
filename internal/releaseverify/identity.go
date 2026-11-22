package releaseverify

// Trusted identity for Sigstore keyless release signatures.
// Workflows and scripts document these values; they are not duplicated in Go code elsewhere.
const (
	// TrustedOIDCIssuer is the Fulcio certificate issuer for GitHub Actions OIDC.
	TrustedOIDCIssuer = "https://token.actions.githubusercontent.com"

	// SubjectSANRegex matches the certificate SAN URI for release.yml on a version tag.
	SubjectSANRegex = `^https://github\.com/thelad-dev/ssh-sync/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$`

	// SourceRepositoryURI is the Fulcio extension for the source repository.
	SourceRepositoryURI = "https://github.com/thelad-dev/ssh-sync"

	// SourceRepositoryOwnerURI is the Fulcio extension for the repository owner.
	SourceRepositoryOwnerURI = "https://github.com/thelad-dev"
)
