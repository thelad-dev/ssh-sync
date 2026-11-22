package version

// Agent is the monotonic release version of the client binary (semver-like).
// Set at build time via -ldflags "-X .../internal/version.Agent=1.2.3".
// Do not use timestamps: self-update requires comparable versions.
var Agent = "0.0.0-dev"
