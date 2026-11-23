package api

// Cosign-Bootstrap fuer die Installer: fehlendes cosign im PATH wird einmalig
// aus dem gepinnten Sigstore-Release geladen (privates Temp, SHA-256 vor Start,
// danach geloescht). PATH-cosign hat Vorrang. Erneuern: docs/release-signing.md
// Abschnitt "Cosign-Bootstrap erneuern".

const cosignPinnedVersion = "v3.1.4"

// cosignBootstrapSHA256: Schluessel = "os-arch" (windows ohne .exe).
// Werte = SHA-256 (klein) der offiziellen Binary von
// https://github.com/sigstore/cosign/releases/download/<version>/cosign-<os>-<arch>[.exe]
var cosignBootstrapSHA256 = map[string]string{
	"linux-amd64":   "424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa",
	"linux-arm64":   "ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2",
	"darwin-amd64":  "9d1e4abe2b6be279ed0d2ff706fde1ccd738747c834e3e6d44039c238867334f",
	"darwin-arm64":  "9f9b8cd557cf2e5b3df3373a00baa005a86b02391e3e06dd0ce37b3a1533d3a4",
	"windows-amd64": "cbe953787074611f1334cbf37dc1cf953995bb8c45398eb4fc7bb781d29c1f2a",
}

func cosignPin(osArch string) string {
	return cosignBootstrapSHA256[osArch]
}
