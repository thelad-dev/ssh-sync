#!/usr/bin/env bash
# Erzeugt offline einen Ed25519-Release-Seed (kein Produktionsschluessel im Repo).
#
# Usage:
#   scripts/gen-release-key.sh [seed-pfad]
#
# Standard-Pfad: ~/ssh-sync-release.seed (ausserhalb des Repos)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-${HOME}/ssh-sync-release.seed}"

case "${OUT}" in
  "${ROOT}"|"${ROOT}/"*|./|./*)
    echo "FEHLER: Seed-Pfad darf nicht im Repository liegen: ${OUT}" >&2
    exit 1
    ;;
esac

echo "WARNUNG: Seed offline sichern (zweite Kopie). Niemals committen." >&2
echo "WARNUNG: Fingerabdruck spaeter im Release nennen." >&2

export PATH="${PATH}"
( cd "${ROOT}" && go run ./cmd/genreleasekey -out "${OUT}" )

echo >&2
echo "Naechste Schritte:" >&2
echo "  1. Public-Key-Zeile nach internal/releaseverify/release_ed25519.pub" >&2
echo "  2. gh secret set RELEASE_SIGNING_KEY < ${OUT}" >&2
echo "  3. docs/release.md befolgen (Tag, Entwurf pruefen, veroeffentlichen)" >&2
