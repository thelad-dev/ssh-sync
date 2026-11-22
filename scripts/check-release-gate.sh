#!/usr/bin/env bash
# Prueft, dass ein Tag-Commit auf origin/main liegt und der CI-Workflow dort gruen war.
# Aufruf: check-release-gate.sh <tag-sha> <owner/repo>
# Erwartet GH_TOKEN (oder gh-Defaultauth). GH_BIN ueberschreibt den gh-Befehl (Tests).
set -euo pipefail

if [[ "${#}" -lt 2 ]]; then
  echo "Usage: $0 <tag-sha> <owner/repo>" >&2
  exit 2
fi

TAG_SHA="${1}"
REPO="${2}"
GH_BIN="${GH_BIN:-gh}"

if ! git merge-base --is-ancestor "${TAG_SHA}" origin/main; then
  echo "Tag-Commit ${TAG_SHA} liegt nicht auf origin/main" >&2
  exit 1
fi

# API-Fehler und fehlendes gruener CI-Lauf getrennt melden (gh-Fehler nicht verschlucken).
err_file="$(mktemp)"
trap 'rm -f "${err_file}"' EXIT

set +e
ci_ok="$("${GH_BIN}" run list --repo "${REPO}" --commit "${TAG_SHA}" --workflow ci.yml \
  --json conclusion --jq 'any(.[]; .conclusion == "success")' 2>"${err_file}")"
gh_rc=$?
set -e

if [[ "${gh_rc}" -ne 0 ]]; then
  echo "API-Fehler beim Abfragen der CI-Laeufe fuer Commit ${TAG_SHA} (exit ${gh_rc}):" >&2
  if [[ -s "${err_file}" ]]; then
    cat "${err_file}" >&2
  else
    echo "(keine Fehlermeldung von gh)" >&2
  fi
  exit 1
fi

if [[ "${ci_ok}" != "true" ]]; then
  echo "Kein erfolgreicher CI-Lauf fuer Commit ${TAG_SHA}" >&2
  exit 1
fi

echo "Gate ok: ${TAG_SHA} auf main, CI gruen"
