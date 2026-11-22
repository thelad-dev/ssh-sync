#!/usr/bin/env bash
# Erzeugt offline einen Ed25519-Release-Seed (kein Produktionsschluessel im Repo).
#
# Usage:
#   scripts/gen-release-key.sh [seed-pfad]
#
# Standard-Pfad: ~/ssh-sync-release.seed (ausserhalb des Repos)
#
# Reihenfolge:
#   1. Lokales Go >= Version aus go.mod  -> go run ./cmd/genreleasekey
#   2. Docker verfuegbar                 -> golang:<go.mod> Container
#   3. OpenSSL >= 3                      -> Seed und Public Key ohne Go
#   4. Sonst Fehler mit den drei Optionen
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-${HOME}/ssh-sync-release.seed}"

# Absolute Seed-Pfad (Parent darf noch fehlen).
if command -v realpath >/dev/null 2>&1; then
  OUT="$(realpath -m "${OUT}")"
else
  case "${OUT}" in
    /*) ;;
    *) OUT="${PWD}/${OUT}" ;;
  esac
fi

case "${OUT}" in
  "${ROOT}"|"${ROOT}/"*|./|./*)
    echo "FEHLER: Seed-Pfad darf nicht im Repository liegen: ${OUT}" >&2
    exit 1
    ;;
esac

if [[ -e "${OUT}" ]]; then
  echo "FEHLER: Seed-Datei existiert bereits (kein Ueberschreiben): ${OUT}" >&2
  exit 1
fi

echo "WARNUNG: Seed offline sichern (zweite Kopie). Niemals committen." >&2
echo "WARNUNG: Fingerabdruck spaeter im Release nennen." >&2

GO_MOD_VERSION="$(awk '/^go[[:space:]]+/ { print $2; exit }' "${ROOT}/go.mod")"
if [[ -z "${GO_MOD_VERSION}" ]]; then
  echo "FEHLER: go-Version in ${ROOT}/go.mod nicht gefunden" >&2
  exit 1
fi

version_ge() {
  # True wenn $1 >= $2 (nur Ziffern.Punkte, z.B. 1.19.8 vs 1.26.0).
  local a="$1" b="$2"
  local IFS=.
  # shellcheck disable=SC2206
  local -a av=(${a}) bv=(${b})
  local i ai bi
  local n=${#av[@]}
  if (( ${#bv[@]} > n )); then
    n=${#bv[@]}
  fi
  for ((i = 0; i < n; i++)); do
    ai=${av[i]:-0}
    bi=${bv[i]:-0}
    ai=${ai%%[!0-9]*}
    bi=${bi%%[!0-9]*}
    ai=${ai:-0}
    bi=${bi:-0}
    if ((10#${ai} > 10#${bi})); then
      return 0
    fi
    if ((10#${ai} < 10#${bi})); then
      return 1
    fi
  done
  return 0
}

local_go_ok() {
  command -v go >/dev/null 2>&1 || return 1
  local raw ver
  raw="$(go version 2>/dev/null || true)"
  # "go version go1.19.8 linux/amd64"
  ver="$(printf '%s\n' "${raw}" | awk '{ for (i=1;i<=NF;i++) if ($i ~ /^go[0-9]/ { sub(/^go/,"",$i); print $i; exit } }')"
  [[ -n "${ver}" ]] || return 1
  version_ge "${ver}" "${GO_MOD_VERSION}"
}

openssl_ok() {
  command -v openssl >/dev/null 2>&1 || return 1
  local raw major
  raw="$(openssl version 2>/dev/null || true)"
  major="$(printf '%s\n' "${raw}" | awk '{ print $2 }' | cut -d. -f1)"
  [[ -n "${major}" ]] || return 1
  (( major >= 3 ))
}

hex_to_bin() {
  # Schreibt Binaerdaten aus Hex-String nach Datei $2.
  local hex="$1" dest="$2"
  local i out=""
  for ((i = 0; i < ${#hex}; i += 2)); do
    out+="\\x${hex:i:2}"
  done
  # shellcheck disable=SC2059
  printf '%b' "${out}" >"${dest}"
}

bin_to_hex() {
  od -An -tx1 -v "$1" | tr -d ' \n'
}

run_go_local() {
  ( cd "${ROOT}" && go run ./cmd/genreleasekey -out "${OUT}" )
}

run_go_docker() {
  local out_dir out_base image
  out_dir="$(dirname "${OUT}")"
  out_base="$(basename "${OUT}")"
  mkdir -p "${out_dir}"
  image="golang:${GO_MOD_VERSION}"
  # Host-Pfad in der Ausgabe zeigen (Container schreibt nach /out/...).
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp \
    -e GOCACHE=/tmp/gocache \
    -v "${ROOT}:/src:ro" \
    -v "${out_dir}:/out" \
    -w /src \
    "${image}" \
    go run ./cmd/genreleasekey -out "/out/${out_base}" \
    | sed "s|/out/${out_base}|${OUT}|g"
}

# PKCS#8 Ed25519 private key: festes Praefix + 32-Byte-Seed.
# Public Key: letzte 32 Byte der SPKI-DER aus openssl pkey -pubout.
# Ausgabeformat identisch zu cmd/genreleasekey.
run_openssl() {
  local seed_hex tmp_dir pkcs8_der pub_der pub_hex fp_hex fp_short out_dir raw_pub
  out_dir="$(dirname "${OUT}")"
  mkdir -p "${out_dir}"

  seed_hex="$(openssl rand -hex 32)"
  if [[ ${#seed_hex} -ne 64 ]]; then
    echo "FEHLER: openssl rand lieferte unerwartete Laenge" >&2
    exit 1
  fi

  tmp_dir="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp_dir}'" RETURN

  pkcs8_der="${tmp_dir}/seed.pkcs8.der"
  pub_der="${tmp_dir}/pub.der"
  raw_pub="${tmp_dir}/pub.raw"
  # 302e020100300506032b657004220420 || seed (RFC 8410 PKCS#8 Ed25519)
  hex_to_bin "302e020100300506032b657004220420${seed_hex}" "${pkcs8_der}"

  openssl pkey -inform DER -in "${pkcs8_der}" -pubout -outform DER -out "${pub_der}"
  tail -c 32 "${pub_der}" >"${raw_pub}"
  pub_hex="$(bin_to_hex "${raw_pub}")"
  if [[ ${#pub_hex} -ne 64 ]]; then
    echo "FEHLER: Public Key aus OpenSSL hat unerwartete Laenge (${#pub_hex})" >&2
    exit 1
  fi

  fp_hex="$(openssl dgst -sha256 -hex "${raw_pub}" | awk '{print $NF}')"
  fp_short="${fp_hex:0:16}"

  local tmp_seed="${OUT}.tmp"
  umask 077
  printf '%s\n' "${seed_hex}" >"${tmp_seed}"
  chmod 0600 "${tmp_seed}"
  mv -f "${tmp_seed}" "${OUT}"
  chmod 0600 "${OUT}"

  printf 'public_key_hex=%s\n' "${pub_hex}"
  printf 'fingerprint_sha256=%s\n' "${fp_hex}"
  printf 'fingerprint_short=%s\n' "${fp_short}"
  echo
  echo "# Zeile fuer internal/releaseverify/release_ed25519.pub:"
  echo "${pub_hex}"
  echo
  echo "# Secret setzen (Seed-Datei, Inhalt nie loggen):"
  echo "gh secret set RELEASE_SIGNING_KEY < ${OUT}"
}

fail_no_backend() {
  echo "FEHLER: Kein geeignetes Backend fuer die Schluesselerzeugung." >&2
  echo "Moeglichkeiten:" >&2
  echo "  1. Go ${GO_MOD_VERSION} oder neuer installieren (go.mod), dann erneut ausfuehren." >&2
  echo "  2. Docker installieren (Image golang:${GO_MOD_VERSION} wird genutzt)." >&2
  echo "  3. OpenSSL 3 oder neuer installieren (Ed25519 ohne Go)." >&2
  exit 1
}

# Optional: SSH_SYNC_GEN_RELEASE_KEY_BACKEND=go|docker|openssl (Tests/Debug)
case "${SSH_SYNC_GEN_RELEASE_KEY_BACKEND:-}" in
  go)
    run_go_local
    ;;
  docker)
    run_go_docker
    ;;
  openssl)
    if ! openssl_ok; then
      echo "FEHLER: OpenSSL >= 3 erforderlich fuer Backend openssl" >&2
      exit 1
    fi
    run_openssl
    ;;
  "")
    if local_go_ok; then
      run_go_local
    elif command -v docker >/dev/null 2>&1; then
      run_go_docker
    elif openssl_ok; then
      run_openssl
    else
      fail_no_backend
    fi
    ;;
  *)
    echo "FEHLER: Unbekanntes SSH_SYNC_GEN_RELEASE_KEY_BACKEND=${SSH_SYNC_GEN_RELEASE_KEY_BACKEND}" >&2
    exit 1
    ;;
esac

if [[ ! -f "${OUT}" ]]; then
  echo "FEHLER: Seed-Datei wurde nicht geschrieben: ${OUT}" >&2
  exit 1
fi
mode="$(stat -c '%a' "${OUT}" 2>/dev/null || stat -f '%OLp' "${OUT}")"
case "${mode}" in
  600|0600) ;;
  *)
    echo "FEHLER: Seed-Datei hat unerwartete Rechte ${mode} (erwartet 0600): ${OUT}" >&2
    exit 1
    ;;
esac

echo >&2
echo "Naechste Schritte:" >&2
echo "  1. Public-Key-Zeile nach internal/releaseverify/release_ed25519.pub" >&2
echo "  2. gh secret set RELEASE_SIGNING_KEY < ${OUT}" >&2
echo "  3. docs/release.md befolgen (Tag, Entwurf pruefen, veroeffentlichen)" >&2
