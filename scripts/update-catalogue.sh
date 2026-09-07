#!/usr/bin/env bash
#
# Vendors the threat-model-library catalogue into the repository.
#
#   scripts/update-catalogue.sh update v1.0.1   download a tag and rewrite the lock file
#   scripts/update-catalogue.sh verify          re-check the vendored files against the lock file
#
set -euo pipefail

REPO="jib1337/threat-model-library"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/ThreatModelKit/Sources/CatalogueGateways/Resources/Library"
LOCK="$DEST/library.lock.json"

FILES=(
  "taxonomy.json"
  "technologies/aws.json"
  "technologies/azure.json"
  "technologies/gcp.json"
  "technologies/saas.json"
  "technologies/self-hosted.json"
  "threats/common-threats.json"
  "mitigations/pathway-mitigations.json"
)

WORKDIR=""
cleanup() { if [ -n "$WORKDIR" ]; then rm -rf "$WORKDIR"; fi; }
trap cleanup EXIT

checksum() { shasum -a 256 "$1" | awk '{print $1}'; }

write_lock() {
  local tag="$1"
  {
    printf '{\n'
    printf '  "repository": "%s",\n' "$REPO"
    printf '  "tag": "%s",\n' "$tag"
    printf '  "files": {\n'
    local i=0
    for f in "${FILES[@]}"; do
      i=$((i + 1))
      local sep=","
      [ "$i" -eq "${#FILES[@]}" ] && sep=""
      printf '    "%s": "%s"%s\n' "$f" "$(checksum "$DEST/$f")" "$sep"
    done
    printf '  }\n'
    printf '}\n'
  } > "$LOCK"
}

cmd_update() {
  local tag="${1:?usage: update-catalogue.sh update <tag>}"
  WORKDIR="$(mktemp -d)"
  local tmp="$WORKDIR"

  echo "Downloading $REPO@$tag"
  curl -fsSL "https://github.com/$REPO/archive/refs/tags/$tag.tar.gz" -o "$tmp/library.tar.gz"
  tar -xzf "$tmp/library.tar.gz" -C "$tmp"

  local src
  src="$(find "$tmp" -maxdepth 1 -type d -name 'threat-model-library-*' | head -1)/data"
  [ -d "$src" ] || { echo "No data/ directory in the downloaded tag" >&2; exit 1; }

  mkdir -p "$DEST/technologies" "$DEST/threats" "$DEST/mitigations"
  for f in "${FILES[@]}"; do
    [ -f "$src/$f" ] || { echo "Missing $f in the downloaded tag" >&2; exit 1; }
    cp "$src/$f" "$DEST/$f"
  done

  write_lock "$tag"
  echo "Vendored ${#FILES[@]} files at $tag"
}

cmd_verify() {
  [ -f "$LOCK" ] || { echo "No lock file at $LOCK" >&2; exit 1; }
  local failed=0
  for f in "${FILES[@]}"; do
    if [ ! -f "$DEST/$f" ]; then
      echo "MISSING $f" >&2
      failed=1
      continue
    fi
    local expected actual
    expected="$(grep -F "\"$f\"" "$LOCK" | sed 's/.*: "//; s/".*//' || true)"
    if [ -z "$expected" ]; then
      echo "NOLOCKENTRY $f" >&2
      failed=1
      continue
    fi
    actual="$(checksum "$DEST/$f")"
    if [ "$expected" != "$actual" ]; then
      echo "MISMATCH $f" >&2
      failed=1
    fi
  done
  if [ "$failed" -eq 0 ]; then
    echo "All ${#FILES[@]} vendored files match the lock file"
  fi
  exit "$failed"
}

case "${1:-}" in
  update) shift; cmd_update "$@" ;;
  verify) cmd_verify ;;
  *) echo "usage: update-catalogue.sh {update <tag>|verify}" >&2; exit 1 ;;
esac
