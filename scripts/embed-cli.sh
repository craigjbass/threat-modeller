#!/usr/bin/env bash
#
# Puts the command line executable inside an application bundle.
#
#   scripts/embed-cli.sh <path to threatmodeller.app> [<signing identity>]
#
# The bundle then holds Contents/Resources/threatmodeller-cli/threatmodeller
# with Library/ and Actors/ beside it, which is the layout the release tarball
# uses, so the executable finds its catalogue with no flag and a symbolic link
# from the user's PATH finds it too.
#
# It goes under Resources rather than Helpers because codesign treats every
# file under Contents/Helpers as code, and the catalogue is data.
#
# WARNING: inserting a file into a signed bundle breaks its signature. When a
# signing identity is given this script signs the helper and then signs the
# bundle again. Give no identity for a local build, which is signed to run on
# this machine only.
set -euo pipefail

APP="${1:-}"
IDENTITY="${2:-}"

if [ -z "$APP" ]; then
  echo "usage: scripts/embed-cli.sh <path to threatmodeller.app> [<signing identity>]" >&2
  exit 2
fi
if [ ! -d "$APP/Contents" ]; then
  echo "embed-cli: $APP is not an application bundle" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESOURCES="$ROOT/ThreatModelKit/Sources/CatalogueGateways/Resources"
HELPERS="$APP/Contents/Resources/threatmodeller-cli"

echo "embed-cli: building the executable"
cd "$ROOT/ThreatModelKit"
if [ -n "$IDENTITY" ]; then
  # A release carries both architectures.
  swift build -c release --product threatmodeller-cli --arch arm64 --arch x86_64
  BUILT="$ROOT/ThreatModelKit/.build/apple/Products/Release/threatmodeller-cli"
else
  swift build -c release --product threatmodeller-cli
  BUILT="$(swift build -c release --product threatmodeller-cli --show-bin-path)/threatmodeller-cli"
fi
cd "$ROOT"

echo "embed-cli: writing $HELPERS"
rm -rf "$HELPERS"
mkdir -p "$HELPERS"
cp "$BUILT" "$HELPERS/threatmodeller"
cp -R "$RESOURCES/Library" "$HELPERS/"
cp -R "$RESOURCES/Actors" "$HELPERS/"

if [ -n "$IDENTITY" ]; then
  echo "embed-cli: signing the helper, then the bundle"
  codesign --force --options runtime --timestamp \
    --sign "$IDENTITY" "$HELPERS/threatmodeller"
  # The bundle is signed again because a file was added to it. The
  # entitlements are the ones the application ships with.
  codesign --force --options runtime --timestamp \
    --entitlements "$ROOT/threatmodeller/threatmodeller.entitlements" \
    --sign "$IDENTITY" "$APP"
  codesign --verify --deep --strict "$APP"
else
  echo "embed-cli: signing the bundle for this machine"
  codesign --force --sign - "$HELPERS/threatmodeller"
  codesign --force --sign - \
    --entitlements "$ROOT/threatmodeller/threatmodeller.entitlements" "$APP"
fi

echo "embed-cli: $APP now carries $("$HELPERS/threatmodeller" help | head -1)"
