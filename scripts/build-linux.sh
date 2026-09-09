#!/usr/bin/env bash
# Builds the threatmodeller executable for Linux from macOS.
#
# The static Linux SDK links musl and the Swift runtime into the binary, so the
# target machine needs no Swift installed. The catalogue does not link in: it
# ships as a directory beside the binary, and --catalogue names it.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! swift sdk list 2>/dev/null | grep -Eq 'swift-linux-musl|static-linux'; then
    echo "No static Linux SDK is installed. Install one with:" >&2
    echo "  swift sdk install <static-linux-sdk-artifactbundle-url>" >&2
    echo "The URL for this toolchain is on swift.org/download." >&2
    exit 1
fi

OUT="$(pwd)/build/linux"
mkdir -p "$OUT"

for TRIPLE in x86_64-swift-linux-musl aarch64-swift-linux-musl; do
    echo "Building $TRIPLE"
    (cd ThreatModelKit && swift build --swift-sdk "$TRIPLE" -c release --product threatmodeller-cli)

    ARCH_OUT="$OUT/$TRIPLE"
    rm -rf "$ARCH_OUT"
    mkdir -p "$ARCH_OUT"
    # Installed under the name a user types.
    cp "ThreatModelKit/.build/$TRIPLE/release/threatmodeller-cli" "$ARCH_OUT/threatmodeller"
    cp -R ThreatModelKit/Sources/CatalogueGateways/Resources/Library "$ARCH_OUT/"
    cp -R ThreatModelKit/Sources/CatalogueGateways/Resources/Actors "$ARCH_OUT/"

    (cd "$OUT" && tar czf "threatmodeller-$TRIPLE.tar.gz" "$TRIPLE")
    echo "Wrote $OUT/threatmodeller-$TRIPLE.tar.gz"
done

echo
echo "On the target machine:"
echo "  tar xzf threatmodeller-<triple>.tar.gz"
echo "  ./threatmodeller --catalogue . format ."
