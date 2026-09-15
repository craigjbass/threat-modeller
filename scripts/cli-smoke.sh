#!/usr/bin/env bash
# Runs the executable over projects this script writes, and reads what it
# wrote and what it exited with.
#
# The package tests state what each verb does. This script states that the
# built executable does it over real files, so run it on any machine, not only
# in the Linux job:
#
#     scripts/cli-smoke.sh
#
# THREATMODELLER names how to run the executable. The default builds it from
# the package. A static binary runs the same script:
#
#     THREATMODELLER="build/linux/x86_64-swift-linux-musl/threatmodeller \
#       --catalogue build/linux/x86_64-swift-linux-musl" scripts/cli-smoke.sh
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
: "${THREATMODELLER:=swift run --package-path $root/ThreatModelKit threatmodeller-cli}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Runs the executable. Word splitting is wanted: THREATMODELLER carries the
# words of a command, not one path.
# shellcheck disable=SC2086
tm() { $THREATMODELLER "$@"; }

# Runs the executable and states the exit code it must give.
expect_code() {
    wanted=$1
    shift
    set +e
    tm "$@"
    code=$?
    set -e
    if [ "$code" -ne "$wanted" ]; then
        echo "expected exit $wanted from '$*', got $code" >&2
        exit 1
    fi
}

# Writes a copy of a file with one word put in place of another. `sed -i`
# takes different arguments on Linux and on macOS, so this writes a new file.
replace() {
    sed "s/$1/$2/g" "$3" > "$3.new"
    mv "$3.new" "$3"
}

step() { echo; echo "== $1"; }

step "format tidies a file"
mkdir -p "$work/sample/threatmodel"
cat > "$work/sample/threatmodel/payments.arch" <<'ARCH'
system "Payments" {
zone "app" { kind = "private"
component "api" { technology = "aws-ec2" } }
}
ARCH
tm format "$work/sample"
cat "$work/sample/threatmodel/payments.arch"
grep -q '^  zone "app" {' "$work/sample/threatmodel/payments.arch"

step "compile writes the controls file"
tm compile "$work/sample"
test -f "$work/sample/threatmodel/payments.controls"

step "check fails while nothing is answered"
expect_code 1 check "$work/sample"

step "check passes once every control is in place"
replace '"not_implemented"' '"implemented"' "$work/sample/threatmodel/payments.controls"
tm check "$work/sample"

step "report writes the report"
tm report "$work/sample"
test -f "$work/sample/threatmodel/payments.md"
head -20 "$work/sample/threatmodel/payments.md"

step "format refuses a file that does not parse"
mkdir -p "$work/broken/threatmodel"
printf 'system "P" {\n  zone "z" { kind = "secret" }\n}\n' \
    > "$work/broken/threatmodel/p.arch"
expect_code 2 format "$work/broken"

step "a vendored library reaches the compiled answers"
# A library repository this script writes, so nothing reaches a network.
mkdir -p "$work/elements"
cat > "$work/elements/acme.lib" <<'LIB'
library "acme" {
  name = "Acme Platform"

  technology "cribl-stream" {
    name     = "Cribl Stream"
    category = "monitoring"
    threats  = ["pipeline-tamper"]
  }

  threat "pipeline-tamper" {
    name     = "Pipeline tampering"
    severity = "high"

    control "Sign pipeline configurations"
  }
}
LIB
git config --global --add safe.directory "$work/elements" || true
git -C "$work/elements" init --initial-branch=main --quiet
git -C "$work/elements" add .
# A machine that signs every commit must not sign this one: the
# repository is a fixture, and no key is wanted.
git -C "$work/elements" -c user.email=a@b.c -c user.name=A \
    -c commit.gpgsign=false commit --quiet -m one
git -C "$work/elements" tag v1.0.0

mkdir -p "$work/library-project/threatmodel"
cat > "$work/library-project/threatmodel/payments.arch" <<'ARCH'
system "Payments" {
  component "ingest" { technology = "acme-cribl-stream" }
}
ARCH

tm library add "$work/elements" v1.0.0 "$work/library-project"
test -f "$work/library-project/threatmodel/library/acme.lib"
test -f "$work/library-project/threatmodel/library/library.lock.json"

tm library verify "$work/library-project"
tm library list "$work/library-project"

tm compile "$work/library-project"
grep -q 'acme-pipeline-tamper' "$work/library-project/threatmodel/payments.controls"
grep -q 'Sign pipeline configurations' "$work/library-project/threatmodel/payments.controls"

step "verify refuses a library edited by hand, and update puts it back"
echo '# edited by hand' >> "$work/library-project/threatmodel/library/acme.lib"
expect_code 1 library verify "$work/library-project"
tm library update "$work/library-project"
tm library verify "$work/library-project"

step "remove refuses while the system names the library"
expect_code 1 library remove acme "$work/library-project"
tm library remove acme --force "$work/library-project"

step "library add refuses a repository that is not there"
mkdir -p "$work/no-repo/threatmodel"
printf 'system "P" { }\n' > "$work/no-repo/threatmodel/p.arch"
expect_code 4 library add /no/such/repository v1.0.0 "$work/no-repo"

echo
echo "the executable passed every smoke test"
