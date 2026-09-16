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

step "list says what the project holds"
tm list "$work/sample" > "$work/sample/list.txt"
grep -q '^NAME' "$work/sample/list.txt"
grep -q 'payments' "$work/sample/list.txt"
tm list "$work/sample" --json > "$work/sample/list.json"
grep -q '"unanswered"' "$work/sample/list.json"

step "export writes the model as data"
tm export "$work/sample"
test -f "$work/sample/threatmodel/payments.json"
grep -q '"schemaVersion"' "$work/sample/threatmodel/payments.json"
tm export "$work/sample" --format otm
grep -q '"otmVersion"' "$work/sample/threatmodel/payments.otm.json"
# The output goes to a file first: `grep -q` closes a pipe as soon as it
# matches, and the writer then dies of SIGPIPE.
tm export "$work/sample" --stdout > "$work/sample/stdout.json"
grep -q '"threats"' "$work/sample/stdout.json"

step "a component sits in a zone another part file declares"
mkdir -p "$work/split/threatmodel/payments/arch"
printf 'system "Payments" {\n  catalogue = "v1.0.0"\n}\n' \
    > "$work/split/threatmodel/payments/arch/payments.arch"
cat > "$work/split/threatmodel/payments/arch/edge.arch" <<'ARCH'
zone "edge" {
  kind            = "public"
  network         = "dmz"
  reduces_risk_by = 20

  component "waf" {
    technology = "aws-waf"
  }
}
ARCH
cat > "$work/split/threatmodel/payments/arch/ledger.arch" <<'ARCH'
component "api" {
  technology = "aws-ec2"
  zone       = "edge"
}

flow waf -> api
ARCH
cp "$work/split/threatmodel/payments/arch/ledger.arch" "$work/split-ledger-first.arch"
cp "$work/split/threatmodel/payments/arch/edge.arch" "$work/split-edge-first.arch"
# A format writes the attribute back where it was and nests nothing across
# files, so both part files read byte for byte.
tm format "$work/split"
diff "$work/split-ledger-first.arch" "$work/split/threatmodel/payments/arch/ledger.arch"
diff "$work/split-edge-first.arch" "$work/split/threatmodel/payments/arch/edge.arch"
tm compile "$work/split"
grep -q 'on component "api"' "$work/split/threatmodel/payments/controls/ledger.controls"

step "a user block formats byte for byte and reaches the report"
mkdir -p "$work/users/threatmodel"
cat > "$work/users/threatmodel/payments.arch" <<'ARCH'
system "Payments" {
  threat_actor "insider" {
    name       = "Disgruntled operator"
    capability = "targeted"
    intent     = "sabotage"
    performs   = ["credential-theft"]
  }

  component "api" {
    technology = "aws-ec2"
    data       = "confidential"
  }

  user "alice" {
    name         = "Alice"
    role         = "Operator"
    access       = "admin"
    reaches      = ["api"]
    threat_actor = "insider"
  }

  flow alice -> api
}
ARCH
cp "$work/users/threatmodel/payments.arch" "$work/users-first.arch"
tm format "$work/users"
diff "$work/users-first.arch" "$work/users/threatmodel/payments.arch"
tm compile "$work/users"
tm report "$work/users"
grep -q '^### Users' "$work/users/threatmodel/payments.md"
grep -q 'Alice (Operator, Administrator): reaches EC2' "$work/users/threatmodel/payments.md"
grep -q 'Disgruntled operator' "$work/users/threatmodel/payments.md"

step "check refuses a user naming a threat actor nothing declares"
mkdir -p "$work/ghost-actor/threatmodel"
printf 'system "Payments" {\n  user "alice" {\n    threat_actor = "ghost"\n  }\n}\n' \
    > "$work/ghost-actor/threatmodel/payments.arch"
expect_code 2 check "$work/ghost-actor"

step "check refuses a zone no part file declares"
mkdir -p "$work/ghost/threatmodel/payments/arch"
printf 'system "Payments" { }\n' > "$work/ghost/threatmodel/payments/arch/payments.arch"
printf 'component "api" {\n  technology = "aws-ec2"\n  zone       = "ghost"\n}\n' \
    > "$work/ghost/threatmodel/payments/arch/ledger.arch"
expect_code 2 check "$work/ghost"

step "lsp answers a client"
# The Language Server Protocol frames each message with its length.
frame() {
    printf 'Content-Length: %d\r\n\r\n%s' "${#1}" "$1"
}
{
    frame '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
    frame '{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///p.arch","text":"system \"P\" {\n  zone \"z\" { kind = \"secret\" }\n}\n"}}}'
    frame '{"jsonrpc":"2.0","method":"exit"}'
} > "$work/lsp-in.bin"
tm lsp < "$work/lsp-in.bin" > "$work/lsp-out.bin"
grep -q 'Content-Length:' "$work/lsp-out.bin"
grep -q '"documentFormattingProvider"' "$work/lsp-out.bin"
grep -q 'publishDiagnostics' "$work/lsp-out.bin"

step "mcp answers a client"
printf '%s\n%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
    > "$work/mcp-in.json"
tm mcp "$work/sample" < "$work/mcp-in.json" > "$work/mcp-out.json"
grep -q '"serverInfo"' "$work/mcp-out.json"
grep -q '"list_systems"' "$work/mcp-out.json"
grep -q '"answer_control"' "$work/mcp-out.json" && exit 1
echo "the read-only server offers no writing tool"

step "import terraform draws what a state holds"
mkdir -p "$work/imported/threatmodel"
tm import terraform "$work/imported" < ThreatModelKit/Tests/Goldens/terraform-aws-state.json
test -f "$work/imported/threatmodel/imported.arch"
grep -q 'technology = "aws-ec2"' "$work/imported/threatmodel/imported.arch"
grep -q 'source     = "terraform"' "$work/imported/threatmodel/imported.arch"
cp "$work/imported/threatmodel/imported.arch" "$work/imported-first.arch"
tm import terraform "$work/imported" < ThreatModelKit/Tests/Goldens/terraform-aws-state.json
diff "$work/imported-first.arch" "$work/imported/threatmodel/imported.arch"

step "the threatcl export is what threatcl accepts"
tm export "$work/sample" --format threatcl
test -f "$work/sample/threatmodel/payments.hcl"
grep -q '^spec_version = ' "$work/sample/threatmodel/payments.hcl"
# The binary is run when this machine holds it. A machine without it keeps the
# golden test in `ExportModelAsThreatclTests`, which states the same file.
if command -v threatcl > /dev/null 2>&1; then
    threatcl validate "$work/sample/threatmodel/payments.hcl"
else
    echo "threatcl is not on this machine; the golden test stands in"
fi

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
