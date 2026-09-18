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

step "a user through a client formats byte for byte and reaches the report"
# Issue #178. Alice holds a browser and a mobile app; the browser reaches
# the api and the console, the mobile app reaches the api.
mkdir -p "$work/clients/threatmodel"
cat > "$work/clients/threatmodel/payments.arch" <<'ARCH'
system "Payments" {
  component "api" {
    technology = "aws-ec2"
    name       = "API"
    data       = "confidential"
  }

  component "console" {
    technology = "aws-ec2"
    name       = "Admin console"
    data       = "confidential"
  }

  component "browser" {
    technology = "actor-browser"
  }

  component "mobile" {
    technology = "actor-mobile"
  }

  user "alice" {
    name = "Alice"
    role = "Operator"
    uses = ["browser", "mobile"]
  }

  flow browser -> api
  flow browser -> console
  flow mobile -> api
}
ARCH
cp "$work/clients/threatmodel/payments.arch" "$work/clients-first.arch"
tm format "$work/clients"
diff "$work/clients-first.arch" "$work/clients/threatmodel/payments.arch"
tm compile "$work/clients"
replace '"not_implemented"' '"implemented"' "$work/clients/threatmodel/payments.controls"
tm check "$work/clients"
tm report "$work/clients"
grep -q 'Alice (Operator, User): through Web Browser reaches API and Admin console; through Mobile App reaches API' \
    "$work/clients/threatmodel/payments.md"

step "check refuses a user holding a client nothing declares"
mkdir -p "$work/ghost-client/threatmodel"
printf 'system "Payments" {\n  user "alice" {\n    uses = ["ghost"]\n  }\n}\n' \
    > "$work/ghost-client/threatmodel/payments.arch"
expect_code 2 check "$work/ghost-client"

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

step "a governed system still parses after a third party leaves the file"
# Issue #144. The window removes a `third_party` block and saves; the save
# writes the governance file. A file the writer wrote must be a file the
# parser reads, so the project opens the next day.
mkdir -p "$work/governed/threatmodel"
cat > "$work/governed/threatmodel/payments.arch" <<'ARCH'
system "Payments" {
  third_party "stripe" {
    name   = "Stripe"
    kind   = "saas"
    uptime = "none"
  }

  component "api" {
    technology = "aws-ec2"
    data       = "confidential"
  }

  component "db" {
    technology = "aws-rds"
    data       = "confidential"
  }

  flow api -> db
}
ARCH
tm compile "$work/governed"
replace '"not_implemented"' '"accepted"' "$work/governed/threatmodel/payments.controls"
tm compile "$work/governed"
grep -q 'on flow "api->db"' "$work/governed/threatmodel/payments.governance"

# The owner and the review date a person writes into each accepted stanza.
awk '{
    print
    if ($0 ~ /accepted "/) {
        print "      owner     = \"Head of Platform\""
        print "      review_by = \"2099-01-01\""
    }
}' "$work/governed/threatmodel/payments.governance" > "$work/governed/governance.new"
mv "$work/governed/governance.new" "$work/governed/threatmodel/payments.governance"
tm check "$work/governed"

# The remove: the block leaves the architecture file, the way the window
# writes the file after a person removes the third party.
cat > "$work/governed/threatmodel/payments.arch" <<'ARCH'
system "Payments" {
  component "api" {
    technology = "aws-ec2"
    data       = "confidential"
  }

  component "db" {
    technology = "aws-rds"
    data       = "confidential"
  }

  flow api -> db
}
ARCH
tm format "$work/governed"
tm compile "$work/governed"
grep -q 'Head of Platform' "$work/governed/threatmodel/payments.governance"
grep -q 'stale' "$work/governed/threatmodel/payments.governance" && exit 1
tm check "$work/governed"
echo "the governance file still parses and still names its owner"

step "format repairs a governance file holding two blocks with one key"
# The shape a save wrote before the key fix. `format` is the way back.
mkdir -p "$work/twice/threatmodel"
cat > "$work/twice/threatmodel/payments.arch" <<'ARCH'
system "Payments" {
  component "api" {
    technology = "aws-ec2"
    data       = "confidential"
  }

  component "db" {
    technology = "aws-rds"
    data       = "confidential"
  }

  flow api -> db
}
ARCH
cat > "$work/twice/threatmodel/payments.governance" <<'GOV'
governance for "Payments" {
  threat "connection-mitm" on flow "api->db" {
    accepted "Enforce TLS" {
    }
  }

  stale threat "connection-mitm" on flow "api->db" {
    stale accepted "Enforce TLS" {
      owner     = "Head of Platform"
      review_by = "2099-01-01"
    }
  }
}
GOV
tm format "$work/twice" | grep -q 'merged the two blocks governing connection-mitm@connection:api->db'
grep -q 'Head of Platform' "$work/twice/threatmodel/payments.governance"
test "$(grep -c 'on flow "api->db"' "$work/twice/threatmodel/payments.governance")" -eq 1
tm format "$work/twice"

step "a chain of steps runs through check, compile and report"
# Issue #137. A `then` states the order the attacker walks the steps.
mkdir -p "$work/chain/threatmodel"
cat > "$work/chain/threatmodel/payments.arch" <<'ARCH'
system "Payments" {
  component "api" {
    technology = "aws-ec2"
    data       = "confidential"
  }

  component "db" {
    technology = "aws-rds"
    data       = "restricted"
  }

  flow api -> db
}
ARCH
cat > "$work/chain/threatmodel/payments.attacktree" <<'TREE'
attack_trees for "Payments" {
  tree "obtain-the-records" {
    name           = "Obtain the records"
    raises_risk_by = 40

    goal "data-exfiltration" on component "db"

    then {
      step "ssrf-attack" on component "api"
      step "credential-theft" on component "api"
      step "unauthorized-access" on component "db"
    }
  }
}
TREE
cp "$work/chain/threatmodel/payments.attacktree" "$work/chain-first.attacktree"
tm format "$work/chain"
diff "$work/chain-first.attacktree" "$work/chain/threatmodel/payments.attacktree"
tm compile "$work/chain"
grep -q 'tree "obtain-the-records" {' "$work/chain/threatmodel/payments.controls"
grep -q 'position = 3' "$work/chain/threatmodel/payments.controls"
grep -q 'stale tree' "$work/chain/threatmodel/payments.controls" && exit 1
# The chain binds, so check fails only on the unanswered controls.
expect_code 1 check "$work/chain"
replace '"not_implemented"' '"implemented"' "$work/chain/threatmodel/payments.controls"
tm check "$work/chain"
tm report "$work/chain"
grep -q '^## Attack trees' "$work/chain/threatmodel/payments.md"
grep -q '^The chain, in order:' "$work/chain/threatmodel/payments.md"
grep -q '^3\. ' "$work/chain/threatmodel/payments.md"
echo "the chain reached the controls file and the report in order"

step "a sufficient control closes the whole route"
# Every control of the compiled file is implemented by now, so the first one
# is sufficient for the route; a control nothing holds fails the check.
sufficient=$(grep -m1 '^    control "' "$work/chain/threatmodel/payments.controls" | sed 's/^    control "\(.*\)" {$/\1/')
write_closed_tree() {
cat > "$work/chain/threatmodel/payments.attacktree" <<TREE
attack_trees for "Payments" {
  tree "obtain-the-records" {
    name           = "Obtain the records"
    raises_risk_by = 40
    closed_by      = ["$1"]

    goal "data-exfiltration" on component "db"

    then {
      step "ssrf-attack" on component "api"
      step "credential-theft" on component "api"
      step "unauthorized-access" on component "db"
    }
  }
}
TREE
}
write_closed_tree "$sufficient"
cp "$work/chain/threatmodel/payments.attacktree" "$work/chain-closed.attacktree"
tm format "$work/chain"
diff "$work/chain-closed.attacktree" "$work/chain/threatmodel/payments.attacktree"
tm compile "$work/chain"
grep -qF "closed_by      = \"$sufficient\"" "$work/chain/threatmodel/payments.controls"
grep -q 'state = "closes"' "$work/chain/threatmodel/payments.controls"
grep -q 'chain          = 0' "$work/chain/threatmodel/payments.controls"
tm check "$work/chain"
tm report "$work/chain"
grep -qF "closed by $sufficient" "$work/chain/threatmodel/payments.md"
write_closed_tree "No such control"
tm compile "$work/chain"
grep -q 'stale tree "obtain-the-records" {' "$work/chain/threatmodel/payments.controls"
grep -q 'state = "unknown"' "$work/chain/threatmodel/payments.controls"
expect_code 1 check "$work/chain"
set +e
unknown=$(tm check "$work/chain" 2>&1)
set -e
echo "$unknown" | grep -qF 'is closed by "No such control", which the catalogue and the libraries do not hold'
echo "the sufficient control closed the route and the unknown one failed the check"

step "cve sync fetches the feeds from a directory and writes the lock file"
# The three feeds, in the shape the services answer, as files: no network.
feeds="$work/feeds"
mkdir -p "$feeds/nvd"
cat > "$feeds/nvd/CVE-2023-44487.json" <<'JSON'
{ "vulnerabilities": [ { "cve": { "id": "CVE-2023-44487", "lastModified": "2024-08-01T15:23:00.000",
  "descriptions": [ { "lang": "en", "value": "The HTTP/2 protocol allows a denial of service." } ],
  "metrics": { "cvssMetricV31": [ { "cvssData": { "version": "3.1", "baseScore": 7.5 } } ] } } } ] }
JSON
cat > "$feeds/nvd/CVE-2024-7347.json" <<'JSON'
{ "vulnerabilities": [ { "cve": { "id": "CVE-2024-7347", "lastModified": "2024-08-14T10:00:00.000",
  "descriptions": [ { "lang": "en", "value": "A buffer over-read in the ngx_http_mp4_module." } ],
  "metrics": { "cvssMetricV31": [ { "cvssData": { "version": "3.1", "baseScore": 5.5 } } ] } } } ] }
JSON
cat > "$feeds/epss.json" <<'JSON'
{ "status": "OK", "data": [
  { "cve": "CVE-2023-44487", "epss": "0.94085", "percentile": "0.99", "date": "2026-09-15" },
  { "cve": "CVE-2024-7347", "epss": "0.0102", "percentile": "0.40", "date": "2026-09-15" } ] }
JSON
cat > "$feeds/kev.json" <<'JSON'
{ "catalogVersion": "2026.09.15", "dateReleased": "2026-09-15T14:00:00.000Z", "count": 1,
  "vulnerabilities": [ { "cveID": "CVE-2023-44487", "dateAdded": "2023-10-10" } ] }
JSON
mkdir -p "$work/cves/threatmodel"
cat > "$work/cves/threatmodel/payments.arch" <<'ARCH'
system "Payments" {
  component "api" {
    technology = "aws-ec2"
    data       = "confidential"
    version    = "1.24.0"
    cves       = ["CVE-2023-44487", "CVE-2024-7347"]
  }
}
ARCH
cp "$work/cves/threatmodel/payments.arch" "$work/cves-first.arch"
tm format "$work/cves"
diff "$work/cves-first.arch" "$work/cves/threatmodel/payments.arch"
tm compile "$work/cves"
# Before the sync, check warns for each CVE the lock file does not hold.
set +e
tm check "$work/cves" > "$work/cves-check.txt"
set -e
grep -q 'warning: the component "api" states CVE-2023-44487, which cve.lock.json does not hold' \
    "$work/cves-check.txt"
THREATMODELLER_CVE_FEEDS="$feeds" tm cve sync "$work/cves"
test -f "$work/cves/threatmodel/cve.lock.json"
grep -q '"epssDate" : "2026-09-15"' "$work/cves/threatmodel/cve.lock.json"
grep -q '"isKnownExploited" : true' "$work/cves/threatmodel/cve.lock.json"
cp "$work/cves/threatmodel/cve.lock.json" "$work/cves-lock-first.json"
THREATMODELLER_CVE_FEEDS="$feeds" tm cve sync "$work/cves" | grep -q unchanged
diff "$work/cves-lock-first.json" "$work/cves/threatmodel/cve.lock.json"
tm cve list "$work/cves" > "$work/cves-list.txt"
grep -q 'CVE-2023-44487 *7.50 *0.94 *KEV' "$work/cves-list.txt"
set +e
tm check "$work/cves" > "$work/cves-check.txt"
set -e
grep -q 'does not hold' "$work/cves-check.txt" && exit 1
echo "check says nothing about a CVE the lock file holds"

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
