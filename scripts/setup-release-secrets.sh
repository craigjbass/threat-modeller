#!/usr/bin/env bash
#
# Make the signing material a release needs, then set it as GitHub secrets.
#
# Apple does not let any API key create a Developer ID certificate: the portal
# answers "This operation can only be performed by the Account Holder", and a
# team API key cannot hold that role. So the work splits in two.
#
#   Pass 1  no --certificate
#           The script generates a private key and a certificate request, and
#           prints what to do with the request in the portal.
#
#   Pass 2  --certificate <the .cer the portal gave>
#           The script builds the .p12 and sets the six repository secrets.
#
# NO SECRET VALUE IS EVER WRITTEN INSIDE THIS REPOSITORY. Pass 2 builds every
# file in a temporary directory outside the working tree and a trap deletes
# that directory on every exit path. Secret values reach `gh` on standard
# input, so no value appears in the shell history or in `ps` output.
#
# WARNING: the private key from pass 1 stays in ~/.threatmodeller-signing so
# that pass 2 can use it. Run the script with --forget after pass 2 to delete
# it. Anyone who holds that key and the certificate can sign as this team.
#
# The App Store Connect API key is made by hand, once:
#   https://appstoreconnect.apple.com/access/integrations/api
#   Team Keys > + > Access: Admin > Generate > Download API Key
#
# Usage:
#   scripts/setup-release-secrets.sh --asc-key ~/Downloads/AuthKey_ABC1234567.p8 \
#                                    --issuer-id 12a34b56-c789-0123-4567-89abcdef0123
#
# See docs/RELEASING.md.

set -euo pipefail

API="https://api.appstoreconnect.apple.com"

# macOS ships LibreSSL at /usr/bin/openssl. A PKCS#12 file that Homebrew's
# OpenSSL 3 writes uses encryption that `security import` on the runner rejects,
# so the script names the system tool rather than taking whatever is on PATH.
OPENSSL=/usr/bin/openssl

SIGNING_DIR="${SIGNING_DIR:-$HOME/.threatmodeller-signing}"

CERT_FILTER="filter%5BcertificateType%5D=DEVELOPER_ID_APPLICATION_G2,DEVELOPER_ID_APPLICATION&limit=200"

ASC_KEY=""
KEY_ID=""
ISSUER_ID=""
CERTIFICATE=""
REPO=""
ASSUME_YES=0
DRY_RUN=0
LIST_CERTS=0
FORGET=0

usage() {
  sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }
note() { printf '==> %s\n' "$1"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --asc-key)     ASC_KEY="$2"; shift 2 ;;
    --key-id)      KEY_ID="$2"; shift 2 ;;
    --issuer-id)   ISSUER_ID="$2"; shift 2 ;;
    --certificate) CERTIFICATE="$2"; shift 2 ;;
    --repo)        REPO="$2"; shift 2 ;;
    --signing-dir) SIGNING_DIR="$2"; shift 2 ;;
    --yes)         ASSUME_YES=1; shift ;;
    --dry-run)     DRY_RUN=1; shift ;;
    --list-certs)  LIST_CERTS=1; shift ;;
    --forget)      FORGET=1; shift ;;
    -h|--help)     usage 0 ;;
    *)             die "unknown option: $1" ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# --------------------------------------------------------------------- forget

if [[ "$FORGET" -eq 1 ]]; then
  if [[ -d "$SIGNING_DIR" ]]; then
    rm -rf "$SIGNING_DIR"
    note "deleted $SIGNING_DIR"
  else
    note "$SIGNING_DIR does not exist"
  fi
  exit 0
fi

# --------------------------------------------------------------- preconditions

for tool in curl jq python3 plutil "$OPENSSL"; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed"
done

command -v gh >/dev/null 2>&1 || die "gh is not installed. Run: brew install gh && gh auth login"
gh auth status >/dev/null 2>&1 || die "gh is not authenticated. Run: gh auth login"

[[ -n "$ASC_KEY" ]] || die "--asc-key is required (the AuthKey_<id>.p8 file)"
[[ -f "$ASC_KEY" ]] || die "no such file: $ASC_KEY"
[[ -n "$ISSUER_ID" ]] || die "--issuer-id is required (App Store Connect > Integrations)"

if [[ -z "$KEY_ID" ]]; then
  KEY_ID="$(basename "$ASC_KEY")"
  KEY_ID="${KEY_ID#AuthKey_}"
  KEY_ID="${KEY_ID%.p8}"
fi
[[ "$KEY_ID" =~ ^[A-Z0-9]{10}$ ]] || die "key identifier '$KEY_ID' is not 10 characters. Pass --key-id."

if [[ -z "$REPO" ]]; then
  REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
fi

TREE_BEFORE="$(git -C "$REPO_ROOT" status --porcelain)"

PLIST="$REPO_ROOT/ExportOptions.plist"
[[ -f "$PLIST" ]] || die "ExportOptions.plist is missing"
TEAM_ID="$(plutil -convert json -o - "$PLIST" | jq -r '.teamID // empty')"
[[ -n "$TEAM_ID" ]] || die "ExportOptions.plist does not name a team"

note "repository       $REPO"
note "team             $TEAM_ID"

# ------------------------------------------------------------- temp workspace

TMP="$(mktemp -d "${TMPDIR:-/tmp}/threatmodeller-secrets.XXXXXX")"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

case "$TMP" in
  "$REPO_ROOT"*) die "the temporary directory is inside the repository: $TMP" ;;
esac
chmod 700 "$TMP"

# --------------------------------------------------------------- the API token

# The release itself uses the App Store Connect key only for notarytool. The
# script calls the API once so that a wrong key identifier or issuer identifier
# fails here, in a second, rather than in the middle of a release.

cat > "$TMP/mkjwt.py" <<'PY'
"""Mint an ES256 JSON Web Token for the App Store Connect API.

The token is signed by /usr/bin/openssl, so the script needs no Python package
beyond the standard library. openssl writes an ECDSA signature in DER form and
the API wants the raw r||s pair, so this converts one to the other.
"""
import base64
import json
import subprocess
import sys
import time

key_path, key_id, issuer_id = sys.argv[1], sys.argv[2], sys.argv[3]


def b64u(raw: bytes) -> bytes:
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def compact(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode()


now = int(time.time())
header = {"alg": "ES256", "kid": key_id, "typ": "JWT"}
payload = {"iss": issuer_id, "iat": now, "exp": now + 1140, "aud": "appstoreconnect-v1"}
signing_input = b64u(compact(header)) + b"." + b64u(compact(payload))

der = subprocess.run(
    ["/usr/bin/openssl", "dgst", "-sha256", "-sign", key_path],
    input=signing_input,
    capture_output=True,
    check=True,
).stdout


def der_to_raw(signature: bytes, size: int = 32) -> bytes:
    if signature[0] != 0x30:
        raise ValueError("the signature does not start with a DER SEQUENCE")
    index = 2
    if signature[1] & 0x80:
        index = 2 + (signature[1] & 0x7F)
    out = b""
    for _ in range(2):
        if signature[index] != 0x02:
            raise ValueError("the signature is missing a DER INTEGER")
        length = signature[index + 1]
        value = signature[index + 2 : index + 2 + length].lstrip(b"\x00")
        index += 2 + length
        out += value.rjust(size, b"\x00")
    return out


sys.stdout.write((signing_input + b"." + b64u(der_to_raw(der))).decode())
PY

TOKEN="$(python3 "$TMP/mkjwt.py" "$ASC_KEY" "$KEY_ID" "$ISSUER_ID")"

# asc <METHOD> <PATH>
# Writes the response body to $TMP/resp.json and sets HTTP_CODE.
asc() {
  HTTP_CODE="$(curl -sS -o "$TMP/resp.json" -w '%{http_code}' -X "$1" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" "$API$2")"
}

asc_or_die() {
  asc "$@"
  case "$HTTP_CODE" in 2*) return 0 ;; esac
  printf 'ERROR: the App Store Connect API answered HTTP %s for %s %s\n' "$HTTP_CODE" "$1" "$2" >&2
  if ! jq -e -r '.errors[] | "  \(.title): \(.detail)"' "$TMP/resp.json" >&2; then
    cat "$TMP/resp.json" >&2
  fi
  exit 1
}

# Read a certificate in DER or PEM form and write PEM to the second path.
to_pem() {
  "$OPENSSL" x509 -inform DER -in "$1" -out "$2" 2>/dev/null \
    || "$OPENSSL" x509 -inform PEM -in "$1" -out "$2"
}

note "checking the API key"
asc_or_die GET "/v1/certificates?$CERT_FILTER"
note "Developer ID Application certificates in the portal: $(jq -r '.data | length' "$TMP/resp.json")"

if [[ "$LIST_CERTS" -eq 1 ]]; then
  jq -r '.data[] | "\(.id)  \(.attributes.certificateType)  expires \(.attributes.expirationDate)  \(.attributes.name)"' \
    "$TMP/resp.json"
  exit 0
fi

# -------------------------------------------------------- pass 1: the request

if [[ -z "$CERTIFICATE" ]]; then
  mkdir -p "$SIGNING_DIR"
  chmod 700 "$SIGNING_DIR"

  if [[ -f "$SIGNING_DIR/key.pem" && -f "$SIGNING_DIR/request.csr" ]]; then
    note "a certificate request already exists in $SIGNING_DIR"
  else
    note "generating the private key and the certificate request"
    "$OPENSSL" req -new -newkey rsa:2048 -nodes \
      -keyout "$SIGNING_DIR/key.pem" -out "$SIGNING_DIR/request.csr" \
      -subj "/CN=threatmodeller Developer ID/O=$TEAM_ID/C=GB" >/dev/null 2>&1
    chmod 600 "$SIGNING_DIR/key.pem"
  fi

  cat <<PASS1

Apple only lets the Account Holder create a Developer ID certificate, and it
refuses the App Store Connect API for this one operation. Do these steps in the
browser, signed in as the Account Holder:

  1. Open https://developer.apple.com/account/resources/certificates/add
  2. Choose "Developer ID Application", then Continue.
     If it asks about the profile type, choose "Direct" (not "G2 Sub-CA").
  3. Upload this certificate request:
       $SIGNING_DIR/request.csr
  4. Choose Continue, then Download. The file is developerID_application.cer.

Then run pass 2:

  ./scripts/setup-release-secrets.sh \\
    --asc-key $ASC_KEY \\
    --issuer-id $ISSUER_ID \\
    --certificate ~/Downloads/developerID_application.cer

WARNING: $SIGNING_DIR now holds a private key. Pass 2 needs it. Delete it after
pass 2 with:

  ./scripts/setup-release-secrets.sh --forget

PASS1
  exit 0
fi

# ------------------------------------------------------ pass 2: the material

[[ -f "$CERTIFICATE" ]] || die "no such file: $CERTIFICATE"
[[ -f "$SIGNING_DIR/key.pem" ]] \
  || die "$SIGNING_DIR/key.pem is missing. Run the script without --certificate first."

note "reading the certificate"
to_pem "$CERTIFICATE" "$TMP/cert.pem"

# A certificate that does not match the stored key would produce a .p12 that
# signs nothing, and the failure would only show on the runner. Check it here.
if [[ "$("$OPENSSL" x509 -in "$TMP/cert.pem" -noout -pubkey)" \
   != "$("$OPENSSL" pkey -in "$SIGNING_DIR/key.pem" -pubout)" ]]; then
  die "the certificate does not match the key in $SIGNING_DIR. Upload $SIGNING_DIR/request.csr, not an older request."
fi
note "$("$OPENSSL" x509 -in "$TMP/cert.pem" -noout -subject)"
note "$("$OPENSSL" x509 -in "$TMP/cert.pem" -noout -enddate)"

# The runner builds a keychain from nothing, so the certificate alone does not
# chain to a root. Follow the "CA Issuers" address in the certificate and
# collect every issuer above it. Reading the address avoids guessing a URL.
note "collecting the issuer certificates"
: > "$TMP/chain.pem"
current="$TMP/cert.pem"
for _ in 1 2 3 4 5; do
  subject="$("$OPENSSL" x509 -in "$current" -noout -subject)"
  issuer="$("$OPENSSL" x509 -in "$current" -noout -issuer)"
  [[ "${subject#subject=}" == "${issuer#issuer=}" ]] && break

  uri="$("$OPENSSL" x509 -in "$current" -noout -text \
    | awk -F'URI:' '/CA Issuers - URI:/ {print $2; exit}' | tr -d ' \r')"
  [[ -n "$uri" ]] || { note "no issuer address in the certificate; the chain stops here"; break; }

  curl -sS -f -o "$TMP/issuer.cer" "$uri" || { note "the issuer certificate did not download from $uri"; break; }
  to_pem "$TMP/issuer.cer" "$TMP/issuer.pem"
  cat "$TMP/issuer.pem" >> "$TMP/chain.pem"
  mv "$TMP/issuer.pem" "$TMP/current-issuer.pem"
  current="$TMP/current-issuer.pem"
done
note "issuer certificates collected: $(grep -c 'BEGIN CERTIFICATE' "$TMP/chain.pem" || true)"

note "building the PKCS#12 file"
"$OPENSSL" rand -hex 24 | tr -d '\n' > "$TMP/p12-password.txt"
p12_args=(pkcs12 -export -inkey "$SIGNING_DIR/key.pem" -in "$TMP/cert.pem"
          -name "Developer ID Application" -passout "file:$TMP/p12-password.txt"
          -out "$TMP/certificate.p12")
if [[ -s "$TMP/chain.pem" ]]; then p12_args+=(-certfile "$TMP/chain.pem"); fi
"$OPENSSL" "${p12_args[@]}"
base64 < "$TMP/certificate.p12" | tr -d '\n' > "$TMP/p12-base64.txt"

# ------------------------------------------------------------------ the secrets

"$OPENSSL" rand -hex 24 | tr -d '\n' > "$TMP/keychain-password.txt"
printf '%s' "$KEY_ID" > "$TMP/asc-key-id.txt"
printf '%s' "$ISSUER_ID" > "$TMP/asc-issuer-id.txt"
cp "$ASC_KEY" "$TMP/asc-private-key.txt"

if [[ "$DRY_RUN" -eq 1 ]]; then
  cat <<PLAN

A real run would set these secrets on $REPO:
  DEVELOPER_ID_CERT_P12  DEVELOPER_ID_CERT_PASSWORD  KEYCHAIN_PASSWORD
  ASC_API_KEY_ID  ASC_API_ISSUER_ID  ASC_API_PRIVATE_KEY

PLAN
  exit 0
fi

if [[ "$ASSUME_YES" -eq 0 ]]; then
  read -r -p "Set the six secrets on $REPO? [y/N] " answer
  [[ "$answer" == "y" || "$answer" == "Y" ]] || die "cancelled by the operator"
fi

set_secret() {
  local name="$1" file="$2" size
  size="$(wc -c < "$file" | tr -d ' ')"
  # gh has no --body-file. Without --body it reads the value from standard
  # input, so the value still never appears in argv or in the shell history.
  gh secret set "$name" --repo "$REPO" < "$file" >/dev/null
  printf '    set %-28s %s bytes\n' "$name" "$size"
}

note "writing the repository secrets on $REPO"
set_secret DEVELOPER_ID_CERT_P12      "$TMP/p12-base64.txt"
set_secret DEVELOPER_ID_CERT_PASSWORD "$TMP/p12-password.txt"
set_secret KEYCHAIN_PASSWORD          "$TMP/keychain-password.txt"
set_secret ASC_API_KEY_ID             "$TMP/asc-key-id.txt"
set_secret ASC_API_ISSUER_ID          "$TMP/asc-issuer-id.txt"
set_secret ASC_API_PRIVATE_KEY        "$TMP/asc-private-key.txt"

# ------------------------------------------------------------------- the proof

note "the repository now holds these secrets"
gh secret list --repo "$REPO" | sed 's/^/    /'

if [[ "$(git -C "$REPO_ROOT" status --porcelain)" != "$TREE_BEFORE" ]]; then
  printf 'WARNING: the working tree changed while the script ran. Check `git status`.\n' >&2
else
  note "the working tree is unchanged; no secret reached the repository"
fi

cat <<DONE

Done. Delete the private key now that the .p12 exists:

  ./scripts/setup-release-secrets.sh --forget

Then start the pre-release workflow:

  git commit --allow-empty -m "ci: prove the release secrets" && git push
  gh run watch --repo $REPO

DONE
