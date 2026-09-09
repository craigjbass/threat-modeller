# Releasing

This repository packages releases the way `craigjbass/clearancekit` does: a
signed, notarized DMG, a GitHub attestation, SLSA provenance, and a GitHub
release that carries all of it.

## What runs, and when

| Workflow | Starts on | Produces |
|---|---|---|
| `pr-test.yml` | a pull request to `main` | the package tests, the application tests, and the Linux job |
| `prerelease.yml` | a push to `main` | a pre-release named `v<marketing>.<next>-beta-<hash>` |
| `release.yml` | a tag matching `v*` | a release named after the tag |
| `linux.yml` | nothing; the other three call it | the package built and tested on Ubuntu, the executable run over a sample project, and, when the caller asks for them, the static Linux binaries |

`linux.yml` is a reusable workflow. `pr-test.yml` calls it for the tests alone.
`prerelease.yml` and `release.yml` call it with `build-binaries: true`, wait for
it, and carry what it makes.

`scripts/tag.sh` makes the next tag from `MARKETING_VERSION` and pushes it, so
publishing a version is one command:

```
./scripts/tag.sh
```

## What a release carries

- `threatmodeller-<version>.dmg` — the application, signed with Developer ID,
  notarized and stapled. It carries the command line executable at
  `Contents/Resources/threatmodeller-cli/`, with the catalogue beside it, and
  *Install Command Line Tool…* writes a link to it in the user's own
  `~/.local/bin`. `scripts/embed-cli.sh` puts it there and signs the bundle
  again, because adding a file to a signed bundle breaks its signature. It goes
  under `Resources` rather than `Helpers` because `codesign` treats every file
  under `Contents/Helpers` as code, and the catalogue is data.
- `threatmodeller-cli-<version>-macos.tar.gz` — the command line executable as a
  universal binary, with the threat catalogue beside it. It is signed and
  notarized; a tar archive cannot be stapled, so Gatekeeper checks it online the
  first time it runs.
- `threatmodeller-cli-<version>-linux-x86_64.tar.gz` and
  `threatmodeller-cli-<version>-linux-aarch64.tar.gz` — the command line
  executable for Linux, with the threat catalogue beside it. The static Linux
  SDK links musl and the Swift runtime into the file, so the target machine
  needs no Swift installed. The Linux job proves this with `ldd` before it
  uploads them.
- `threatmodeller-<version>.sigstore` — the GitHub build attestation.
- `threatmodeller-<version>.intoto.jsonl` — SLSA build provenance.

Every one of these is attested and named in the SLSA provenance.

Using the executable from the tarball:

```
tar xzf threatmodeller-cli-<version>-macos.tar.gz
cd threatmodeller-<version>
./threatmodeller check /path/to/your/project
```

It needs no `--catalogue` flag. The executable reads the directory it sits in
when `Library/` and `Actors/` are beside it, and it resolves its own path
through a symbolic link first, so this works too:

```
ln -sf "$PWD/threatmodeller" ~/.local/bin/threatmodeller
```

## The sandbox

**This application is not sandboxed.** `threatmodeller.entitlements` grants
`com.apple.security.files.user-selected.read-write` and nothing else.

The reason is the Libraries sheet. Fetching a library runs `git`, and a child
process inherits its parent's container. Inside one, `~` is redirected to
`~/Library/Containers/uk.craigbass.threatmodeller/Data`, so `git` reads an empty
`.ssh` rather than the user's, and `$SSH_AUTH_SOCK` names a socket the container
denies. A private repository could therefore not be fetched. The socket's path
changes with every login session, so no temporary exception entitlement can name
it.

**What this costs.** Inside the container a fault in this application reached one
directory. Outside it, a fault reaches what the user can reach. That is the price
of the window using the user's own `git` access.

**What does not change.** The Hardened Runtime, the Developer ID signature, the
notarization, the stapled ticket, the attestation and the SLSA provenance are all
as they were. Developer ID distribution does not require the sandbox; only the
Mac App Store does, and this application does not ship there.

Because there is no container, a recent project is stored as a path rather than
as a security-scoped bookmark. `RecentProjects` reads an older list that carries
a bookmark and uses its path.

## Setting the secrets

`scripts/setup-release-secrets.sh` makes the signing material and sets all six
secrets. It runs in two passes, because Apple does not let any API key create a
Developer ID certificate. The portal answers `This operation can only be
performed by the Account Holder`, and a team API key cannot hold that role.

| Pass | What it does |
|---|---|
| 1 | generates a private key and a certificate request, and prints what to do with the request |
| 2 | builds the `.p12` and sets the six secrets |

No secret value is written inside this repository. Pass 2 builds every file in a
temporary directory outside the working tree and deletes that directory on every
exit path. Values reach `gh` on standard input, so no value appears in the
shell history or in `ps` output.

**Step 1 — make an App Store Connect API key.** Apple does not issue its own API
key over the API, so make this one by hand. It is needed once.

1. Open <https://appstoreconnect.apple.com/access/integrations/api>.
2. Choose the **Team Keys** tab, then **+**.
3. Name the key `notarize-ci` and set Access to **Admin**.
4. Choose **Generate**, then **Download API Key**. Apple gives the file once
   only. It is named `AuthKey_<key id>.p8`.
5. Copy the **Issuer ID** from the top of the same page.

Keep the `.p8` file. The script reads it and never copies it, and Apple will not
give it again.

**Step 2 — install and sign in to `gh`.**

```
brew install gh
gh auth login
```

**Step 3 — run pass 1.**

```
./scripts/setup-release-secrets.sh \
  --asc-key ~/Downloads/AuthKey_<key id>.p8 \
  --issuer-id <issuer id>
```

The script writes `~/.threatmodeller-signing/key.pem` and
`~/.threatmodeller-signing/request.csr`, then prints the portal steps.

WARNING: `~/.threatmodeller-signing` holds a private key. Pass 2 needs it.
Delete it after pass 2 with `./scripts/setup-release-secrets.sh --forget`.
Anyone who holds that key and the certificate can sign as this team.

**Step 4 — get the certificate signed.** Sign in to the developer portal as the
**Account Holder**. No other role can do this.

1. Open <https://developer.apple.com/account/resources/certificates/add>.
2. Choose **Developer ID Application**, then Continue.
3. If the page asks about the profile type, choose **Direct**.
4. Upload `~/.threatmodeller-signing/request.csr`.
5. Choose Continue, then Download. The file is `developerID_application.cer`.

**Step 5 — run pass 2.**

```
./scripts/setup-release-secrets.sh \
  --asc-key ~/Downloads/AuthKey_<key id>.p8 \
  --issuer-id <issuer id> \
  --certificate ~/Downloads/developerID_application.cer
```

Pass 2:

1. checks that the certificate matches the key it generated in pass 1;
2. collects the issuer certificates above it, by reading the certificate's own
   "CA Issuers" address rather than guessing a URL;
3. builds a `.p12` from the key, the certificate and the chain, with a random
   password;
4. sets `DEVELOPER_ID_CERT_P12`, `DEVELOPER_ID_CERT_PASSWORD`,
   `KEYCHAIN_PASSWORD`, `ASC_API_KEY_ID`, `ASC_API_ISSUER_ID` and
   `ASC_API_PRIVATE_KEY`;
5. prints `gh secret list` and checks that the working tree did not change.

Both passes read the team identifier from `ExportOptions.plist` and call the
App Store Connect API once. That call proves the key identifier and the issuer
identifier are right here, in a second, rather than in the middle of a release.

`--dry-run` stops before it changes anything and prints what a real run would
do. `--list-certs` prints the Developer ID certificates the portal holds and
stops. `--yes` skips the question pass 2 asks before it writes.

**Step 6 — delete the private key and prove the release.**

```
./scripts/setup-release-secrets.sh --forget
git commit --allow-empty -m "ci: prove the release secrets" && git push
gh run watch
```

## The secrets a release needs

Set these in **Settings ▸ Secrets and variables ▸ Actions**.

`scripts/setup-release-secrets.sh` sets all six. The table says what each one
is, for the day the script is not there.

| Secret | What it is | How to make it |
|---|---|---|
| `DEVELOPER_ID_CERT_P12` | the Developer ID Application certificate and its private key, as base64 | the script builds it, or export the certificate from Keychain Access as a `.p12` and run `base64 -i cert.p12 \| pbcopy` |
| `DEVELOPER_ID_CERT_PASSWORD` | the password on that `.p12` | the script makes a random one |
| `KEYCHAIN_PASSWORD` | any password; it unlocks the keychain the job creates | the script makes a random one |
| `ASC_API_KEY_ID` | the App Store Connect API key identifier | App Store Connect ▸ Users and Access ▸ Integrations |
| `ASC_API_ISSUER_ID` | the issuer identifier on the same page | the same page |
| `ASC_API_PRIVATE_KEY` | the contents of the `AuthKey_<id>.p8` file, verbatim | downloaded once, when the key is created |

**There is no provisioning profile, and no `PROVISIONING_PROFILE_APP` secret.**
A Developer ID application needs a profile only for a capability that names an
entitlement Apple must grant, such as iCloud or Push. `threatmodeller.entitlements`
carries one key, `com.apple.security.files.user-selected.read-write`, and no
capability. `ExportOptions.plist` therefore names a team and a certificate and
nothing else, and neither workflow installs a profile. This also removes the
failure where the profile name in the portal and the name in
`ExportOptions.plist` differ.

## What is not automated

- **The version number.** `MARKETING_VERSION` in `threatmodeller.xcodeproj` is
  edited by hand. `scripts/tag.sh` reads it and counts the increment.
