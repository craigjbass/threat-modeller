# Releasing

This repository packages releases the way `craigjbass/clearancekit` does: a
signed, notarized DMG, a GitHub attestation, SLSA provenance, and a GitHub
release that carries all of it.

## What runs, and when

| Workflow | Starts on | Produces |
|---|---|---|
| `pr-test.yml` | a pull request to `main` | the package tests and the application tests |
| `linux.yml` | a push to `main`, and a pull request | the package built and tested on Ubuntu, and the executable run over a sample project |
| `prerelease.yml` | a push to `main` | a pre-release named `v<marketing>.<next>-beta-<hash>` |
| `release.yml` | a tag matching `v*` | a release named after the tag |

`scripts/tag.sh` makes the next tag from `MARKETING_VERSION` and pushes it, so
publishing a version is one command:

```
./scripts/tag.sh
```

## What a release carries

- `threatmodeller-<version>.dmg` — the application, signed with Developer ID,
  notarized and stapled.
- `threatmodeller-cli-<version>-macos.tar.gz` — the command line executable as a
  universal binary, with the threat catalogue beside it. It is signed and
  notarized; a tar archive cannot be stapled, so Gatekeeper checks it online the
  first time it runs.
- `threatmodeller-<version>.sigstore` — the GitHub build attestation.
- `threatmodeller-<version>.intoto.jsonl` — SLSA build provenance.

Using the executable from the tarball:

```
tar xzf threatmodeller-cli-<version>-macos.tar.gz
cd threatmodeller-<version>
./threatmodeller --catalogue . check /path/to/your/project
```

## The secrets a release needs

Set these in **Settings ▸ Secrets and variables ▸ Actions**.

| Secret | What it is | How to make it |
|---|---|---|
| `DEVELOPER_ID_CERT_P12` | the Developer ID Application certificate and its private key, as base64 | export the certificate from Keychain Access as a `.p12`, then `base64 -i cert.p12 \| pbcopy` |
| `DEVELOPER_ID_CERT_PASSWORD` | the password set on that `.p12` | chosen during the export |
| `KEYCHAIN_PASSWORD` | any password; it unlocks the keychain the job creates | make one up |
| `PROVISIONING_PROFILE_APP` | the Developer ID provisioning profile for `uk.craigbass.threatmodeller`, as base64 | download the profile from the developer portal, then `base64 -i profile.provisionprofile \| pbcopy` |
| `ASC_API_KEY_ID` | the App Store Connect API key identifier | App Store Connect ▸ Users and Access ▸ Integrations |
| `ASC_API_ISSUER_ID` | the issuer identifier on the same page | the same page |
| `ASC_API_PRIVATE_KEY` | the contents of the `AuthKey_<id>.p8` file, verbatim | downloaded once, when the key is created |

**`PROVISIONING_PROFILE_OPFILTER` is not needed here.** That secret exists in
`clearancekit` because that application ships a network extension in a second
target. This application has one signed bundle, so it has one profile.

The profile in `ExportOptions.plist` is named `threatmodeller Developer ID`.
The profile in the developer portal must carry that name, or the export step
fails with "no profile for team 37KMK6XFTT matching 'threatmodeller Developer
ID' found".

## What is not automated

- **The Linux binaries.** `scripts/build-linux.sh` cross-compiles them from a
  machine with the static Linux SDK installed. No job builds them, so no release
  carries them.
- **The version number.** `MARKETING_VERSION` in `threatmodeller.xcodeproj` is
  edited by hand. `scripts/tag.sh` reads it and counts the increment.
