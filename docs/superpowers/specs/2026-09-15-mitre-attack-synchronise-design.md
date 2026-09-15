# Synchronising MITRE ATT&CK — design

Date: 2026-09-15
Status: approved. It replaces `2026-09-13-mitre-attack-import-design.md`, which
states the same data and a different way of getting it.

**Issue:** #6, "Synchronise MITRE ATT&CK on the user's machine".

## 1. What changes

| Subject | The old design | This design |
| --- | --- | --- |
| Who downloads | a maintainer, before a release | the person, when they ask |
| Where the data sits | inside the application bundle | a data directory on the person's machine |
| What extracts it | a Python script | the application and the executable, in Swift |
| What is committed | `groups.json`, `techniques.json`, `mitre.lock.json` | the lock file only, in the project |
| A release | carries the matrix of that day | carries no matrix, and stays its size |

What does not change: the group to actor mapping (section 6.1 of the old
design), the lazy load, the technique names in the report, the `actors list`
verb, and the rule that a missing matrix reads as zero groups rather than
refusing to start.

## 2. Decision: where the data sits

**A per-user data directory**, so two projects on one machine share one copy
and nobody commits 396 KB of somebody else's data.

| Platform | Directory |
| --- | --- |
| macOS | `~/Library/Application Support/threatmodeller/attack` |
| Linux | `$XDG_DATA_HOME/threatmodeller/attack`, and `~/.local/share/threatmodeller/attack` when `XDG_DATA_HOME` is not set |

`AttackDataLocation.directory()` states it, and `THREATMODELLER_ATTACK_DIR`
overrides it, which is what a test and a build machine use.

**The lock file is the project's.** `<directory>/mitre.lock.json` sits beside
the systems, and a team commits it, so every machine synchronises the release
the team agreed on. The lock file names the tag and the checksum of each
written file; it never holds the data.

## 3. Decision: how a static Linux binary downloads

**A child `curl`.** The executable ships as a static musl binary, and
`FoundationNetworking` is neither small nor dependable in that build. `curl` is
on every machine that already runs `git`, which the library verbs need, so this
adds no requirement a person does not already meet.

One path for both platforms: macOS runs the same child `curl`. A machine with
no `curl` states `curl is not installed, so ATT&CK cannot be synchronised`, and
everything else in the application still works.

## 4. What a synchronise does

1. Reads the tag: the one a person named, else the one the project's lock file
   states, else `AttackRelease.default`.
2. States what it will do before it starts: the tag, the address and the size
   the release is (about 53 MB). The application asks; the executable prints it
   and carries on, because a person typed the verb.
3. Downloads
   `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/<tag>/enterprise-attack/enterprise-attack-<version>.json`
   into a temporary file. `<version>` is the tag without its leading `v`.
4. Extracts it in Swift, reading `intrusion-set` and `attack-pattern` objects
   and the `uses` relationships between them. Enterprise only: ICS and Mobile
   are never downloaded, so they cannot be read.
5. Writes `groups.json` and `techniques.json` into the data directory, in the
   shape sections 5.2 and 5.3 of the old design state, then deletes the bundle.
6. Writes `mitre.lock.json` into the project: the repository, the tag, the
   bundle path and the `sha256` of each written file.

A synchronise that fails at any step leaves the previous data where it is and
states what failed. The files are written to a temporary name and moved into
place, so a half-written file never becomes the data.

## 5. What a verify does

`threatmodeller attack verify` reads the two files on the machine, hashes them
and compares the hashes with the project's lock file. It makes no network call
and runs no child process. It answers one of:

- the data matches the lock file,
- the data is not there, and the tag the lock file states,
- the data does not match, naming the file.

## 6. When the application reaches the network

Only while a person is synchronising. Opening a project, drawing, compiling,
checking and reporting make no network call and start no child process for
ATT&CK. A test states it with a downloader that records every call.

## 7. What the code is

| Path | What it holds |
| --- | --- |
| `ThreatModelKit/attack/domain/AttackDataLocation.swift` | where the data sits |
| `ThreatModelKit/attack/domain/AttackBundle.swift` | the extraction, as a pure function of the bundle's bytes |
| `ThreatModelKit/attack/domain/AttackLock.swift` | the lock file |
| `ThreatModelKit/attack/gateway/AttackDataGateway.swift` | reads and writes the data directory |
| `ThreatModelKit/attack/gateway/AttackDownloading.swift` | fetches the bundle |
| `ThreatModelKit/attack/usecase/SynchroniseAttack.swift` | the steps of section 4 |
| `ThreatModelKit/attack/usecase/VerifyAttack.swift` | section 5 |
| `ThreatModelKit/attack/usecase/ListThreatActorsInUse.swift` | the `actors list` verb |
| `FileGateways/FileSystemAttackData.swift` | the real data directory |
| `FileGateways/CurlDownloader.swift` | the child `curl` |
| `CatalogueGateways/MitreActorCatalogue.swift` | the lazy read of `groups.json` |
