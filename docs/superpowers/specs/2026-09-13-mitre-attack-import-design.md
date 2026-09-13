# The MITRE ATT&CK import — design

Date: 2026-09-13
Status: approved for planning

## 1. Why

`2026-09-13-threat-actors-design.md` gives the model a `threat_actor` block
with a capability and a list of MITRE technique ids. It gives a team nothing to
put in that block. A team that wants to say "we face FIN7" has to read the
ATT&CK website and copy 22 technique ids by hand, for every actor it names.

MITRE publishes the whole matrix as one STIX bundle, and the vendored threat
catalogue already names MITRE techniques on every threat. So the join exists;
the data is missing. This design vendors the data.

## 2. What the upstream data holds

Measured against `mitre-attack/attack-stix-data` at tag `v19.2`, file
`enterprise-attack/enterprise-attack-19.2.json`:

| Measure | Value |
| --- | --- |
| bundle size | 53,835,637 bytes |
| objects | 26,086 |
| `intrusion-set` objects | 191, of which 176 are neither revoked nor deprecated |
| `attack-pattern` objects | 858, of which 697 are neither revoked nor deprecated |
| `relationship` objects | 21,262 |
| techniques per group, direct | minimum 0, median 19, maximum 130 |
| groups with no direct technique | 4 |

Measured against the vendored catalogue's `threats/common-threats.json`:

| Measure | Value |
| --- | --- |
| threats | 55 |
| threats naming at least one technique | 55 |
| distinct technique ids named | 33 |
| threats an ATT&CK group performs, matched at parent level | 55 |

## 3. Scope

**In scope.** A script that downloads a pinned ATT&CK release and writes two
small JSON files and a lock file; a bundled provider that reads them; the
technique names in the report; one CLI verb that lists the ids a person may
put in `faces`.

**Out of scope.** ATT&CK campaigns, software, mitigations, data sources,
detection strategies and analytics. The bundle holds all of them. This design
reads `intrusion-set` and `attack-pattern` and nothing else.

**Out of scope.** The ICS and Mobile matrices. Enterprise only.

**Out of scope.** Any network call at run time. The application reads vendored
files, the way it reads the vendored catalogue.

**Out of scope.** Changing the likelihood rule. This design produces actors
that `ActorLikelihood` reads unchanged.

## 4. The script

`scripts/update-mitre.sh`, written to the shape of `scripts/update-catalogue.sh`:

```
scripts/update-mitre.sh update v19.2   download a release and rewrite the lock file
scripts/update-mitre.sh verify         re-check the vendored files against the lock file
```

`update` downloads
`https://raw.githubusercontent.com/mitre-attack/attack-stix-data/<tag>/enterprise-attack/enterprise-attack-<version>.json`
into a temporary directory, runs `scripts/extract-mitre.py`, writes the two
output files and the lock file, and deletes the bundle. The 53 MB bundle is
never committed.

`verify` re-checksums the two output files against the lock file. It runs no
child process and reaches no server, which is the promise
`threatmodeller library verify` already makes.

## 5. The extraction

`scripts/extract-mitre.py` reads the bundle and writes two files. It is a
plain function of its input, and `scripts/tests/test_extract_mitre.py` runs it
against a small fixture bundle, the way `scripts/tests/test_build_docs_page.py`
tests the docs script.

### 5.1 What it drops

- Any object with `revoked` true.
- Any object with `x_mitre_deprecated` true.
- Any object with no `mitre-attack` external reference, because it has no
  `Txxxx` or `Gxxxx` identifier to name it by.

### 5.2 `Resources/Mitre/groups.json`

301,416 bytes at v19.2, 176 groups.

```json
{
  "release": "v19.2",
  "groups": [
    {
      "id": "fin7",
      "attackId": "G0046",
      "name": "FIN7",
      "aliases": ["Carbon Spider", "ELBRUS", "Sangria Tempest"],
      "description": "FIN7 is a financially motivated threat group ...",
      "techniques": ["T1059", "T1204", "T1566"],
      "techniquesViaSoftware": ["T1027", "T1105"]
    }
  ]
}
```

| Field | From |
| --- | --- |
| `id` | the group's name, lower case, every run of characters that is not a letter or a digit becomes one hyphen, and a hyphen never starts or ends it |
| `attackId` | the `mitre-attack` external reference |
| `name`, `aliases`, `description` | the object, with the description cut at the first paragraph and at 400 characters |
| `techniques` | a `uses` relationship from the group straight to a technique |
| `techniquesViaSoftware` | a `uses` relationship from the group to a malware or tool, and from that software to a technique |

The id rule is the rule `ProjectConvention.fileName(forSystemNamed:)` already
applies to a system name. Measured at v19.2 it gives 176 distinct ids and no
collision, so the ids `admin-338`, `apt1` and `lazarus-group` each name one
group.

`techniquesViaSoftware` is written and is not read by the likelihood rule. A
group uses a tool that does a hundred things; that is not the same claim as the
group doing them. The field is there so a later design can read it without a
re-import.

### 5.3 `Resources/Mitre/techniques.json`

95,200 bytes at v19.2, 697 techniques.

```json
{
  "release": "v19.2",
  "techniques": [
    { "id": "T1566", "name": "Phishing", "tactics": ["initial-access"], "subtechnique": false }
  ]
}
```

The report reads this file to print a technique's name beside its id. Nothing
else reads it.

### 5.4 `Resources/Mitre/mitre.lock.json`

```json
{
  "repository": "mitre-attack/attack-stix-data",
  "tag": "v19.2",
  "bundle": "enterprise-attack/enterprise-attack-19.2.json",
  "bundleSha256": "…",
  "files": {
    "groups.json": "…",
    "techniques.json": "…"
  }
}
```

`bundleSha256` records what the two files were derived from, so a person can
prove the import again from the same input.

## 6. How the application reads it

### 6.1 The provider

`CatalogueGateways/MitreActorCatalogue.swift` reads the two files and returns
`[ThreatActor]`. Every group becomes one actor:

| `ThreatActor` field | Value |
| --- | --- |
| `id` | `mitre-<group id>`, so `mitre-fin7` |
| `name` | the group name |
| `description` | the group description |
| `aliases` | the group aliases |
| `capability` | `targeted`, for every group |
| `intent` | empty |
| `performs` | empty |
| `techniques` | the group's `techniques` |
| `performsCatalogueTier` | none |

Every group reads `targeted` because ATT&CK states no frequency and a named
intrusion set is not commodity malware. A team that disagrees writes a local
override, which section 3.2 of the threat-actor design already allows:

```hcl
threat_actor "mitre-fin7" { name = "FIN7" capability = "commodity" }
```

A group with no technique at all — 4 of the 176 at v19.2 — becomes an actor
that performs nothing. `ActorLikelihood` returns no performer for it, and the
threat-actor design's warning `the threat actor "<id>" performs no threat this
model raises` tells the person who faced it.

### 6.2 Loading is lazy

The two files parse the first time something asks for a `mitre-` actor. A
project that faces no MITRE group parses neither file, so the 396 KB costs an
existing project nothing at open time.

### 6.3 A missing directory

`CatalogueLocation.directoryBeside` tests for `Library` and `Actors` beside the
executable. It keeps that test. A release tarball built before this design has
no `Mitre` directory, and the application reads it as zero groups rather than
refusing to start. A `faces` entry naming a `mitre-` id then gives the
threat-actor design's error `this project holds no threat actor called
"mitre-fin7"`, which says what is wrong.

### 6.4 The report

`MarkdownThreatStanza` prints a technique's name and first tactic beside its
id, read from `techniques.json`:

```markdown
- MITRE ATT&CK: T1552 Unsecured Credentials (credential-access), T1078 Valid Accounts (defense-evasion)
```

A technique id the file does not hold prints as the bare id, which is what the
report prints today.

## 7. The CLI

```
threatmodeller actors list [<root>]        say what threat actors this project may face
threatmodeller actors list --mitre [<root>]  the imported ATT&CK groups only
```

It prints one line per actor: the id, the name, the capability, and the count
of threats in this project's catalogue that the actor performs. The count is
what makes the list useful: it says which of the 176 groups touch this model.

## 8. The finding a reader must not be given

Matching is at parent-technique level, and parent techniques are broad.
Measured at v19.2 against the vendored catalogue:

| Technique | Groups that perform it |
| --- | --- |
| `T1059` Command and Scripting Interpreter | 124 of 176 |
| `T1204` User Execution | 99 |
| `T1027` Obfuscated Files or Information | 93 |
| `T1078` Valid Accounts | 66 |
| `T1562` Impair Defenses | 0 |

So a model that faces three or four real groups marks most of its threats as
performed by a `targeted` actor. The effect on the numbers is small, because a
threat the catalogue already marks `commodity` keeps 1.0 once
`commodity-crimeware` is faced. The effect on the report is large and correct:
the reader learns which named adversaries perform each threat.

The spec states this so that nobody reads a long `Performed by:` line as
evidence that the model is under sustained attack by 124 groups. The report
section in the threat-actor design prints the actor count per threat, not a
threat level.

## 9. Testing

| Test | Says |
| --- | --- |
| `scripts/tests/test_extract_mitre.py` | a fixture bundle with one group, one revoked group, one deprecated technique produces one group and no revoked or deprecated object |
| | the id rule turns `admin@338` into `admin-338` and `Threat Group-3390` into `threat-group-3390` |
| | a technique reached only through a tool lands in `techniquesViaSoftware` and not in `techniques` |
| `MitreActorCatalogueTests` | a group becomes an actor with `capability` targeted and the id `mitre-<slug>` |
| | a missing `Mitre` directory reads as zero actors and throws nothing |
| | the files parse once, and not at all when nothing asks for a `mitre-` id |
| `MarkdownThreatStanzaTests` | a known technique prints its name and tactic; an unknown one prints the bare id |
| `CommandLineToolTests` | `actors list` prints the built-in actor, and `--mitre` prints only imported ones |

The vendored files are committed, so the Swift tests read the real 176 groups
rather than a fixture. One test asserts the counts of section 2, so a future
`update-mitre.sh update` that changes the shape of the data fails a test rather
than passing quietly.

## 10. Where the code goes

| File | Change |
| --- | --- |
| `scripts/update-mitre.sh` | new |
| `scripts/extract-mitre.py` | new |
| `scripts/tests/test_extract_mitre.py` | new |
| `CatalogueGateways/Resources/Mitre/groups.json` | new, vendored |
| `CatalogueGateways/Resources/Mitre/techniques.json` | new, vendored |
| `CatalogueGateways/Resources/Mitre/mitre.lock.json` | new, vendored |
| `CatalogueGateways/MitreActorCatalogue.swift` | new |
| `CatalogueGateways/MitreJSON.swift` | new |
| `CatalogueGateways/BundledTechnologyCatalogue.swift` | serves the imported actors beside the built-in one |
| `reporting/usecase/MarkdownThreatStanza.swift` | technique names |
| `CommandLineApplication/CommandLineApplication.swift` | `actors list`, and the usage text |
| `scripts/embed-cli.sh`, `scripts/build-linux.sh` | copy `Mitre/` beside the executable |
| `docs/LANGUAGE.md` | the `mitre-` id form in the actor section |
| `README.md` | the new verb |

## 11. What this design does not close

- An actor's reach, which the threat-actor design also leaves out.
- ATT&CK campaigns, which say when a group was active. A model that wants
  "active in the last two years" needs them.
- Sector and region. ATT&CK does not carry either in a form worth reading, so
  a team that only faces adversaries in its sector still picks the groups by
  hand.
