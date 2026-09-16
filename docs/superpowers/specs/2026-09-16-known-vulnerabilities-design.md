# Known vulnerabilities in the model — design

Date: 2026-09-16
Status: decided

**Issue:** #131, "The model states no known vulnerability, so a CVE moves no
score and reaches no report".

## 1. Why

A technology states the threats its kind faces. Nothing states a known
vulnerability in the version a component runs, so a CVE against a library or a
product the system uses is not in the model, not in the score and not in the
report. A person who picks a threat on the diagram has no way to find which
CVEs apply to the component the threat is raised on, so a list written by hand
is the only source.

This design gives the model a place to name a CVE, a verb that brings the
facts about each named CVE onto the machine, a rule that turns a known
exploited vulnerability into a likelihood, a rule that ranks each CVE, a
report section, two fields on the component panel, a line on the threat card,
and a lookup that runs a tool the person installed.

## 2. Decision: where a CVE attaches

**A `version` and a `cves` list on a `component`.**

| Place | Why not |
| --- | --- |
| `technology` | A technology is a kind, shared by every component that names it and by every system that reads the library. `aws-ec2` has no version; the box that runs nginx 1.24.0 does. Two components with one technology run two versions. |
| `third_party` | A third party is a company, a project or a person, and its `uptime` states what happens when it stops. A CVE is against software a component runs, whether a third party runs that component or not. A component with `provided_by` states its own `cves`. |
| `component` | The threat is raised on the component, the score is per component, the threat card is per component, and the version is the version this box runs. |

### 2.1 The language

```hcl
component "api" {
  technology = "nginx"
  version    = "1.24.0"
  cves       = ["CVE-2023-44487", "CVE-2024-7347"]
}
```

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `version` | string | any | empty |
| `cves` | string list | CVE ids in the form `CVE-<year>-<digits>` | none |

A component that states no `version` writes no `version` line, and a
component that states no `cves` writes no `cves` line, so every file written
before the two attributes reads and writes byte for byte. The writer keeps
the order the file states.

`version` on a `system` block is the document version and stays what it is.
The two share a keyword and no meaning, the way `name` does across blocks.

### 2.2 What the parser refuses

| Check | Severity | Message |
| --- | --- | --- |
| a `cves` entry not in the form `CVE-<year>-<digits>` | error | `the component "<id>" states cves "<word>", which is not a CVE id` |
| a `cves` entry stated twice on one component | warning | `the component "<id>" states "<cve>" twice`; the second entry is dropped |

The form is `CVE-`, four digits, `-`, four or more digits, upper case. The
parser normalises nothing: a lower case `cve-` is not a CVE id, so the file
round-trips byte for byte.

## 3. Decision: where the data comes from, and where it sits

### 3.1 The three sources

| Fact | Source | Address |
| --- | --- | --- |
| CVSS base score and summary | NVD | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<id>`, one request per CVE |
| EPSS probability and its date | FIRST | `https://api.first.org/data/v1/epss?cve=<id>,<id>,…`, one request for every CVE |
| Known exploited, and the catalogue version | CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, one request |

The CVSS taken is the highest metric version NVD states for the CVE: `4.0`,
else `3.1`, else `3.0`, else `2.0`, and the first entry of that version. A CVE
NVD holds and has not scored has no CVSS. A CVE EPSS does not list has no
EPSS. A CVE NVD does not hold is a fault the sync names, and the sync writes
nothing for it.

WARNING: NVD answers five requests in thirty seconds to a caller with no key.
The sync waits six seconds between NVD requests after the fifth. A project
that names thirty CVEs waits about three minutes; the verb prints each CVE as
it arrives so a person sees the wait is the wait.

### 3.2 The lock file holds the data

**`threatmodel/cve.lock.json` holds the records, and a team commits it.**

The ATT&CK lock file holds checksums and never the data, because the data is
396 KB of somebody else's whole matrix and a per-user directory shares one
copy between projects. A CVE record is a few hundred bytes about a CVE this
team named, and the score reads it. A score that reads a file outside the
project is a score two machines compute differently, and a check that fails
on one machine and passes on another. So the lock file is the data, and a
machine that has the project has the score.

```json
{
  "cves" : {
    "CVE-2023-44487" : {
      "cvss" : 7.5,
      "cvssVersion" : "3.1",
      "epss" : 0.94,
      "isKnownExploited" : true,
      "kevDateAdded" : "2023-10-10",
      "modified" : "2024-08-01T15:23:00.000",
      "summary" : "The HTTP/2 protocol allows a denial of service…"
    }
  },
  "epssDate" : "2026-09-15",
  "kevCatalogueVersion" : "2026.09.15",
  "sources" : {
    "epss" : "https://api.first.org/data/v1/epss",
    "kev" : "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "nvd" : "https://services.nvd.nist.gov/rest/json/cves/2.0"
  }
}
```

**The stated date is the upstream's.** `epssDate` is the date the EPSS feed
states, `kevCatalogueVersion` is the version the KEV catalogue states, and
`modified` is NVD's `lastModified` for that CVE. No field is the local clock.
A second sync against an unchanged upstream writes the same bytes, so a diff
of the lock file is a diff of the world, never of the day the sync ran.

The file is pretty-printed with sorted keys, so a diff of one CVE is one
stanza. A CVE no `.arch` file names any more is dropped on the next sync.

### 3.3 The verbs

```
threatmodeller cve sync [<root>]   fetch CVSS, EPSS and KEV for every CVE the project names
threatmodeller cve list [<root>]   say what the lock file holds, one row per CVE with its priority
```

`sync` reads every `.arch` file of every system in the project, collects the
`cves` entries, fetches the three sources, and writes the lock file. The
window offers the same in the toolbar as *Synchronise CVEs*, and asks first,
the way *Synchronise ATT&CK* asks. A sync that fails at any step leaves the
previous lock file where it is and states what failed. A project that names
no CVE writes no lock file and says so.

`list` reads the lock file and prints one row per CVE: the id, the CVSS, the
EPSS, `KEV` or `-`, and the priority of section 5. It makes no network call.

The download goes through `AttackDownloading`, which is the child `curl` the
ATT&CK synchronise already runs. The application reaches the network through
that port and nothing else. A machine with no `curl` states
`curl is not installed, so CVEs cannot be synchronised`.

### 3.4 The gateway boundary

```swift
public protocol VulnerabilitySource: Sendable {
    func fetch(cveIds: [String]) throws -> VulnerabilityFetch
}
```

`VulnerabilityFetch` holds the records and the two dates. Three conformers:

| Conformer | Where | What it does |
| --- | --- | --- |
| `WebVulnerabilitySource` | `FileGateways` | runs the three requests through `AttackDownloading` and parses the bytes with `VulnerabilityFeeds` |
| `DirectoryVulnerabilitySource` | `FileGateways` | reads `nvd/<id>.json`, `epss.json` and `kev.json` from a directory, in the shape the three feeds answer, and makes no network call |
| `FakeVulnerabilitySource` | `TestSupport` | answers what a test put in it, and records every id it was asked for |

`THREATMODELLER_CVE_FEEDS=<directory>` makes the executable read the directory
source instead of the web. `scripts/cli-smoke.sh` writes the three feed files
and runs `cve sync` against them, so the smoke test proves the verb, the lock
file and the priority over real files with no network. No test reaches the
network: the package tests use the fake, and the smoke test uses the
directory.

`VulnerabilityFeeds` is a pure function of the bytes each feed answers, tested
against fixture bytes in the shape the three services publish.

## 4. Decision: how a known exploited vulnerability moves the score

**A component carrying a CVE the KEV catalogue lists raises every threat on
that component to `commodity`, the same claim a faced `commodity` actor
makes.**

A faced actor sets a likelihood by its `capability`, and the threat takes the
highest factor among its performers. A CVE CISA lists as known exploited is
exploited by attackers that exist today, at the highest frequency the model
holds, so it carries `commodity` (factor 1.0).

`LikelihoodSource` gains one case:

```swift
case vulnerability(Likelihood, cveId: String)
```

with the reason `set by CVE-2023-44487, known exploited`.

`ThreatResolver.likelihooded` applies the claims in this order:

1. a `likelihood` finding in the `.controls` file;
2. a known exploited CVE on the component the threat is raised on;
3. the actor-derived likelihood, when the system faces an actor that performs
   the threat;
4. the catalogue's own tier.

Step 2 sits above step 3 because `commodity` is the highest tier: the highest
factor wins, and when two claims tie the earlier one names the reason, which
is the rule `ActorLikelihood` already applies among performers. A component
with two KEV CVEs names the first in file order.

| Component's CVEs | Lock file | Threat's tier before | Result |
| --- | --- | --- | --- |
| one KEV | held | targeted | commodity, set by the CVE |
| one KEV | held | commodity | commodity, set by the CVE |
| one CVE, not KEV | held | targeted | targeted, from the catalogue or the actor |
| one CVE | not held | targeted | targeted, from the catalogue or the actor |
| none | any | targeted | targeted, from the catalogue or the actor |

Rows three to five keep the design safe: a CVE never lowers a score, and a
lock file that is not there changes no score.

**What a CVE does not do.** A CVE the KEV catalogue does not list changes no
likelihood, whatever its CVSS and EPSS. Its priority is what the report and
the threat card state about it. A threat on a zone or on a flow reads no CVE:
the CVE is the component's.

The rule is a pure function in `assessment/domain/VulnerabilityLikelihood.swift`.

## 5. Decision: the priority rule

**The CVE_Prioritizer quadrant is the default, and the policy file changes
the two thresholds.**

| Priority | Rule |
| --- | --- |
| `1+` | the KEV catalogue lists the CVE |
| `1` | CVSS at or above the CVSS threshold and EPSS at or above the EPSS threshold |
| `2` | CVSS at or above the CVSS threshold and EPSS below the EPSS threshold |
| `3` | CVSS below the CVSS threshold and EPSS at or above the EPSS threshold |
| `4` | CVSS below the CVSS threshold and EPSS below the EPSS threshold |

The defaults are the tool's: CVSS `6.0` and EPSS `0.2`. A CVE with no CVSS or
no EPSS reads that value as `0.0` for the rule, and the report prints `—` in
that column so a reader sees the value is missing, not low. A CVE the lock
file does not hold has no priority.

The policy file states the thresholds:

```hcl
policy {
  cve_cvss_threshold = 7.0
  cve_epss_threshold = 0.1
}
```

| Setting | Type | Values | Default |
| --- | --- | --- | --- |
| `cve_cvss_threshold` | number | `0.0` to `10.0` | `6.0` |
| `cve_epss_threshold` | number | `0.0` to `1.0` | `0.2` |

They are settings, beside `template`, not rules: neither is in force or
breached, and the `## Policy` section does not list them. A value outside its
range is the error `<setting> is <value>; this application holds 0.0 to
<top>`.

The rule is a pure function in `assessment/domain/VulnerabilityPriority.swift`,
so `cve list`, the report and the threat card cannot disagree.

## 6. What `check` says

A CVE a component states that the lock file does not hold is a warning:

```
threatmodel/payments.arch: the component "api" states CVE-2024-7347, which cve.lock.json does not hold; run threatmodeller cve sync
```

A project with no lock file gets one such line per CVE. A warning prints and
does not fail, so a project that names a CVE before its first sync still
builds. An unsynchronised CVE is a fact the model does not yet hold, not a
wrong answer, and the lock file is the team's to commit. A team that wants
the build to fail on it opens an issue for a policy rule; section 10 leaves
that out.

`check` reads the lock file and the `.arch` files and makes no network call.

## 7. The report

### 7.1 The section

`## Known vulnerabilities` sits after `## Third parties` and before
`## Policy`. A system whose components state no CVE writes no section. The
template slot is `known_vulnerabilities`.

```markdown
## Known vulnerabilities

The CVEs this system's components state, ranked by the CVE_Prioritizer rule with CVSS at or above 6.0 and EPSS at or above 0.2. A known exploited vulnerability raises every threat on its component to Commodity.

| CVE | Component | Version | CVSS | EPSS | KEV | Priority |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2023-44487 | Application Server | 1.24.0 | 7.5 | 0.94 | Yes | 1+ |
| CVE-2024-7347 | Application Server | 1.24.0 | 5.5 | 0.01 | No | 4 |
| CVE-2025-0001 | Ledger | 15.2 | — | — | — | not synchronised |
```

One row per CVE per component, ordered by priority (`1+` first, then `1` to
`4`, then unsynchronised) and then by CVE id. A CVE two components state
writes two rows. The CVE id links to `https://nvd.nist.gov/vuln/detail/<id>`.
The sentence above the table states the thresholds in force, so a reader of
a report with a policy file sees the rule the numbers were ranked by.

### 7.2 The threat stanza

A threat whose likelihood a CVE set writes the reason of section 4 on the
likelihood line:

```markdown
- Likelihood: Commodity, set by CVE-2023-44487, known exploited
```

### 7.3 The exports

`--format json` writes `knownVulnerabilities[]` with the seven columns.
`docs/threatmodel-export.schema.json` states the keys. The OTM export writes
nothing new: OTM has no vulnerability object.

## 8. The window

### 8.1 The component panel

`ComponentPanel` holds a Version field and a CVEs field after the Tags field,
each a `DeferredTextField`. The CVEs field reads and writes one line,
separated by commas, the way the Tags field does. Both write through
`SetComponentProperties`, the one path every control on that bar uses, so
the `.arch` file holds the attributes on the next save. A word in the CVEs
field that is not a CVE id is not written and the field shows the ids that
were.

### 8.2 The threat card

A threat raised on a component that states CVEs shows one read-only line
under `Performed by`:

```
Known vulnerabilities: CVE-2023-44487 (KEV, 1+), CVE-2024-7347 (4), CVE-2025-0001 (not synchronised)
```

The `Happens` line reads the reason of section 4 when a CVE set the
likelihood. A threat on a zone or a flow shows no line.

### 8.3 The lookup

The threat card of a component threat holds a *Look up CVEs…* button. It
opens a sheet that runs the lookup and lists what came back.

**The query.** The technology's name from the catalogue (`Nginx`), the
component's `version`, and, for the reader, the threat's id and STRIDE kind.
The tool takes the product and the version. The catalogue holds no CWE, so
none is sent; the sheet shows the threat so the person reading the results
knows what they are looking for.

**The tool.** `vulnx` from ProjectDiscovery, run as a child process the way
`git` and `curl` are, found on `PATH` through `/usr/bin/env`. The application
ships no tool and calls no network of its own for the lookup.

**The boundary.**

```swift
public protocol VulnerabilityLookup: Sendable {
    func search(_ query: VulnerabilityQuery) throws -> [VulnerabilityRecord]
}
```

| Conformer | Where | What it does |
| --- | --- | --- |
| `VulnxLookup` | `FileGateways` | runs `vulnx search --json` with the product and the version, and reads the records from the JSON lines |
| `FakeVulnerabilityLookup` | `TestSupport` | answers what a test put in it, or throws the fault a test named |

`VulnerabilityLookupFault.toolIsNotInstalled` shows one message:
`vulnx is not installed; install it with go install github.com/projectdiscovery/vulnx/cmd/vulnx@latest`.
The README states the same command. No test calls the real tool.

**The result list.** One row per record: the CVE id, CVSS, EPSS, `KEV` when
listed, and the summary, with a checkbox. *Attach* writes the picked ids onto
the component through `SetComponentProperties`, added to the ids the
component already states, and the window saves the way it saves every other
edit. The lock file does not change: a person runs *Synchronise CVEs* after,
and the threat card shows `not synchronised` until they do.

## 9. What the code is

| Path | What it holds |
| --- | --- |
| `ThreatModelKit/vulnerability/domain/KnownVulnerability.swift` | one record: id, CVSS, EPSS, known exploited, summary, dates |
| `ThreatModelKit/vulnerability/domain/VulnerabilityLock.swift` | the lock file, read and written |
| `ThreatModelKit/vulnerability/domain/VulnerabilityFeeds.swift` | the three feed parsers, as pure functions of bytes |
| `ThreatModelKit/vulnerability/gateway/VulnerabilitySource.swift` | the fetch port and its fault |
| `ThreatModelKit/vulnerability/gateway/VulnerabilityLookup.swift` | the lookup port, the query, and its fault |
| `ThreatModelKit/vulnerability/usecase/SynchroniseVulnerabilities.swift` | `cve sync` |
| `ThreatModelKit/vulnerability/usecase/ListVulnerabilities.swift` | `cve list` |
| `ThreatModelKit/vulnerability/usecase/ApplyVulnerabilityLock.swift` | puts the lock's records onto the model, the way `ApplyPolicy` puts the rules |
| `ThreatModelKit/vulnerability/usecase/LookUpVulnerabilities.swift` | the sheet's search |
| `ThreatModelKit/assessment/domain/VulnerabilityLikelihood.swift` | section 4 |
| `ThreatModelKit/assessment/domain/VulnerabilityPriority.swift` | section 5 |
| `ThreatModelKit/assessment/domain/LikelihoodSource.swift` | the new case |
| `ThreatModelKit/assessment/domain/ThreatResolver.swift` | the order of section 4 |
| `ThreatModelKit/architecture/domain/ArchitectureSource.swift` | `version`, `cves` |
| `ThreatModelKit/architecture/domain/PolicySource.swift` | the two thresholds |
| `ThreatModelKit/architecture/domain/ProjectLayout.swift` | `vulnerabilityLockPath` |
| `ThreatModelKit/architecture/usecase/OpenSystem.swift` | applies the lock |
| `ThreatModelKit/architecture/usecase/CheckControlAnswers.swift` | the warning of section 6 |
| `ThreatModelKit/modelling/domain/Component.swift` | `version`, `cves` |
| `ThreatModelKit/modelling/domain/ThreatModel.swift` | `vulnerabilities`, by id |
| `ThreatModelKit/modelling/usecase/SetComponentProperties.swift` | writes both |
| `ThreatModelKit/modelling/usecase/ViewThreatModel.swift` | carries both to the canvas |
| `ThreatModelKit/reporting/domain/Report.swift` | `ReportKnownVulnerability` |
| `ThreatModelKit/reporting/usecase/MarkdownKnownVulnerabilities.swift` | section 7.1 |
| `ThreatModelKit/reporting/usecase/BuildThreatModelReport.swift` | fills the rows |
| `ThreatModelKit/reporting/usecase/ExportModelAsJson.swift` | section 7.3 |
| `ArchitectureDSL/ArchitectureParser.swift`, `ArchitectureWriter.swift` | read and write both attributes |
| `ArchitectureDSL/PolicyParser.swift` | the two thresholds |
| `FileGateways/WebVulnerabilitySource.swift` | the three requests |
| `FileGateways/DirectoryVulnerabilitySource.swift` | the smoke test's source |
| `FileGateways/VulnxLookup.swift` | the child process |
| `TestSupport/FakeVulnerabilitySource.swift`, `FakeVulnerabilityLookup.swift` | the fakes |
| `CommandLineApplication/CommandLineApplication.swift` | `cve sync`, `cve list`, the usage text |
| `CommandLineApplication/LanguageServer.swift` | the two completions |
| `threatmodeller/canvas/ComponentPanel.swift` | the two fields |
| `threatmodeller/sidebar/ThreatCard.swift` | the line and the button |
| `threatmodeller/sidebar/VulnerabilityLookupSheet.swift` | section 8.3 |
| `scripts/cli-smoke.sh` | `cve sync` and `cve list` against the directory source |
| `docs/LANGUAGE.md`, `README.md` | the attributes, the settings, the verbs |

## 10. Out of scope

- A policy rule that fails `check` on an unsynchronised or a high-priority
  CVE. Section 6 states the warning; a rule is a later issue.
- An NVD API key. The sync waits between requests instead.
- CVSS vectors, CWE ids, affected version ranges, and a check that the
  component's `version` is inside a CVE's range. The person who attaches a
  CVE states that it applies.
- A CVE on a `technology` in a library, or on a `third_party`.
- A likelihood between the tiers from EPSS alone. A CVE not in the KEV
  catalogue changes no likelihood.
- A fix recommendation from the CVE. The recommendations editor is where a
  team writes what it will do.
- Any lookup tool but `vulnx`. The port takes another conformer; none is
  written.

## 11. Testing

| Test | Says |
| --- | --- |
| `KnownVulnerabilityLanguageTests` | `version` and `cves` parse and round-trip byte for byte, with a golden `.arch` file; a component stating neither writes neither; a word that is not a CVE id is the error of section 2.2 |
| `VulnerabilityFeedsTests` | fixture bytes in each feed's shape give the CVSS, the EPSS with its date, and the KEV entry with the catalogue version |
| `VulnerabilitySyncTests` | a sync with the fake writes the lock file of section 3.2; a second sync against the same fake writes the same bytes and reports nothing changed; a failed fetch leaves the previous lock file; a project naming no CVE writes none |
| `VulnerabilityLikelihoodTests` | the five rows of section 4 |
| `VulnerabilityPriorityTests` | one CVE per quadrant and one KEV give `1+` to `4` with the default thresholds, which is what CVE_Prioritizer gives for the same inputs; the policy thresholds move a CVE between quadrants |
| `PolicyTests` | the two settings parse; a value outside its range is the error of section 5 |
| `CheckVulnerabilityTests` | a CVE the lock file does not hold prints the warning of section 6 and does not fail the check |
| `MarkdownKnownVulnerabilitiesTests` | the section of 7.1 with a golden, ordered by priority; no section without a CVE |
| `VulnerabilityLookupTests` | the fake lookup returns records with CVSS, EPSS and KEV; the missing tool gives the one message of section 8.3 |
| `KnownVulnerabilityFlowTests` (window) | the panel writes `version` and `cves` into the file; the threat card shows the line of 8.2; the sheet lists the fake's records, attaches one, and the file holds it through the one writer |
| `scripts/cli-smoke.sh` | `cve sync` against the directory source writes the lock file; `cve list` prints the priority; `check` warns for an unsynchronised CVE |
