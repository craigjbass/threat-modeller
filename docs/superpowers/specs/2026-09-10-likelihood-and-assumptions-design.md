# Likelihood and assumptions as score dimensions: design

Date: 2026-09-10. Status: approved in conversation, ready for an implementation
plan.

Scope: items 1, 4, 5, 7 and 8 of the ClearanceKit endpoint modelling review.
Catalogue content (target types, the missing threats, the endpoint.lib fixes)
and the recommendation lifecycle are separate work, and each gets its own spec.

## 1. What this fixes

A user built a full threat model of a macOS endpoint security product, then ran
eleven evidence-backed research passes over real malware campaigns and CVEs to
say how often each residual threat actually happens. The application had no
place to put any of that.

| # | Fault | Evidence from that model |
| --- | --- | --- |
| 1 | A threat carries no prior for "does this happen" | SIP bypass, which no malware family uses, and package postinstall persistence, which 800+ Lazarus npm packages used in 2025, start at the same weight |
| 2 | A likelihood finding has to be written as a compensating control | "kernel 0-days cost six figures" is not a control, and the report reads as if the team built something |
| 3 | A likelihood finding and a control never both count | `compensating` takes the stronger of two, so evidence and mechanism never multiply, and combined evidence under-counts |
| 4 | Hardening that is planned but not shipped has nowhere to live | A hardening baseline was modelled as adopted, documented in an unused "hardening-note" technology block |
| 5 | A report cannot separate "protected" from "unlikely" from "assumed" | All three arrive as `compensating` blocks and render identically |
| 6 | A CVE or a URL has nowhere to live | Every likelihood verdict crammed its sources into rationale prose |
| 7 | `severity =` in a controls file is parsed and dropped | `ControlsParser` reads it into `severityLabel`; `ApplyControlAnswers` never uses it. An assessor who downgrades a threat sees no change and no warning |

## 2. The decisions this design fixes

1. **A threat carries a likelihood, and likelihood multiplies the score.** The
   tiers are `commodity` (1.0), `targeted` (0.6) and `research` (0.25). A
   numeric prior from 0 to 100 maps to `prior / 100`. A threat that states
   none is `commodity`, so every existing model keeps its numbers.

2. **Likelihood multiplies; it never takes the stronger of two.** A likelihood
   finding and a control are independent evidence. The compensating stage
   keeps its stronger-of-two rule, because two compensating controls describe
   one team's work.

3. **A library states the prior; a controls file states the finding.** The
   catalogue holds what is true of the threat everywhere. A `likelihood` block
   in a controls file overrides it for one threat on one source, and needs a
   rationale.

4. **A `mitigates` edge states whether it is adopted or assumed.** An assumed
   edge never lowers the residual score. It lowers a second number, the target
   posture, which the report shows beside the residual.

5. **A system states its assumptions.** An `assumption` block names what the
   model takes on trust and who owns it. The report gives them a section.

6. **Evidence carries its sources.** `sources` is a list of text on the
   `likelihood`, `compensating`, `severity_override` and `recommendation`
   blocks. The report renders a URL as a link and any other text as it stands.

7. **An assessor downgrades a severity in a block, with a reason.** The
   `severity_override` block takes the severity and needs a rationale. The
   `severity` attribute the compiler writes stays information, so a catalogue
   that raises a threat's severity is never masked by a stale written value.

8. **A likelihood finding answers a threat only inside the project's
   tolerance.** `threatmodeller check` exits 1 for an unanswered threat, unless
   that threat carries a likelihood block and its residual score sits at or
   below `risk_tolerance`. The default tolerance is `low`.

## 3. The score pipeline

The stage order becomes:

```
severity × sensitivity
  → zone multiplier
  → control coverage
  → pathway mitigation
  → mitigates edges (adopted only)
  → likelihood            ← new
  → compensating
```

Likelihood sits after the mitigates edges and before the compensating control,
so a reader sees mechanism first and evidence last. The floor is 1, which every
other stage already holds.

`Likelihood.factor` gives the multiplier. `Likelihood.apply(to:factor:)` gives
`max(1, round(score × factor))`.

### 3.1 Two postures

`ComponentMitigations.apply` takes the edges it is given. The resolver runs it
twice:

- the **residual** pass reads edges whose status is `adopted`;
- the **target** pass reads edges whose status is `adopted` or `assumed`.

Both passes then run the likelihood and compensating stages, so the two numbers
differ by the assumed edges alone. `ResolvedThreat` gains:

| Field | Meaning |
| --- | --- |
| `likelihood` | the tier and factor the score used |
| `likelihoodFinding` | the block from the controls file, or nil |
| `scoreBeforeLikelihood` | the score the likelihood stage received |
| `scoreIfAssumptionsHold` | the target posture score |
| `assumedMitigations` | the assumed edges that lowered the target posture |

When no assumed edge touches a threat, `scoreIfAssumptionsHold` equals
`score.value`.

### 3.2 Where the likelihood comes from

| Source | Wins over | Needs |
| --- | --- | --- |
| a `likelihood` block in the controls file | the library prior | a rationale |
| the `likelihood` attribute on a library threat | the default | nothing |
| the default, `commodity` | — | — |

A block that names both `tier` and `prior` is an error: one threat gets one
number.

## 4. The file formats

### 4.1 `.lib`

```
threat "sip-bypass" {
  name        = "SIP Bypass"
  severity    = "critical"
  likelihood  = "research"
}
```

`likelihood` takes `commodity`, `targeted`, `research`, or a whole number from
0 to 100. Any other value is an error, the way an unknown severity is. The
library writer emits the attribute only when the threat states one, so a
library that says nothing round-trips unchanged.

### 4.2 `.controls`

```
threat "sip-bypass" on component "laptop" {
  severity = "critical"
  score    = 3

  likelihood "no in-the-wild use since Big Sur" {
    tier      = "research"
    rationale = "every bypass was researcher-found; MITRE lists no procedure examples"
    sources   = ["https://support.apple.com/en-gb/HT212804", "CVE-2021-30892"]
  }

  severity_override "high" {
    rationale = "the exploit reads; the write path stays gated by SIP"
    sources   = ["CVE-2021-30892"]
  }

  compensating "hardware-bound key" {
    reduces_risk_by = 40
    rationale       = "the key never leaves the Secure Enclave"
    sources         = ["https://example.internal/adr/17"]
  }

  recommendation "allow-list only hardened-runtime binaries" {
    note    = "Homebrew builds are ad-hoc signed"
    sources = ["https://attack.mitre.org/techniques/T1218/"]
  }
}
```

Rules:

- `likelihood` holds `tier`, `prior`, `rationale` and `sources`. A block with
  no rationale is an error, and the block changes nothing. That is the rule
  `compensating` already holds: a reduction nobody can justify is not one.
- `severity_override` holds `rationale` and `sources`. The label is the
  severity the assessor chose. An id the taxonomy does not know is an error.
  A block with no rationale is an error.
- `sources` is a list of text. It is optional everywhere it appears.
- A `severity_override` block applies to that threat on that source alone. The
  application's own override, `SeverityOverrideKey`, keys a component threat by
  its technology, so it moves every component of that technology. The two stay
  separate: the file's block is keyed by `ThreatKey`, and it wins over the
  technology-wide override when both name one threat on one source.
- Two `likelihood` blocks on one threat is an error. Two
  `severity_override` blocks on one threat is an error.
- The writer emits `likelihood`, then `control`, then `severity_override`,
  then `compensating`, then `recommendation`, so a compile of an unchanged
  model writes the file it read.

### 4.3 `.arch`

```
system "clearancekit" {
  risk_tolerance = "low"

  assumption "mdm-push" {
    text  = "the hardening baseline is written, and MDM has not pushed it yet"
    owner = "platform team"
  }

  mitigates hardening -> laptop {
    threats         = ["persistence", "unsigned-code-load"]
    reduces_risk_by = 60
    status          = "assumed"
  }
}
```

Rules:

- `risk_tolerance` takes a level id from the risk ladder: `low`, `medium`,
  `high` or `critical`. Missing means `low`.
- `status` on a `mitigates` edge takes `adopted` or `assumed`. Missing means
  `adopted`, so every existing file keeps its numbers.
- `assumption` takes a label, a required `text` and an optional `owner`. A
  duplicate label is an error.
- The architecture writer emits `risk_tolerance` and every `assumption` in the
  canonical shape, and emits `status` only when the edge states `assumed`.

## 5. `threatmodeller check`

`check` exits 1 for a threat that holds no implemented control and no
compensating control, as it does today, with one exception: a threat that
carries a `likelihood` block **and** whose residual score sits at or below the
project's `risk_tolerance` band counts as answered.

| Tolerance | Answers a likelihood-backed threat scoring |
| --- | --- |
| `low` | 1 to 3 |
| `medium` | 1 to 7 |
| `high` | 1 to 11 |
| `critical` | any score |

`threatmodeller check --tolerance <level>` overrides the file for one run. The
output states the tolerance it used, so a passing build says on what basis it
passed. A library prior alone never answers a threat: the finding, its
rationale and its sources are what a reviewer reads.

## 6. The report

- Each threat row states the residual score. When a likelihood finding or a
  library prior below `commodity` moved it, the row also states
  `<score before likelihood> → <residual>`, the tier, and the rationale.
- `sources` render as a bullet list under the block they belong to. A value
  starting `http://` or `https://` renders as a link; anything else renders as
  text.
- A `severity_override` renders as `critical → high` with its rationale and its
  sources.
- Every rollup table and every threat row gains an `If assumed hold` column.
  The column appears only when the model draws at least one assumed edge.
- A new `## Assumptions` section lists each system assumption, its owner, and
  each assumed edge with the threats it would answer and the reduction it would
  buy.
- The existing sections keep their shape, so a reader of an older report reads
  a newer one.

## 7. What this design does not do

- It does not change the compensating stage's stronger-of-two rule.
- It does not score an assumption's own likelihood.
- It does not touch the catalogue's content. The `likelihood` attribute lands
  in the language, and no vendored threat states one until the catalogue work.
- It does not change the recommendation blocks beyond adding `sources`.
- It does not add a user interface for any of this. The application reads and
  writes the new blocks through the same gateways; the sidebar keeps its
  current controls.

## 8. Testing

| Level | What it proves |
| --- | --- |
| Unit | `Likelihood.factor` for each tier and for a numeric prior; `apply` floors at 1 |
| Unit | The resolver's two passes differ by the assumed edges alone |
| Unit | A controls-file finding wins over a library prior; the default is `commodity` |
| Unit | A `likelihood` block with no rationale is an error and changes no score |
| Unit | `severity_override` changes the severity the score uses; an unknown id is an error |
| Unit | `check` exit code for each tolerance level, with and without a finding |
| Parser | Every new block reads, and each fault gives one diagnostic with a line and a column |
| Writer | A parse-then-write round trip of a file holding every new block gives the same text |
| End to end | An `.arch` and a `.lib` and a `.controls` file holding assumed edges and likelihood findings compile to a report holding the Assumptions section and both columns |

## 9. Files this touches

| File | Change |
| --- | --- |
| `assessment/domain/Likelihood.swift` | new: the tiers, the factors, the apply stage |
| `assessment/domain/LikelihoodFinding.swift` | new: the block a controls file holds |
| `assessment/domain/SeverityOverrideDecision.swift` | new: the label, the rationale and the sources |
| `assessment/domain/ComponentMitigations.swift` | filters by status |
| `assessment/domain/ThreatResolver.swift` | the likelihood stage, and the two passes |
| `assessment/usecase/AssessThreatModel.swift` | carries the new fields out |
| `architecture/domain/ControlsSource.swift` | the new blocks on `SourceThreatAnswer` |
| `architecture/domain/ArchitectureSource.swift` | `risk_tolerance`, `assumption`, edge `status` |
| `architecture/domain/LibrarySource.swift` | the library threat's `likelihood` |
| `architecture/usecase/ApplyControlAnswers.swift` | applies the findings and the override |
| `architecture/usecase/CheckControlAnswers.swift` | the tolerance rule |
| `ArchitectureDSL/ControlsParser.swift`, `ControlsWriter.swift` | the new blocks |
| `ArchitectureDSL/ArchitectureParser.swift`, `ArchitectureWriter.swift` | the new statements |
| `ArchitectureDSL/LibraryParser.swift`, `LibraryWriter.swift` | the new attribute |
| `catalogue/domain/Threat.swift`, `Library.swift` | the prior |
| `modelling/domain/MitigatesEdge.swift`, `ThreatModel.swift` | the status, the assumptions, the tolerance |
| `reporting/*` | the columns, the sources, the Assumptions section |
| `CommandLineApplication.swift` | `--tolerance`, and the line that states the tolerance used |
| `docs/LANGUAGE.md` | the new blocks and attributes |
