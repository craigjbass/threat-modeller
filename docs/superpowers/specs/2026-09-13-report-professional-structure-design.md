# Report professional structure — design

Date: 2026-09-13
Status: approved for planning

## 1. Why

The report proves its arithmetic and cites its evidence, and it explains none
of itself. It opens with count bullets, it never states what a score of 13 out
of 16 means, it gives every threat the same weight from the first to the three
hundredth, and it writes attack paths as a graph dump.

This design closes the part of that gap the report can close on its own, from
the data the model already holds. A second design covers the part that needs
new authored data: governance fields on an accepted risk, evidence tiers on a
control, document control, and threat actors as first-class elements.

## 2. Scope

**In scope.** Executive summary, methodology, diagram legend, glossary, a
curated findings section, the full threat register demoted to an appendix, the
model inventory demoted to an appendix, a narrative attack paths section, and
the removal of the second PDF renderer.

**Out of scope.** Every new attribute in the architecture and controls
languages. `LANGUAGE.md` needs no change from this design: nothing here adds a
keyword.

**Out of scope.** "What changed since the last assessment". The tool stores no
prior report, so a change log needs a second input and a diff engine.

## 3. The report's new shape

```
# <model name>
Assessed against threat catalogue `<tag>`.
<whole-system picture>

## Executive summary
<rollup tables>
<top residual threat pictures>
## Methodology
### Diagram legend
## Findings
## Attack paths
## Protection dependencies
## Recommendations
## Assumptions
## Glossary
## Appendix A — Full threat register
## Appendix B — Model inventory
## Appendix C — Attack paths not listed
```

The present `## Summary` section, which writes the count bullets, is removed.
Its counts are covered twice over: the executive summary states the totals a
reader needs, and the rollup tables carry the breakdowns. The rollup tables and
the top-residual threat pictures keep the position they hold today, directly
below the opening section and above the methodology.

`ExportModelAsMarkdown` writes this order. `ExportModelAsHtml` converts that
Markdown, so the page follows without its own change.

## 4. Prose register

The executive summary reads as a consultancy deliverable: graded, hedged where
the evidence is thin, and framed by business impact. Every other section the
tool writes keeps the project's plain register: short common words, active
voice, one word for one meaning.

The two registers never mix inside one section.

## 5. New types on `Report`

All four are computed by `BuildThreatModelReport` and printed by a writer. A
writer decides nothing.

### 5.1 `ReportExecutiveSummary`

```swift
public struct ReportExecutiveSummary: Equatable, Sendable {
    public let verdict: String
    public let toleranceLabel: String
    public let topRisks: [ReportThreat]
    public let topActions: [ReportRecommendation]
    public let unansweredCount: Int
    public let totalThreats: Int
}
```

`verdict` is one sentence, chosen by the count of threats whose `riskLevel`
ranks above `ThreatModel.effectiveRiskTolerance`:

| Count above tolerance | Sentence |
| --- | --- |
| 0 | `No residual exposure exceeds the project's <tolerance> risk tolerance.` |
| 1 | `The assessment identifies a single residual exposure above the project's <tolerance> risk tolerance.` |
| 2 or more | `The assessment identifies <n> residual exposures above the project's <tolerance> risk tolerance.` |

`topRisks` is the three worst threats by `riskScore`, already sorted in
`Report.threats`. `topActions` is the three recommendations whose `riskScore`
is highest, from `Report.recommendations`. A report with fewer than three of
either prints what it has, and a report with none prints the heading and the
verdict alone.

`unansweredCount` counts the threats holding no control whose
`ControlStatus.isAnswered` is true and no compensating control.

### 5.2 `ReportMethodology`

```swift
public struct ReportMethodology: Equatable, Sendable {
    public let levelThresholds: [ReportLevelThreshold]
    public let controlCapPercent: Int
    public let likelihoodTiers: [ReportCount]
    public let zoneReductions: [ReportCount]
    public let toleranceLabel: String
}
```

`ReportLevelThreshold` carries `label`, `lowest` and `highest`. The values come
from `RiskScore.level`, not from a second copy of the thresholds: the section
would otherwise disagree with the scoring the day a threshold moves.

`controlCapPercent` reads `ControlCoverage.maxReduction`. `likelihoodTiers`
reads `Likelihood.allTiers`, each factor written as a percentage.
`zoneReductions` names each zone that has risk reduction on, with its own
percentage, taken from `ReportZone.riskReductionPercent`.

Both lists reuse `ReportCount`, and in both the `count` is a percentage, not a
tally. A doc comment on each property says so.

### 5.3 `ReportFindingsCut`

```swift
public struct ReportFindingsCut: Equatable, Sendable {
    public let above: [ReportThreat]
    public let notShown: Int
}
```

`above` holds every threat whose `riskLevel` ranks above the effective risk
tolerance, worst first, capped at 25. `notShown` is how many qualified and did
not fit. A model with `risk_tolerance = "low"` raises nearly every threat above
tolerance, and the cap is what keeps the section a findings section.

### 5.4 The attack path narrative

`ReportAttackPath` gains `likelihoodLabel: String` — the likelihood tier of the
threat that set the path's worst score.

`Report.attackPathsNotListed` changes type from `Int` to
`[ReportAttackPathSummary]`, each carrying `startName`, `endName` and
`worstScore`. The count a reader sees is the list's count.

`Report` gains `attackPathPrefix: [ReportAttackPathHop]` — the longest hop
prefix that every listed path shares, matched by component name. Empty when
the listed paths share no first hop.

## 6. Section by section

### 6.1 Executive summary

```markdown
## Executive summary

The assessment identifies a single residual exposure above the project's
medium risk tolerance.

**Highest residual risk**

1. Supply-chain package substitution — Build pipeline — Critical (13 of 16).
   The element holds confidential data and runs as root.
2. …

**Do first**

1. Pin every package to a hash in the lockfile — answers Supply-chain package
   substitution on Build pipeline (13 of 16).
2. …

47 of 330 threats hold no answered control and no compensating control.
```

Each risk line names the threat, the element, the level and the score out of
16, then one sentence carrying the element's sensitivity and privilege, which
`ReportComponent` already holds.

### 6.2 Methodology

Written in the order `ThreatResolver` runs the stages, so a reader can follow
one threat through the arithmetic:

1. Base score is the severity rank multiplied by the data sensitivity rank,
   from 1 to 16.
2. The level thresholds, from `ReportMethodology.levelThresholds`.
3. A private zone with risk reduction on multiplies the score by
   `(100 − percent) / 100`. Each such zone is named with its percentage. A
   flow between two private zones takes the smaller of the two reductions.
4. The implemented controls take off `implemented / applicable` of the score,
   capped at 70%. `applicable` is every control not marked not applicable. A
   control marked accepted stays in the divisor and lowers nothing.
5. A pathway mitigation and a `mitigates` edge each take off their stated
   percentage. Two that answer one threat give the stronger, never the sum.
6. The likelihood multiplies the score. Commodity 100%, Targeted 60%,
   Research 25%, or the percentage a finding states.
7. A compensating control multiplies the score by its stated reduction. Two
   give the stronger, never the sum.
8. A score never falls below 1.
9. The project's risk tolerance is `<level>`. A likelihood finding answers a
   threat only when the threat sits at or below that level.
10. "If the assumptions hold" is the same arithmetic with the `assumed`
    `mitigates` edges counted as in place.

### 6.3 Diagram legend

Fixed text. Every claim is written against the drawing code and matches it:

| Mark | Meaning | Where the code sets it |
| --- | --- | --- |
| Red, orange, yellow, green | Critical, High, Medium, Low | `DiagramColour.forLevel` |
| Dashed tinted box | a zone, tinted by the worst risk inside it | `DiagramBuilderParts`, dash `[2, 4]` |
| Purple dashed line | a control protecting an element; it carries no data | `DiagramBuilderParts`, `.protects`, dash `[5, 4]` |
| Grey boundary run | a trust boundary crossing with no guard on it | `.quiet` when `run.guards` is empty |
| Dashed guard marker | a guard that is assumed, not adopted | boundary run, dash `[3, 3]` |
| Thick ring | the element the picture is about | `DiagramBuilder.focusWidth` |
| Badge on a node | how many threats are still open on that node | `ThreatDiagrams` |
| Arrowhead | the direction the data flows | `DiagramBuilderParts` |

Any entry whose claim the drawing code contradicts is corrected to what the
code does, not written as intended.

### 6.4 Findings

Every threat above tolerance, printed in the full stanza the threat register
uses today — description, severity, risk, likelihood with its rationale and
sources, STRIDE, ATT&CK, compensation, and the control checklist. A line under
the heading states the cut: `Every threat above the project's <tolerance> risk
tolerance. <n> more qualify and are in Appendix A.`

### 6.5 Attack paths

```markdown
## Attack paths

Every path below starts at Internet → ClearanceKit GUI.

### 1. Internet → Secrets store — worst 13, Commodity

| Hop | Flow | Worst threat | Score | Reduced by |
| --- | --- | --- | --- | --- |
| Build pipeline | Network | Supply-chain package substitution | 13 | nothing reduces this hop |
| Secrets store | Local IPC | Credential theft | 9 | Touch ID gate |
```

The curation runs in `AttackPaths.build`:

1. Sort the traced paths by worst score, highest first, and keep five.
2. Compute the longest hop prefix the five share, by component name, and state
   it once above them. Each path then prints only the hops after that prefix.
   A path reduced to no hops is dropped from the five and the next path takes
   its place.
3. Each path states its own worst score and the likelihood tier of the hop
   that set it.
4. A hop whose `reducedBy` is empty prints `nothing reduces this hop`.
5. Every path not among the five becomes one line in Appendix C.

### 6.6 Recommendations

Ordered by the `riskScore` of the threat each answers, highest first, rather
than grouped by element. The grouping by element is what hides the order a
team should work in. Each entry keeps its threat, its element, its note and
its sources.

### 6.7 Glossary

Fixed text, one line per word, defining: answered, not applicable, accepted,
implemented, compensating control, pathway mitigation, `mitigates` edge,
adopted, assumed, inherent score, residual score, if the assumptions hold,
risk tolerance, prior, source kind, and stanza.

### 6.8 The appendices

Appendix A is the present `## Threats` section, unchanged in content, moved and
renamed. Its first lines carry the control counts the removed `## Summary`
section wrote — offered, recorded, and the tally per status — so no count the
report published today is lost. Appendix B holds the present `## Components`, `## Connections` and
`## Zones` sections as `### ` subheadings. Appendix C lists the attack paths
the narrative did not carry.

## 7. The PDF path

`PDFReportRenderer` writes five sections and has not followed the report since
attack paths, recommendations, protection dependencies and assumptions were
added. Two renderers that must agree is the reason it drifted.

Delete `threatmodeller/reporting/PDFReportRenderer.swift`,
`ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/ExportModelAsPdf.swift`
and the `ReportRenderer` gateway.

Keep the **Export as PDF…** menu item and its `.pdf` file type. It renders the
HTML page through `ExportModelAsHtml`, loads that page into an offscreen
`WKWebView`, and prints it to PDF data with the A4 page setup the page's
stylesheet already targets. One report path feeds Markdown, HTML and PDF.

`ReportExporter` keeps its `.pdf` case. `ThreatModelSession.pdfExport()` calls
the new path.

## 8. Empty and edge cases

| Case | What the report writes |
| --- | --- |
| No threats | Executive summary states the verdict for zero, prints no risk list and no action list. Findings writes `No threat sits above the project's <tolerance> risk tolerance.` |
| No zones with risk reduction | The methodology omits the zone line rather than writing an empty table. |
| No recommendations | "Do first" is omitted; the recommendations section keeps its present empty behaviour. |
| No attack paths | The section writes `None.`, and no prefix line. |
| Every path shares no first hop | No prefix line; each path prints all its hops. |
| More than 25 threats above tolerance | Findings prints 25 and states how many more are in Appendix A. |

## 9. Testing

Test first, every item.

**Use case tests on `BuildThreatModelReport`.**
- The verdict sentence at zero, one and many above tolerance.
- The findings cut at each of the four tolerance levels.
- The 25 cap and the `notShown` count.
- The shared hop prefix: none, one hop, every hop.
- `unansweredCount` against a model mixing implemented, accepted, not
  applicable and compensating answers.

**Writer tests.** One suite each for `MarkdownExecutiveSummary`,
`MarkdownMethodology`, `MarkdownLegend`, `MarkdownFindings`,
`MarkdownGlossary`, and the rewritten `MarkdownAttackPaths`.

**Report order tests.** `ReportRendererTests` and `LibraryEndToEndTests` pin
the Markdown line for line. They are rewritten to the new order as the first
step of the work, not patched after it.

**A model with nothing in it** writes every section, crashes nowhere, and
leaves no heading with an empty body.

**PDF.** An application-level test, beside the other `threatmodellerTests`
cases that touch AppKit: the exporter returns PDF data for a model with one
component, and the data starts with `%PDF`. The `WKWebView` load is
asynchronous, so the test awaits the render rather than polling.

## 10. Where the code goes

| File | Change |
| --- | --- |
| `reporting/domain/Report.swift` | the four new types, `attackPathPrefix`, `attackPathsNotListed` retyped |
| `reporting/domain/AttackPaths.swift` | the curation of section 6.5 |
| `reporting/usecase/BuildThreatModelReport.swift` | builds the new types |
| `reporting/usecase/MarkdownExecutiveSummary.swift` | new |
| `reporting/usecase/MarkdownMethodology.swift` | new, holds the legend |
| `reporting/usecase/MarkdownFindings.swift` | new |
| `reporting/usecase/MarkdownGlossary.swift` | new |
| `reporting/usecase/MarkdownAttackPaths.swift` | rewritten |
| `reporting/usecase/MarkdownRecommendations.swift` | ordered by risk score |
| `reporting/usecase/ExportModelAsMarkdown.swift` | the new section order, appendix headings, `## Summary` removed |
| `reporting/usecase/ExportModelAsPdf.swift` | deleted |
| `reporting/gateway/ReportRenderer.swift` | deleted |
| `threatmodeller/reporting/PDFReportRenderer.swift` | deleted |
| `threatmodeller/reporting/ReportExporter.swift` | `.pdf` renders the HTML page |

## 11. What this design does not close

These stay for the second design, and the report is still short of a
professional extended deliverable until they are done:

- Governance on an accepted risk: who accepted it, when, and when it is
  reviewed again.
- Governance on a recommendation: owner, effort, acceptance criteria.
- Document control: version, date, author, classification, scope and
  out-of-scope statement.
- Threat actors as first-class elements, with capability, intent and access,
  and threats tied to them.
- Evidence tiers on a control note: tested, observed, documented, asserted.
