# Risk by leverage — design

Date: 2026-09-13
Status: approved for planning

## 1. Why

The report ranks what to do by the score of the threat a recommendation is
written against. That is the wrong number. It answers "which threat is worst",
not "which action removes the most risk", and those have different answers.

The ClearanceKit enterprise model shows the gap. Its worst threat,
`credential-theft` on `devtools`, scores 13 and carries no recommendation at
all, so no action can ever name it. The highest-scoring threat that carries a
recommendation scores 9, and the report lists three of those. The action that
would most change the posture — adopting Secretive, which removes the private
key from disk and so removes the theft — sits on a threat scoring 8, seventh in
rank order.

The model already knows the leverage. It is written in three places that cannot
refer to each other:

| Concept | Holds | Cannot say |
| --- | --- | --- |
| `assumption` | why a thing is not true, and who owns it | what it would change |
| `mitigates` with `status = "assumed"` | what it would reduce, by how much | what action makes it real |
| `recommendation` in a threat stanza | what to do | which threats, which elements, how much |

This design joins them, and makes the join computable.

## 2. Scope

**In scope.** A `recommendation` block on an assumed `mitigates` edge; the
grouping of several edges into one action; a use case that measures each
action's leverage by re-running the assessment; a report section ranking
actions by leverage; and the executive summary's "Do first" ranking by leverage
when a model declares actions.

**Out of scope.** Governance fields on an accepted risk, evidence tiers on a
control, document control, and threat actors as first-class elements. Those
remain the second design.

**Out of scope.** Changing how any score is computed. Leverage measures the
existing arithmetic; it does not add a stage to it.

**Out of scope.** `threatmodeller check`. An action with no leverage is worth
reporting and is not worth failing a build over.

## 3. The language

### 3.1 `recommendation` on an assumed edge

```hcl
mitigates opfilter -> devtools {
  threats         = ["credential-theft", "data-exfiltration"]
  reduces_risk_by = 60
  status          = "assumed"

  recommendation "reenable-devtool-rules" {
    text       = "Re-enable the dev-tool read rules"
    note       = "The rules were disabled for friction, not for risk."
    blocked_by = "devtool-rules-disabled"
    sources    = ["https://example.com/ticket/1"]
  }
}

mitigates opfilter -> rootdevtools {
  threats         = ["credential-theft", "data-exfiltration"]
  reduces_risk_by = 40
  status          = "assumed"

  recommendation "reenable-devtool-rules" {}
}
```

The label is the action's identity. Every edge whose recommendation carries
that label is one action, and the action's leverage is the total across all of
them.

| Attribute | Type | Values | Default |
| --- | --- | --- | --- |
| `text` | string | any, and not empty | **required on exactly one edge per label** |
| `note` | string | any | none |
| `blocked_by` | string | an `assumption` label | none |
| `sources` | list of strings | any | empty |

### 3.2 What the parser refuses

Each fault drops the `recommendation` block and keeps the edge, the way a
faulty block elsewhere in the language drops itself rather than the file.

| Fault | Error |
| --- | --- |
| the edge's `status` is not `assumed` | `the mitigates edge "<id>" is adopted, so it carries no recommendation` |
| two edges state `text` for one label | `the action "<label>" states its text twice` |
| no edge states `text` for a label | `the action "<label>" states no text` |
| `text` is empty | `the action "<label>" has no text` |
| `blocked_by` names no assumption | `the action "<label>" is blocked by "<name>", which no assumption declares` |

An adopted edge carries no recommendation because it has no leverage left to
claim: the reduction is already in the residual score.

### 3.3 What does not change

A `recommendation` block inside a `threat` stanza in a `.controls` file keeps
its present shape, its present meaning and its present section. It is advice
about one threat, ranked by that threat's score, and it claims no leverage. A
model that declares no actions reports exactly as it does today.

## 4. The domain

### 4.1 `EdgeAction` and `Action`

`MitigatesEdge` gains one optional property:

```swift
/// What a team would do to adopt this edge, or nil when the edge names none.
public let action: EdgeAction?
```

```swift
/// A recommendation written on one assumed edge.
public struct EdgeAction: Equatable, Sendable {
    public let label: String
    /// Stated on exactly one edge per label, and nil on the others.
    public let text: String?
    public let note: String?
    public let blockedBy: String?
    public let sources: [String]
}
```

The model-wide view is assembled from the edges:

```swift
/// One thing a team could do, and every assumed edge it would adopt.
public struct Action: Equatable, Sendable {
    public let label: String
    public let text: String
    public let note: String?
    public let blockedBy: String?
    public let sources: [String]
    /// The edges this action adopts, in the order the file declares them.
    public let edgeIds: [String]
}
```

`Actions.build(from: [MitigatesEdge]) -> [Action]` collects them, in the order
each label's `text` is first declared, so two runs of one model read the same.

### 4.2 `AssessLeverage`

```swift
public struct LeverageOfAction: Equatable, Sendable {
    public let action: Action
    /// Residual points this action removes across the whole model.
    public let removes: Int
    /// The sum of every threat's residual score before it.
    public let totalResidual: Int
    /// How many threats it moves at all.
    public let threatsMoved: Int
    public let worstBefore: Int
    public let worstAfter: Int
}
```

`worstBefore` and `worstAfter` are the worst residual score anywhere in the
model, not on the elements the action touches. An action that removes points
without moving the headline reports the same number twice, which is the honest
answer and the one a reader needs.

The use case resolves the model once for the baseline, then once per action
with that action's edges promoted from `assumed` to `adopted` and every other
assumed edge left assumed. It reads `ThreatResolver`, the same resolution
`AssessThreatModel` and `SummariseRisk` read, so a leverage number cannot
disagree with a residual number.

Results are ordered by `removes` descending, ties broken by `action.label`
ascending, so two runs of one model rank the same.

## 5. Two things the report must not let a reader believe

**Leverage is not additive.** Each action is measured alone against today's
posture. Two actions that reduce one threat do not remove the sum of their
leverage: `ComponentMitigations` takes the stronger edge and never the sum, and
this design does not change that. The section states this beside the numbers.

**Leverage is not "if the assumptions hold".** That column counts every assumed
edge at once. Leverage counts one action's edges. Both stay, and the report
never prints them as the same number.

An action whose edges move nothing scores 0, and the section still lists it,
saying `removes nothing at today's posture`. A zero is a finding: the work buys
nothing until something else changes.

## 6. The report

### 6.1 The new section

It sits after `## Findings` and before `## Attack paths` — a reader meets the
problems, then what to do about them, then how an attacker would move.

```markdown
## What removes the most risk

Each action is measured on its own against today's posture. Two actions that
answer one threat do not remove the sum of their leverage: the stronger
reduction wins, never the sum.

| Action | Removes | Threats moved | Worst | Blocked by |
| --- | --- | --- | --- | --- |
| Re-enable the dev-tool read rules | 19 of 412 | 8 | 13 → 5 | devtool-rules-disabled |
| Adopt Secretive as standard | 14 of 412 | 6 | 13 → 13 | secretive-not-standard |
| Harden the Okta tenant itself | 0 of 412 | 0 | 13 → 13 | — |
```

`ReportAction` carries what the section and the summary both print:

```swift
public struct ReportAction: Equatable, Sendable {
    public let label: String
    public let text: String
    public let note: String?
    public let blockedBy: String?
    public let sources: [String]
    public let removes: Int
    public let totalResidual: Int
    public let threatsMoved: Int
    public let worstBefore: Int
    public let worstAfter: Int
}
```

An action's `note` and `sources` are written under its row, the way the
recommendations section writes them.

A model that declares no action writes no section at all.

### 6.2 The executive summary

`ReportExecutiveSummary` keeps `topActions: [ReportRecommendation]` exactly as
it is, and gains a second list:

```swift
/// The actions that remove the most risk, worst first. Empty when the model
/// declares none, and then `topActions` is what the summary writes.
public let topLeverageActions: [ReportAction]
```

`MarkdownExecutiveSummary` writes the leverage list when it holds anything, and
the recommendation list when it does not. Two lists rather than one changed
type, so every existing model, both bundled samples and every existing test
keep working with no edit.

Each line names what the action removes rather than the score of a threat it
hangs off:

```markdown
**Do first**

1. Re-enable the dev-tool read rules — removes 19 of 412 residual points
   across 8 threats; worst falls 13 → 5. Blocked by devtool-rules-disabled.
```

The line the report cannot produce today is the one a reader acts on.

### 6.3 What the summary keeps

The "No recommendation names this threat" line stays. A top risk can still
carry neither a recommendation nor an action, and that remains worth saying.

## 7. Where the code goes

| File | Change |
| --- | --- |
| `modelling/domain/MitigatesEdge.swift` | `EdgeAction`, and `action` on the edge |
| `modelling/domain/Action.swift` | new: `Action` and `Actions.build` |
| `assessment/usecase/AssessLeverage.swift` | new: the measurement |
| `architecture/domain/ArchitectureSource.swift` | `SourceMitigates` carries the block |
| `ArchitectureDSL/ArchitectureParser.swift` | parses it, and reports section 3.2 |
| `ArchitectureDSL/ArchitectureWriter.swift` | writes it back in canonical form |
| `architecture/usecase/ImportArchitecture.swift` | carries it into the model |
| `FileGateways/DocumentJSON.swift`, `ThreatModelCodec.swift` | persists it in the document |
| `reporting/domain/Report.swift` | `ReportAction`, and the summary's new source |
| `reporting/usecase/BuildThreatModelReport.swift` | reads `AssessLeverage` |
| `reporting/usecase/MarkdownLeverage.swift` | new: the section |
| `reporting/usecase/MarkdownExecutiveSummary.swift` | writes an action line |
| `reporting/usecase/ExportModelAsMarkdown.swift` | places the section |
| `docs/LANGUAGE.md` | section 4.7 gains the block, its attributes and its errors |

The document format gains a field, so it takes a format version bump and a
round-trip test beside the existing `DocumentFormatVersion*` suites.

## 8. Testing

- `Actions.build`: one edge, several edges sharing a label, the declaration
  order of two labels.
- `AssessLeverage`: a single assumed edge, where leverage equals the drop and
  the worst score moves; an action spanning two edges, totalling both; two
  overlapping actions, where neither reports the sum; an action that moves
  nothing, reporting 0.
- The parser refuses each fault in section 3.2, dropping the block and keeping
  the edge.
- `ArchitectureWriter` round-trips a model carrying actions, and `format`
  leaves a canonical file unchanged.
- The document codec round-trips an edge with and without an action.
- `MarkdownLeverage` writes the table, the non-additivity sentence, a zero row,
  and nothing at all for a model with no actions.
- The executive summary ranks by leverage with actions, and by score without
  them.
- A measured run of `AssessLeverage` on the ClearanceKit enterprise model, with
  the wall-clock time recorded in the plan. The design chooses correctness over
  speed; the number decides whether that choice needs revisiting.

## 9. The risk in this design

`AssessLeverage` resolves the model once per action. On a model with 330
threats and ten actions that is eleven resolutions. If it proves slow, the
optimisation is to re-run only the threats an action's edges touch — exact, not
approximate, because `ComponentMitigations` filters on the edge's target. That
optimisation rests on an invariant, so it needs a test naming the invariant
before anyone takes it. Measure first.
