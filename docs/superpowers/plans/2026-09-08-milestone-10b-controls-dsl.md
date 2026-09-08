# Milestone 10B: the controls language — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A compiler writes every threat and every control into a file a team
fills in and commits; the answers score the model, the report reads them, and
continuous integration fails a pull request that answers nothing.

**Architecture:** A second grammar in `ArchitectureDSL`, a `ControlsSource` value
tree, a merge that never deletes an answer, two new model fields the resolver
reads, and three more verbs in the executable.

**Tech Stack:** Swift 6.3, SwiftPM, Swift Testing, SwiftUI (application target
only), Foundation only in the package.

**Spec:** `docs/superpowers/specs/2026-09-08-code-first-dsl-design.md` §4, §5,
§6.5, §9, §11.

## Global Constraints

- Swift 6.3, `swift-tools-version: 6.2`, `platforms: [.macOS(.v26)]`.
- **No package target may import AppKit, CoreGraphics, SwiftUI, CoreText or
  PDFKit.**
- No third-party dependency.
- Swift Testing in the package; XCTest in the application targets.
- A gateway gets a shared contract in `TestSupport`, run against the fake and
  the real implementation.
- Every task ends with the package suite green and one commit.
- Commits are unsigned: `git -c commit.gpgsign=false commit`.
- Prose follows ASD-STE100.

---

### Task 1: what an answer is

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ControlsSource.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ControlStatus.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/CompensatingControl.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/gateway/ControlsSourceGateway.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ControlsSourceTests.swift`

**Interfaces:**

```swift
public enum ControlStatus: String, Equatable, Sendable, CaseIterable {
    case implemented, notImplemented = "not_implemented"
    case notApplicable = "not_applicable", accepted
    /// True when a person has answered. `not_implemented` has not been answered.
    public var isAnswered: Bool
    /// Only `implemented` records the control, as the checkbox does today.
    public var isRecorded: Bool
    public var label: String
}

public struct CompensatingControl: Equatable, Sendable {
    public let label: String
    public let reducesRiskBy: Int      // 0 to 100
    public let rationale: String
}

/// `"<threatId>@<source.id>"`, the pair ThreatResolver already mints.
public struct ThreatKey: Hashable, Sendable, CustomStringConvertible {
    public init(threatId: String, sourceId: String)
    public init(_ value: String)
    public let value: String
}

public struct SourceThreatAnswer: Equatable, Sendable {
    public let threatId: String
    public let sourceKind: String        // component | zone | flow
    public let sourceId: String
    public let severityLabel: String?    // written for the reader; ignored on read
    public let score: Int?
    public let controls: [SourceControlAnswer]
    public let compensating: [CompensatingControl]
    public let isStale: Bool
    public var key: ThreatKey
}

public struct SourceControlAnswer: Equatable, Sendable {
    public let description: String
    public let status: ControlStatus
    public let note: String?
}

public struct ControlsSource: Equatable, Sendable {
    public let systemName: String
    public let catalogueTag: String?
    public let answers: [SourceThreatAnswer]
}

public struct ControlsRead: Equatable, Sendable {
    public let source: ControlsSource?
    public let diagnostics: [Diagnostic]
    public var hasErrors: Bool
}

public protocol ControlsSourceGateway: Sendable {
    func read(_ text: String) -> ControlsRead
    func write(_ source: ControlsSource) -> String
}
```

- [ ] **Step 1: Write the failing tests** for `ThreatKey`'s two initialisers,
      `ControlStatus.isAnswered` (true for every case except
      `not_implemented`), `isRecorded` (true only for `implemented`), and
      `SourceThreatAnswer.key`.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Write the types and the port.**
- [ ] **Step 4: Run the suite.**
- [ ] **Step 5: Commit.** `feat: state what a control answer is`

---

### Task 2: the controls grammar

**Files:**
- Create: `ThreatModelKit/Sources/ArchitectureDSL/ControlsParser.swift`
- Create: `ThreatModelKit/Sources/ArchitectureDSL/ControlsWriter.swift`
- Create: `ThreatModelKit/Sources/ArchitectureDSL/HclControlsSource.swift`
- Create: `ThreatModelKit/Sources/TestSupport/ControlsSourceGatewayContract.swift`
- Create: `ThreatModelKit/Sources/TestSupport/FakeControlsSource.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ControlsParserTests.swift`
- Test: `ThreatModelKit/Tests/GatewayContractTests/ControlsSourceGatewayContractTests.swift`

The grammar of spec §4.1, read by the lexer written in Milestone 10A:

```hcl
controls for "Payments" {
  catalogue = "v1.0.1"

  threat "credential-theft" on component "api" {
    severity = "critical"
    score    = 90

    control "Enforce MFA" {
      status = "implemented"
      note   = "Okta"
    }

    compensating "Break-glass account" {
      reduces_risk_by = 40
      rationale       = "The one account left alerts on use."
    }
  }

  stale threat "sql-injection" on component "cache" { }
}
```

Rules: `on` takes `component`, `zone` or `flow`; a status outside the four is an
error naming the field and the value; `reduces_risk_by` outside 0 to 100 is an
error; a `compensating` block with no `rationale` is an error, because a
reduction nobody can justify is not one. The writer's order is fixed: components
in the order the answers arrived, then flows, then zones, then stale; inside
each, threats by id; inside each, controls by description.

- [ ] **Step 1: Write the failing tests**, one per rule, plus the two properties
      the architecture writer already has: read, write, read gives the same
      value tree, and a canonical file is reproduced character for character.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Write the parser, the writer, the gateway, the fake and the
      contract.**
- [ ] **Step 4: Run the suite.**
- [ ] **Step 5: Commit.** `feat: read and write the controls language`

---

### Task 3: the model and the resolver

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/ThreatModel.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ThreatResolver.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/AssessThreatModel.swift`
- Test: `ThreatModelKit/Tests/UnitTests/CompensatingControlTests.swift`

`ThreatModel` gains:

```swift
public var controlStatuses: [ControlKey: ControlStatus]
public var compensatingControls: [ThreatKey: [CompensatingControl]]
/// Derived, so nothing that reads it changes.
public var implementedControls: Set<ControlKey> { get set }
```

`implementedControls` keeps its name and its shape: reading it returns every key
whose status is `implemented`; writing it sets those keys to `implemented` and
clears the rest. `ThreatResolver` applies the compensating reduction **last**,
multiplicatively, and two compensating controls on one threat give the stronger,
not the sum. `AssessedThreat` gains `controlStatuses: [String: String]` keyed by
control key, `compensatingControls: [CompensatingControl]` and
`scoreBeforeCompensation: Int`.

- [ ] **Step 1: Write the failing tests**: a compensating control lowers a
      score; two give the stronger; it applies after a pathway mitigation; the
      card can show the score before it; a status of `accepted` does not change
      a score; `implementedControls` still reads and writes as it did.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Write the changes.**
- [ ] **Step 4: Run the suite** — every existing scoring test must stay green.
- [ ] **Step 5: Commit.** `feat: let a compensating control lower a score`

---

### Task 4: document format version 3

**Files:**
- Modify: `ThreatModelKit/Sources/FileGateways/DocumentJSON.swift`
- Modify: `ThreatModelKit/Sources/FileGateways/ThreatModelCodec.swift`
- Test: `ThreatModelKit/Tests/GatewayIntegrationTests/ThreatModelCodecTests.swift`

`formatVersion` becomes 3; `readableFormatVersions` becomes `[1, 2, 3]`. The
document gains `controlStatuses: [String: String]` and
`compensatingControls: [String: [CompensatingControlJSON]]`. A version 1 or 2
file has neither and reads as before, with `implementedControls` setting the
statuses.

- [ ] **Step 1: Write the failing tests**: a round trip carries both fields; a
      version 2 file still opens and its ticks become `implemented` statuses.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Write the changes.**
- [ ] **Step 4: Run the suite.**
- [ ] **Step 5: Commit.** `feat: carry control answers in the document format`

---

### Task 5: `CompileControls`

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/CompileControls.swift`
- Modify: the three composition roots
- Test: `ThreatModelKit/Tests/UnitTests/CompileControlsTests.swift`

```swift
public struct CompileControlsRequest: Equatable, Sendable {
    public let architectureText: String
    /// The answers as they are now, or nil the first time.
    public let controlsText: String?
}
public enum CompileControlsResponse: Equatable, Sendable {
    case compiled(text: String, answered: Int, unanswered: Int, stale: Int)
    case refused(diagnostics: [Diagnostic])
}
```

The merge table of spec §4.3, stated as one test each:

| Case | Result |
|---|---|
| raised, and answered | the answer is kept whole |
| raised, not answered | a stanza with every control at `not_implemented` |
| answered, no longer raised | the answer moves into a `stale` block |
| a control has left the catalogue | it is dropped; its answer is not kept |
| a stale answer's threat is raised again | it moves back out of `stale` |

Plus: compiling an unchanged model writes the file it read.

- [ ] **Step 1: Write the failing tests.**
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Write the use case.** It imports the architecture into a
      throw-away gateway, resolves through `ThreatResolver`, and merges.
- [ ] **Step 4: Run the suite.**
- [ ] **Step 5: Commit.** `feat: compile the controls a model's threats need`

---

### Task 6: applying and checking

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/ApplyControlAnswers.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/CheckControlAnswers.swift`
- Modify: the three composition roots
- Test: `ThreatModelKit/Tests/UnitTests/ApplyControlAnswersTests.swift`

```swift
public enum ApplyControlAnswersResponse: Equatable, Sendable {
    case applied(answers: Int, warnings: [Diagnostic])
    case refused(diagnostics: [Diagnostic])
}
public struct UnansweredThreat: Equatable, Sendable {
    public let threatId: String, sourceName: String, riskLevel: String
}
public struct CheckControlAnswersResponse: Equatable, Sendable {
    public let unanswered: [UnansweredThreat]
    public let stale: [String]
    public var isClean: Bool
}
```

`ApplyControlAnswers` sets `controlStatuses` and `compensatingControls` on the
model. An answer naming a control the model does not offer is a warning, not an
error: a catalogue moved under a committed file, and that is what the warning
says.

- [ ] **Step 1: Write the failing tests**, including that applying an answer
      moves the score the sidebar shows.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Write the two use cases.**
- [ ] **Step 4: Run the suite.**
- [ ] **Step 5: Commit.** `feat: apply and check the answers a file holds`

---

### Task 7: the report

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/Report.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/BuildThreatModelReport.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/ExportModelAsMarkdown.swift`
- Modify: `threatmodeller/reporting/PDFReportRenderer.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ReportingTests.swift`

`ReportControl` gains `statusLabel: String`. `ReportThreat` gains
`compensating: [ReportCompensatingControl]` and `scoreBeforeCompensation: Int`.
`ReportSummary` gains `byControlStatus: [ReportCount]`. The Markdown writes a
status beside each control and a line naming what compensates a threat and what
it bought.

- [ ] **Step 1: Write the failing tests**, pinning the Markdown text.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Write the changes.**
- [ ] **Step 4: Run the suite and the application test target.**
- [ ] **Step 5: Commit.** `feat: report what is answered and what compensates`

---

### Task 8: `compile`, `check` and `report`

**Files:**
- Modify: `ThreatModelKit/Sources/CommandLineApplication/CommandLineApplication.swift`
- Modify: `.github/workflows/linux.yml`
- Test: `ThreatModelKit/Tests/UnitTests/CommandLineApplicationTests.swift`

```
threatmodeller compile [<root>]
threatmodeller check   [<root>]
threatmodeller report  [<root>] [-o <dir>]
```

`check` returns 1 when a threat is unanswered or an answer is stale, and prints
one line per finding. `report` writes `<name>.md` beside the architecture, or
into `-o <dir>`.

- [ ] **Step 1: Write the failing tests**, including the exit codes.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Write the verbs, and put `check` into the Linux job.**
- [ ] **Step 4: Run the suite, then the three verbs over a scratch project.**
- [ ] **Step 5: Commit.** `feat: compile, check and report from a shell`

---

### Task 9: the sidebar and the project window

**Files:**
- Modify: `threatmodeller/sidebar/ThreatCard.swift`
- Create: `threatmodeller/sidebar/CompensatingControlSheet.swift`
- Modify: `threatmodeller/ThreatModelSession.swift`
- Modify: `threatmodeller/project/ProjectSession.swift`
- Modify: `threatmodeller/threatmodellerApp.swift`
- Test: `threatmodellerTests/threatmodellerTests.swift`

A control row's checkbox becomes a four-way status control. A compensating
section under a threat's controls lists what compensates it, with a sheet to add
or edit one. `ProjectSession.save()` writes the architecture **and** merges the
answers into the `.controls` file. A *Compile Report* command writes the `.md`.

- [ ] **Step 1: Write the failing tests** over the session.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Write the changes.**
- [ ] **Step 4: Run the application test target.**
- [ ] **Step 5: Commit.** `feat: answer a control and compensate a threat in the application`

---

### Task 10: the whole line

**Files:**
- Create: `ThreatModelKit/Tests/AcceptanceTests/AnsweringThreatsInSourceTests.swift`
- Modify: `threatmodellerUITests/threatmodellerUITests.swift`
- Create: `docs/superpowers/specs/MILESTONE-11-CARRY-FORWARD.md`

The acceptance test: write `.arch`, compile the controls, read the stub, answer
one control and compensate one threat, apply, and see the score move and the
Markdown say so. The journey: open a project with a `.controls` file beside its
`.arch` and read a recorded control in the sidebar.

- [ ] **Step 1: Write the acceptance test and the journey.**
- [ ] **Step 2: Run the whole test plan.**
- [ ] **Step 3: Write the carry-forward.**
- [ ] **Step 4: Commit and push.** `test: walk the whole code-first line`

---

## Self-review

- **Spec coverage.** §4.1 and §4.2 Task 2. §4.3 Task 5. §5 Task 3. §6.5 Tasks 3,
  4, 7. §9 Task 8. §11 Tasks 2, 5, 6, 10.
- **Placeholders.** None.
- **Type consistency.** `ControlStatus`, `CompensatingControl` and `ThreatKey`
  are defined in Task 1 and used in Tasks 2 to 9. `ControlsSource` and
  `SourceThreatAnswer` are defined in Task 1 and used in Tasks 2, 5 and 6.
