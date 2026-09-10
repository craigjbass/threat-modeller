# Host and endpoint modelling implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A user models a macOS endpoint and the security product that protects
it, and the report states an honest residual score, the local flows raise no
TLS threats, a privilege boundary is a boundary, one component mitigates a
threat on another, and the report names the recommendations and the attack
paths.

**Architecture:** Three new application-owned vocabularies (`FlowKind`,
`ZoneBoundary`, `PrivilegeLevel`) reach the resolver through two new domain
types the resolver calls but does not hold: `ThreatApplicability` decides
whether a threat is raised, and `ComponentMitigations` decides what a
`mitigates` edge takes off. A fourth new domain type, `ControlCoverage`, adds
the stage that makes an implemented control lower a score. The report gains
four sections, each built by its own domain type and rendered by its own
Markdown file, so four agents write four sections without touching one file.

**Tech Stack:** Swift 6.3, `swift-tools-version: 6.2`, SwiftPM, Swift Testing,
SwiftUI in the application target only, Foundation only in the package.

**Spec:** `docs/superpowers/specs/2026-09-10-endpoint-modelling-design.md`

## Global Constraints

- Swift 6.3, `swift-tools-version: 6.2`, `platforms: [.macOS(.v26)]`.
- **No package target may import AppKit, CoreGraphics, SwiftUI, CoreText or
  PDFKit.** Foundation only.
- No third-party dependency.
- Swift Testing (`@Test`, `#expect`, `#require`) in the package and in the
  application test target.
- Domain objects never cross the use case boundary. A use case takes a request
  value and returns a response value.
- A gateway gets a shared contract in `TestSupport`, run against the fake and
  the real implementation.
- Every task ends with `cd ThreatModelKit && swift test` green and one commit.
- Commits are unsigned: `git -c commit.gpgsign=false commit`.
- Prose in code comments, commits and documents follows ASD-STE100.
- **Never edit the vendored catalogue.** Every file under
  `ThreatModelKit/Sources/CatalogueGateways/Resources/Library/` is third-party
  and checksum-locked. `scripts/update-catalogue.sh verify` must pass at the
  end of every task.
- After adding a file to `ThreatModelKit`, run
  `xcodebuild clean -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
  before the application tests. `docs/TESTING.md` states why.
- The PDF renderer gains the inherent score in Task 2 and nothing else. The
  four new report sections are Markdown and report tree only.

## How the seventeen agents run

One branch, `endpoint-modelling`. Five waves. A wave that needs new types
starts with one **contract task** that adds the types, the fields and the call
sites and changes no behaviour. The consumer tasks of that wave start as soon
as the contract task's commit exists, run at the same time as each other, and
own disjoint files.

| Wave | Contract task | Consumer tasks, run together |
| --- | --- | --- |
| 1 | Task 1 | Task 2, Task 3 |
| 2 | Task 4 | Task 5, Task 6, Task 7 |
| 3 | none — Task 4 laid the contract | Task 8, Task 9, Task 10, Task 11, Task 12 |
| 4 | Task 13 | Task 14, Task 15, Task 16 |
| 5 | none | Task 17, which runs alone |

Task 12 sits in wave 3 rather than wave 2 because it needs the `.lib`
attributes Task 6 adds, and it changes no Swift file, so it collides with
nothing.

**The ownership rule.** A file appears in the **Files** block of exactly one
task per wave. An agent that needs to change a file another agent in its wave
owns must stop and report it, never edit it.

Start the branch before Task 1:

```bash
git fetch origin main
git checkout -b endpoint-modelling origin/main
```

---

## Wave 1: the control coverage stage

### Task 1: control coverage lowers the score

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ControlCoverage.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ThreatResolver.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ControlCoverageTests.swift`

**Interfaces:**
- Consumes: `ResolvedControl`, `ControlStatus`, `Threat`, `RiskScore`.
- Produces:
  `enum ControlCoverage { static let maxReduction: Double; static func coverage(of: [ResolvedControl]) -> Double; static func apply(to score: Int, controls: [ResolvedControl]) -> Int }`,
  and on `ResolvedThreat` the new stored property
  `public let scoreBeforeControls: Int`, with the initialiser parameter
  `scoreBeforeControls: Int? = nil` defaulting to `score.value`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/ControlCoverageTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct ControlCoverageTests {
    private func control(_ description: String, _ status: ControlStatus) -> ResolvedControl {
        ResolvedControl(
            description: description,
            isTechnologySpecific: false,
            key: ControlKey(description),
            isImplemented: status == .implemented,
            status: status
        )
    }

    @Test func noControlsGiveNoCoverage() {
        #expect(ControlCoverage.coverage(of: []) == 0)
    }

    @Test func coverageIsTheImplementedShareOfTheApplicableControls() {
        let controls = [
            control("a", .implemented),
            control("b", .implemented),
            control("c", .notImplemented),
            control("d", .notImplemented),
            control("e", .notImplemented)
        ]
        #expect(ControlCoverage.coverage(of: controls) == 0.4)
    }

    @Test func aNotApplicableControlLeavesTheDenominator() {
        let controls = [
            control("a", .implemented),
            control("b", .notApplicable),
            control("c", .notImplemented)
        ]
        #expect(ControlCoverage.coverage(of: controls) == 0.5)
    }

    @Test func anAcceptedControlStaysInTheDenominatorAndLowersNothing() {
        let controls = [control("a", .accepted), control("b", .notImplemented)]
        #expect(ControlCoverage.coverage(of: controls) == 0)
    }

    @Test func threeOfFiveImplementedTakeTwelveToSeven() {
        let controls = [
            control("a", .implemented),
            control("b", .implemented),
            control("c", .implemented),
            control("d", .notImplemented),
            control("e", .notImplemented)
        ]
        #expect(ControlCoverage.apply(to: 12, controls: controls) == 7)
    }

    @Test func everyControlImplementedStillLeavesThirtyPercent() {
        let controls = [control("a", .implemented), control("b", .implemented)]
        #expect(ControlCoverage.apply(to: 10, controls: controls) == 3)
    }

    @Test func theScoreNeverFallsBelowOne() {
        let controls = [control("a", .implemented)]
        #expect(ControlCoverage.apply(to: 1, controls: controls) == 1)
    }
}
```

- [ ] **Step 2: Run the test and see it fail**

Run: `cd ThreatModelKit && swift test --filter ControlCoverageTests`
Expected: FAIL, `cannot find 'ControlCoverage' in scope`.

- [ ] **Step 3: Write the type**

Create `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ControlCoverage.swift`:

```swift
/// How much the answered controls take off a threat's score.
///
/// Spec section 3.1. The stage sits after the zone multiplier and before the
/// pathway mitigation, so a user who answers the questions sees the number
/// move, and nobody has to restate an implemented control as compensating
/// prose to make the number honest.
public enum ControlCoverage {
    /// The most the controls take off, whatever the coverage. A threat that
    /// every control answers is smaller, never absent.
    public static let maxReduction = 0.70

    /// The share of the applicable controls a person has implemented.
    ///
    /// `not_applicable` leaves the denominator, because a control that does
    /// not apply is not work anybody skipped. `accepted` stays in the
    /// denominator and gives nothing, because an accepted risk is still a
    /// risk.
    public static func coverage(of controls: [ResolvedControl]) -> Double {
        let applicable = controls.filter { $0.status != .notApplicable }
        guard applicable.isEmpty == false else { return 0 }
        let implemented = applicable.filter { $0.status == .implemented }
        return Double(implemented.count) / Double(applicable.count)
    }

    /// The score after the controls, and never below 1.
    public static func apply(to score: Int, controls: [ResolvedControl]) -> Int {
        let reduction = coverage(of: controls) * maxReduction
        return max(1, Int((Double(score) * (1 - reduction)).rounded()))
    }
}
```

- [ ] **Step 4: Run the test and see it pass**

Run: `cd ThreatModelKit && swift test --filter ControlCoverageTests`
Expected: PASS.

- [ ] **Step 5: Write the failing resolver test**

Add to `ThreatModelKit/Tests/UnitTests/ControlCoverageTests.swift`:

```swift
struct ControlCoverageInTheResolverTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func ec2() -> Component {
        Component(
            id: ComponentId("c1"),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: .confidential
        )
    }

    /// The two technology-specific controls EC2 offers against credential
    /// theft. `CatalogueFixture.ec2()` declares both.
    private func key(_ description: String) -> ControlKey {
        ControlIdentity.componentControl(
            componentId: ComponentId("c1"),
            threatId: ThreatId("credential-theft"),
            description: description,
            isTechnologySpecific: true
        )
    }

    private func resolve(_ statuses: [ControlKey: ControlStatus]) -> ResolvedThreat {
        let model = ThreatModel(components: [ec2()], controlStatuses: statuses)
        let resolved = ThreatResolver(model: model, catalogue: catalogue).resolve()
        return resolved.first { $0.threat.id == ThreatId("credential-theft") }!
    }

    @Test func anUnansweredThreatKeepsItsScore() {
        let threat = resolve([:])
        #expect(threat.score.value == 12)
        #expect(threat.scoreBeforeControls == 12)
    }

    @Test func oneOfTwoControlsTakesTwelveToEight() {
        let threat = resolve([key("Enforce IMDSv2 to block SSRF-based credential theft"): .implemented])
        #expect(threat.score.value == 8)
        #expect(threat.scoreBeforeControls == 12)
    }

    @Test func bothControlsTakeTwelveToFour() {
        let threat = resolve([
            key("Enforce IMDSv2 to block SSRF-based credential theft"): .implemented,
            key("Use IAM roles with minimal permissions"): .implemented
        ])
        #expect(threat.score.value == 4)
    }

    @Test func anAcceptedControlChangesNothing() {
        let threat = resolve([key("Enforce IMDSv2 to block SSRF-based credential theft"): .accepted])
        #expect(threat.score.value == 12)
    }
}
```

- [ ] **Step 6: Run it and see it fail**

Run: `cd ThreatModelKit && swift test --filter ControlCoverageInTheResolverTests`
Expected: FAIL, `value of type 'ResolvedThreat' has no member 'scoreBeforeControls'`.

- [ ] **Step 7: Add the field to `ResolvedThreat`**

In `ThreatResolver.swift`, add the stored property beside
`scoreBeforePathwayMitigation`:

```swift
    /// The score before the controls answered anything. Equal to `score.value`
    /// when no control was implemented.
    public let scoreBeforeControls: Int
```

Add the parameter to the initialiser, after `scoreBeforePathwayMitigation`:

```swift
        scoreBeforeControls: Int? = nil,
```

and assign it first in the body, beside the other defaulted assignments:

```swift
        self.scoreBeforeControls = scoreBeforeControls ?? score.value
```

Then carry it through `compensated(_:)`, which rebuilds the value: add
`scoreBeforeControls: threat.scoreBeforeControls` to the `ResolvedThreat(...)`
it returns.

- [ ] **Step 8: Add the stage to the component branch**

In `resolve()`, in the `for component in model.components` loop, hoist the
controls above the score and put the stage between the zone multiplier and the
pathway mitigation:

```swift
                let base = RiskScore(severity: chosen.severity, sensitivity: sensitivity)
                let zoned = RiskScore(value: ZoneMultiplier.apply(multiplier, to: base.value))
                guard zoned.value > 0 else { continue }
                let controls = componentControls(
                    for: threat,
                    on: technology,
                    componentId: component.id
                )
                let covered = ControlCoverage.apply(to: zoned.value, controls: controls)
                guard let mitigation = mitigated(
                    threat: threat,
                    score: covered,
                    upstreamOf: component.id,
                    graph: graph,
                    technologyById: technologyById
                ) else { continue }
                let score = RiskScore(value: mitigation.score)
```

In the same `raise(...)` call, pass `controls: controls`,
`scoreBeforePathwayMitigation: covered` and `scoreBeforeControls: zoned.value`.

- [ ] **Step 9: Add the stage to the connection branch and the zone branch**

Connection branch, same shape:

```swift
                let zoned = RiskScore(value: ZoneMultiplier.apply(multiplier, to: base.value))
                guard zoned.value > 0 else { continue }
                let controls = sharedControls(for: threat, keyedBy: ControlIdentity.connectionControl)
                let covered = ControlCoverage.apply(to: zoned.value, controls: controls)
                guard let mitigation = mitigated(
                    threat: threat,
                    score: covered,
                    upstreamOf: source.id,
                    graph: graph,
                    technologyById: technologyById
                ) else { continue }
```

and in its `raise(...)`: `controls: controls`,
`scoreBeforePathwayMitigation: covered`, `scoreBeforeControls: zoned.value`.

Zone branch, which has no pathway stage:

```swift
                let base = RiskScore(severity: chosen.severity, sensitivity: .internalData)
                let zoned = RiskScore(value: ZoneMultiplier.apply(multiplier, to: base.value))
                guard zoned.value > 0 else { continue }
                let controls = sharedControls(for: threat, keyedBy: ControlIdentity.zoneControl)
                let score = RiskScore(value: ControlCoverage.apply(to: zoned.value, controls: controls))
```

and in its `raise(...)`: `controls: controls`,
`scoreBeforePathwayMitigation: score.value`, `scoreBeforeControls: zoned.value`.

- [ ] **Step 10: Run the whole package suite**

Run: `cd ThreatModelKit && swift test`
Expected: PASS. Existing tests that assert a score on an answered threat now
read the lower number. Change the expected value in the test, never the
arithmetic: the lower number is the point of this task. Note each changed
expectation in the commit body.

- [ ] **Step 11: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ControlCoverage.swift \
        ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ThreatResolver.swift \
        ThreatModelKit/Tests/UnitTests/ControlCoverageTests.swift
git -c commit.gpgsign=false commit -m "feat: an implemented control lowers the risk score"
```

---

### Task 2: the report states the inherent score and the residual score

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/AssessThreatModel.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/Report.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/BuildThreatModelReport.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/ExportModelAsMarkdown.swift`
- Modify: `threatmodeller/reporting/PDFReportRenderer.swift`
- Modify: `threatmodeller/sidebar/ThreatCard.swift`
- Test: `ThreatModelKit/Tests/UnitTests/InherentScoreTests.swift`

**Interfaces:**
- Consumes: `ResolvedThreat.scoreBeforeControls` from Task 1.
- Produces: `AssessedThreat.inherentScore: Int`, `ReportThreat.inherentScore: Int`.
  Both take the initialiser parameter `inherentScore: Int? = nil`, defaulting to
  the residual score, so no existing caller breaks.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/InherentScoreTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct InherentScoreTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func model() -> ThreatModel {
        ThreatModel(
            components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .confidential
                )
            ],
            controlStatuses: [
                ControlIdentity.componentControl(
                    componentId: ComponentId("c1"),
                    threatId: ThreatId("credential-theft"),
                    description: "Enforce IMDSv2 to block SSRF-based credential theft",
                    isTechnologySpecific: true
                ): .implemented
            ]
        )
    }

    @Test func theAssessmentStatesBothScores() throws {
        let response = AssessThreatModel(
            models: InMemoryThreatModelGateway(model()),
            catalogue: catalogue
        ).execute(AssessThreatModelRequest())
        let threat = try #require(response.threats.first { $0.threatId == "credential-theft" })
        #expect(threat.riskScore == 8)
        #expect(threat.inherentScore == 12)
    }

    @Test func theReportStatesBothScores() throws {
        let report = BuildThreatModelReport(
            models: InMemoryThreatModelGateway(model()),
            catalogue: catalogue
        ).execute(BuildThreatModelReportRequest()).report
        let threat = try #require(report.threats.first { $0.threatId == "credential-theft" })
        #expect(threat.riskScore == 8)
        #expect(threat.inherentScore == 12)
    }

    @Test func theMarkdownStatesWhatTheControlsBought() {
        let markdown = ExportModelAsMarkdown(
            reports: BuildThreatModelReport(
                models: InMemoryThreatModelGateway(model()),
                catalogue: catalogue
            )
        ).execute(ExportModelAsMarkdownRequest()).markdown
        #expect(markdown.contains("- Risk: High (8), before controls 12"))
    }
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd ThreatModelKit && swift test --filter InherentScoreTests`
Expected: FAIL, `value of type 'AssessedThreat' has no member 'inherentScore'`.

- [ ] **Step 3: Add the field to the assessment**

In `AssessThreatModel.swift`, add to `AssessedThreat`:

```swift
    /// The score before the implemented controls lowered it. Equal to
    /// `riskScore` when nothing was implemented.
    public let inherentScore: Int
```

Add `inherentScore: Int? = nil` as the last initialiser parameter and
`self.inherentScore = inherentScore ?? riskScore` in the body. In
`AssessThreatModel.execute`, pass `inherentScore: threat.scoreBeforeControls`.

- [ ] **Step 4: Add the field to the report tree**

In `Report.swift`, add to `ReportThreat`:

```swift
    /// The score before the implemented controls lowered it.
    public let inherentScore: Int
```

Add `inherentScore: Int? = nil` as the last initialiser parameter, assign
`self.inherentScore = inherentScore ?? riskScore` at the top of the body beside
`self.compensating`, and in `BuildThreatModelReport.threat(from:...)` pass
`inherentScore: assessed.inherentScore`.

- [ ] **Step 5: Render it in the Markdown**

In `ExportModelAsMarkdown.threats(_:)`, replace the risk line:

```swift
            if threat.inherentScore == threat.riskScore {
                lines.append("- Risk: \(threat.riskLevel) (\(threat.riskScore))")
            } else {
                lines.append(
                    "- Risk: \(threat.riskLevel) (\(threat.riskScore)),"
                        + " before controls \(threat.inherentScore)"
                )
            }
```

- [ ] **Step 6: Run the package suite**

Run: `cd ThreatModelKit && swift test`
Expected: PASS. `ReportRendererTests` in the application target may pin the old
line; Step 8 runs it.

- [ ] **Step 7: Show it in the PDF and on the threat card**

In `threatmodeller/reporting/PDFReportRenderer.swift`, wherever the renderer
draws `riskScore`, draw the same two-number form the Markdown uses: the
residual score, then `before controls <n>` when `inherentScore` differs.

In `threatmodeller/sidebar/ThreatCard.swift`, add the same under the score
badge, using `threat.inherentScore`.

- [ ] **Step 8: Run the application tests**

```bash
xcodebuild clean -project threatmodeller.xcodeproj -scheme threatmodeller \
  -destination 'platform=macOS'
xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller \
  -destination 'platform=macOS'
```
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/AssessThreatModel.swift \
        ThreatModelKit/Sources/ThreatModelKit/reporting \
        ThreatModelKit/Tests/UnitTests/InherentScoreTests.swift \
        threatmodeller/reporting/PDFReportRenderer.swift \
        threatmodeller/sidebar/ThreatCard.swift
git -c commit.gpgsign=false commit -m "feat: every report states the inherent score and the residual score"
```

---

### Task 3: the language reference states the coverage stage

**Files:**
- Modify: `docs/LANGUAGE.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: `ControlCoverage.maxReduction` from Task 1. Nothing consumes this
  task.

- [ ] **Step 1: Change the status table in `LANGUAGE.md` section 5.5**

Replace the table under "| Status | Counts as an answer | Lowers the score |"
with:

```markdown
| Status | Counts as an answer | Lowers the score |
| --- | --- | --- |
| `implemented` | yes | yes, by its share of the applicable controls |
| `not_applicable` | yes | no, and it leaves the share |
| `accepted` | yes | no, and it stays in the share |
| `not_implemented` | no | no |
```

- [ ] **Step 2: Add the scoring paragraph after that table**

```markdown
The implemented controls lower the score together, not one at a time. The
share is `implemented / applicable`, where `applicable` is every control whose
status is not `not_applicable`. That share takes off at most 70% of the score,
and a score never falls below 1. A threat with 5 controls and 3 implemented
scores `round(12 * (1 - 0.6 * 0.70))` = 7 where it scored 12.

WARNING: `accepted` answers a threat and lowers nothing. An accepted risk is
still a risk, and the report states it at its full score.
```

- [ ] **Step 3: State the pipeline in `README.md`**

Find the section that states how a score is worked out and replace the list of
stages with:

```markdown
1. the threat's severity rank, multiplied by the component's data sensitivity
2. the zone's risk reduction, when the component sits in a private zone
3. the implemented controls, by their share of the applicable controls
4. the strongest pathway mitigation upstream of the component
5. the strongest compensating control on the threat
```

- [ ] **Step 4: Check the documents build**

Run: `grep -n "not_applicable" docs/LANGUAGE.md`
Expected: the new table rows appear, and no other row contradicts them.

- [ ] **Step 5: Commit**

```bash
git add docs/LANGUAGE.md README.md
git -c commit.gpgsign=false commit -m "docs: state that an implemented control lowers the score"
```

---

## Wave 2: the vocabularies and the three languages

### Task 4: the vocabularies, the fields and the resolver hooks

This is the contract task of wave 2 and wave 3. It changes no behaviour: every
new type is inert, and every new hook returns what the resolver already
produced. Tasks 5, 6, 7, 8, 9, 10 and 11 all read the names this task mints.

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/FlowKind.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/PrivilegeLevel.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/ZoneBoundary.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Asset.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/MitigatesEdge.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/Recommendation.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ThreatApplicability.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ComponentMitigations.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Connection.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Component.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Zone.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/ThreatModel.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/Threat.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ThreatResolver.swift`
- Test: `ThreatModelKit/Tests/UnitTests/VocabularyTests.swift`

**Interfaces:**
- Produces, and nothing in this task may change after it is committed:
  - `enum FlowKind: String { case network, ipc, file, syscall, human }`, with
    `var label: String` and `static let `default`: FlowKind = .network`.
  - `enum PrivilegeLevel: String { case user, admin, root, system, kernel }`,
    with `var rank: Int` (1 to 5) and `var label: String`.
  - `enum ZoneBoundary: String { case network, privilege }`, with `var label: String`.
  - `struct Asset { let name: String; let sensitivity: DataSensitivity }`.
  - `struct MitigatesEdge { let id: String; let source: ComponentId; let target: ComponentId; let threatIds: [ThreatId]; let reducesRiskBy: Int }`.
  - `struct Recommendation { let text: String; let note: String? }`.
  - `struct ComponentMitigation { let protectorId: ComponentId; let protectorName: String; let reducesRiskBy: Int }`.
  - `enum ThreatApplicability { static func appliesToComponent(threat:runsAs:) -> Bool; static func appliesToConnection(threat:kind:crossesPrivilege:) -> Bool; static func appliesToZone(threat:boundary:) -> Bool }`.
  - `enum ComponentMitigations { static func apply(score:threatId:target:edges:nameOf:) -> (score: Int, by: [ComponentMitigation]) }`.
  - `Connection.kind: FlowKind`, `Connection.description: String?`.
  - `Component.runsAs: PrivilegeLevel`, `Component.assets: [Asset]`,
    `Component.effectiveSensitivity: DataSensitivity`.
  - `Zone.boundary: ZoneBoundary`, `Zone.description: String?`.
  - `ThreatModel.mitigatesEdges: [MitigatesEdge]`,
    `ThreatModel.recommendations: [ThreatKey: [Recommendation]]`.
  - `Threat.appliesToFlowKinds: [FlowKind]`, `Threat.boundary: ZoneBoundary?`,
    `Threat.appliesToPrivilegeLevels: [PrivilegeLevel]`.
  - `ResolvedThreat.mitigatedByComponents: [ComponentMitigation]`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/VocabularyTests.swift`:

```swift
import Testing
import ThreatModelKit

struct VocabularyTests {
    @Test func aFlowIsANetworkFlowUnlessItSaysOtherwise() {
        #expect(FlowKind.default == .network)
        #expect(FlowKind(rawValue: "ipc") == .ipc)
        #expect(FlowKind.allCases.count == 5)
    }

    @Test func thePrivilegeLadderRuns() {
        #expect(PrivilegeLevel.user.rank < PrivilegeLevel.root.rank)
        #expect(PrivilegeLevel.root.rank < PrivilegeLevel.kernel.rank)
    }

    @Test func aZoneIsANetworkBoundaryUnlessItSaysOtherwise() {
        #expect(Zone(id: ZoneId("z"), rect: Rect(x: 0, y: 0, width: 200, height: 200)).boundary == .network)
    }

    @Test func aComponentRunsAsTheUserUnlessItSaysOtherwise() {
        #expect(component().runsAs == .user)
    }

    @Test func aComponentWithNoAssetScoresAtItsOwnSensitivity() {
        #expect(component().effectiveSensitivity == .internalData)
    }

    @Test func aComponentScoresAtItsHighestAsset() {
        let held = component(assets: [
            Asset(name: "cookies", sensitivity: .confidential),
            Asset(name: "ssh-keys", sensitivity: .restricted)
        ])
        #expect(held.effectiveSensitivity == .restricted)
    }

    @Test func anAssetNeverLowersTheComponentsOwnSensitivity() {
        let held = component(
            sensitivity: .restricted,
            assets: [Asset(name: "notes", sensitivity: .publicData)]
        )
        #expect(held.effectiveSensitivity == .restricted)
    }

    private func component(
        sensitivity: DataSensitivity = .internalData,
        assets: [Asset] = []
    ) -> Component {
        Component(
            id: ComponentId("c1"),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: sensitivity,
            assets: assets
        )
    }
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd ThreatModelKit && swift test --filter VocabularyTests`
Expected: FAIL, `cannot find 'FlowKind' in scope`.

- [ ] **Step 3: Write the three vocabularies**

`FlowKind.swift`:

```swift
/// What a flow between two components is.
///
/// Application-owned, as `DataSensitivity` and `NetworkZone` are: the
/// catalogue carries no flow vocabulary. A threat states the kinds it applies
/// to, and a threat that states none applies to a network flow only, so a
/// local call raises no threat about TLS.
public enum FlowKind: String, CaseIterable, Equatable, Sendable {
    case network
    case ipc
    case file
    case syscall
    case human

    public static let `default` = FlowKind.network

    public var label: String {
        switch self {
        case .network: "Network"
        case .ipc: "Local IPC"
        case .file: "File"
        case .syscall: "System Call"
        case .human: "Human"
        }
    }
}
```

`PrivilegeLevel.swift`:

```swift
/// The privilege a component runs at. Application-owned.
///
/// The ranks compare, so a flow between two levels is a privilege crossing
/// without anybody drawing a second component or a second zone.
public enum PrivilegeLevel: String, CaseIterable, Equatable, Sendable {
    case user
    case admin
    case root
    case system
    case kernel

    public static let `default` = PrivilegeLevel.user

    public var rank: Int {
        switch self {
        case .user: 1
        case .admin: 2
        case .root: 3
        case .system: 4
        case .kernel: 5
        }
    }

    public var label: String {
        switch self {
        case .user: "User"
        case .admin: "Administrator"
        case .root: "Root"
        case .system: "System"
        case .kernel: "Kernel"
        }
    }
}
```

`ZoneBoundary.swift`:

```swift
/// What a zone is a boundary of. Application-owned.
///
/// A network zone raises the network threat set. A privilege zone raises the
/// privilege threat set. Neither raises the other's, so a `uid 0` boundary no
/// longer collects threats about network misconfiguration.
public enum ZoneBoundary: String, CaseIterable, Equatable, Sendable {
    case network
    case privilege

    public static let `default` = ZoneBoundary.network

    public var label: String {
        switch self {
        case .network: "Network Boundary"
        case .privilege: "Privilege Boundary"
        }
    }
}
```

- [ ] **Step 4: Write the four value types**

`Asset.swift`:

```swift
/// One thing a component holds.
///
/// A secret store is not one blob: SSH keys and browser cookies differ in
/// sensitivity. A component scores at the highest sensitivity it holds.
public struct Asset: Equatable, Sendable {
    public let name: String
    public let sensitivity: DataSensitivity

    public init(name: String, sensitivity: DataSensitivity = .internalData) {
        self.name = name
        self.sensitivity = sensitivity
    }
}
```

`MitigatesEdge.swift`:

```swift
/// One component answers a named threat on another component.
///
/// This is the shape of the problem "a security product protects a host". The
/// product is a component like any other, and what it answers is an edge, not
/// prose repeated in every compensating control.
public struct MitigatesEdge: Equatable, Sendable {
    public let source: ComponentId
    public let target: ComponentId
    public let threatIds: [ThreatId]
    public let reducesRiskBy: Int

    public init(
        source: ComponentId,
        target: ComponentId,
        threatIds: [ThreatId],
        reducesRiskBy: Int
    ) {
        self.source = source
        self.target = target
        self.threatIds = threatIds
        self.reducesRiskBy = reducesRiskBy
    }

    /// The identifier, minted the way a flow's is.
    public var id: String { "\(source.value)->\(target.value)" }

    public func answers(_ threatId: ThreatId) -> Bool {
        threatIds.contains(threatId)
    }
}
```

`Recommendation.swift`:

```swift
/// What a person says should be done about a threat.
///
/// It is not an answer and it does not move a score. It is the work the
/// assessment found, and the report gives it its own section.
public struct Recommendation: Equatable, Sendable {
    public let text: String
    public let note: String?

    public init(text: String, note: String? = nil) {
        self.text = text
        self.note = note
    }
}
```

`ComponentMitigations.swift`:

```swift
/// What a `mitigates` edge takes off a threat.
public struct ComponentMitigation: Equatable, Sendable {
    public let protectorId: ComponentId
    public let protectorName: String
    public let reducesRiskBy: Int

    public init(protectorId: ComponentId, protectorName: String, reducesRiskBy: Int) {
        self.protectorId = protectorId
        self.protectorName = protectorName
        self.reducesRiskBy = reducesRiskBy
    }
}

/// The stage between the pathway mitigation and the compensating control.
///
/// Task 9 fills this in. Until then it returns the score it was given, so the
/// hook in `ThreatResolver` changes nothing.
public enum ComponentMitigations {
    public static func apply(
        score: Int,
        threatId: ThreatId,
        target: ComponentId,
        edges: [MitigatesEdge],
        nameOf: (ComponentId) -> String
    ) -> (score: Int, by: [ComponentMitigation]) {
        (score, [])
    }
}
```

- [ ] **Step 5: Write the applicability hook**

`ThreatApplicability.swift`:

```swift
/// Whether a threat is raised at all.
///
/// Task 8 fills these in. Until then every threat is raised, which is what the
/// resolver does today.
public enum ThreatApplicability {
    public static func appliesToComponent(threat: Threat, runsAs: PrivilegeLevel) -> Bool {
        true
    }

    public static func appliesToConnection(
        threat: Threat,
        kind: FlowKind,
        crossesPrivilege: Bool
    ) -> Bool {
        true
    }

    public static func appliesToZone(threat: Threat, boundary: ZoneBoundary) -> Bool {
        true
    }
}
```

- [ ] **Step 6: Add the fields to the model types**

`Connection.swift`: add `public var kind: FlowKind` and
`public var description: String?`, with the initialiser parameters
`kind: FlowKind = .default` and `description: String? = nil`.

`Component.swift`: add `public var runsAs: PrivilegeLevel` and
`public var assets: [Asset]`, with the initialiser parameters
`runsAs: PrivilegeLevel = .default` and `assets: [Asset] = []`, and this
derived property:

```swift
    /// The sensitivity the score uses: the highest of the component's own and
    /// every asset it holds. An asset never lowers what the component states.
    public var effectiveSensitivity: DataSensitivity {
        SensitivityLadder.higher(
            sensitivity,
            SensitivityLadder.highest(of: assets.map(\.sensitivity)) ?? sensitivity
        )
    }
```

`Zone.swift`: add `public var boundary: ZoneBoundary` and
`public var description: String?`, with the parameters
`boundary: ZoneBoundary = .default` and `description: String? = nil`.

`ThreatModel.swift`: add `public var mitigatesEdges: [MitigatesEdge]` and
`public var recommendations: [ThreatKey: [Recommendation]]`, with the
parameters `mitigatesEdges: [MitigatesEdge] = []` and
`recommendations: [ThreatKey: [Recommendation]] = [:]`.

`Threat.swift`: add `public let appliesToFlowKinds: [FlowKind]`,
`public let boundary: ZoneBoundary?` and
`public let appliesToPrivilegeLevels: [PrivilegeLevel]`, with the parameters
`appliesToFlowKinds: [FlowKind] = []`, `boundary: ZoneBoundary? = nil` and
`appliesToPrivilegeLevels: [PrivilegeLevel] = []`.

- [ ] **Step 7: Add the two hooks and the new field to the resolver**

In `ThreatResolver.swift`, add to `ResolvedThreat`:

```swift
    /// The components whose `mitigates` edges lowered this threat.
    public let mitigatedByComponents: [ComponentMitigation]
```

with the initialiser parameter `mitigatedByComponents: [ComponentMitigation] = []`,
and carry it through `compensated(_:)`.

In the component loop, read the sensitivity through the new derived property:
replace every `component.sensitivity` with `component.effectiveSensitivity`,
and in `escalated(...)` build `sensitivityById` from
`component.effectiveSensitivity`.

Guard the component threats:

```swift
            for threat in lookup.threatsFor(technologyId: component.technologyId) {
                guard ThreatApplicability.appliesToComponent(
                    threat: threat,
                    runsAs: component.runsAs
                ) else { continue }
```

Guard the connection threats, computing the crossing once above the loop:

```swift
            let crossesPrivilege = source.runsAs != target.runsAs

            for threat in catalogue.connectionThreats() {
                guard ThreatApplicability.appliesToConnection(
                    threat: threat,
                    kind: connection.kind,
                    crossesPrivilege: crossesPrivilege
                ) else { continue }
```

Guard the zone threats:

```swift
            for threat in catalogue.zoneThreats() {
                guard ThreatApplicability.appliesToZone(
                    threat: threat,
                    boundary: zone.boundary
                ) else { continue }
```

Add the `mitigates` stage after the pathway stage in the component branch, and
name the components once above the component loop:

```swift
        var nameById: [ComponentId: String] = [:]
        for component in model.components {
            nameById[component.id] = component.customName
                ?? lookup.findById(component.technologyId)?.name
                ?? component.technologyId.value
        }
```

then, in the component branch, between `mitigation` and `raise`:

```swift
                let byComponents = ComponentMitigations.apply(
                    score: mitigation.score,
                    threatId: threat.id,
                    target: component.id,
                    edges: model.mitigatesEdges,
                    nameOf: { nameById[$0] ?? $0.value }
                )
                let score = RiskScore(value: byComponents.score)
```

and pass `mitigatedByComponents: byComponents.by` to `raise`.

- [ ] **Step 8: Run the whole package suite**

Run: `cd ThreatModelKit && swift test`
Expected: PASS, and no expected value changes. This task changes no behaviour.
A changed score here is a fault in this task, not in a test.

- [ ] **Step 9: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit ThreatModelKit/Tests/UnitTests/VocabularyTests.swift
git -c commit.gpgsign=false commit -m "feat: the flow, privilege and boundary vocabularies and their resolver hooks"
```

---

### Task 5: the architecture language reads the new blocks

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ArchitectureSource.swift`
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/ArchitectureParser.swift`
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/ArchitectureWriter.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ArchitectureSourceBuilder.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/ImportArchitecture.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ArchitectureLanguageTests.swift`

**Interfaces:**
- Consumes: `FlowKind`, `PrivilegeLevel`, `ZoneBoundary`, `Asset`,
  `MitigatesEdge`, `Component.runsAs`, `Component.assets`, `Zone.boundary`,
  `Zone.description`, `Connection.kind`, `Connection.description`,
  `ThreatModel.mitigatesEdges` — all from Task 4.
- Produces:
  - `SourceFlow.kind: String` and `SourceFlow.description: String?`, with the
    initialiser parameters `kind: String = "network"` and
    `description: String? = nil`.
  - `SourceZone.boundary: String` and `SourceZone.description: String?`, with
    `boundary: String = "network"` and `description: String? = nil`.
  - `SourceComponent.runsAs: String` and `SourceComponent.assets: [SourceAsset]`,
    with `runsAs: String = "user"` and `assets: [SourceAsset] = []`.
  - `struct SourceAsset { let name: String; let data: String }`, with
    `data: String = "internal"`.
  - `struct SourceMitigates { let sourceId: String; let targetId: String; let threatIds: [String]; let reducesRiskBy: Int; var id: String }`.
  - `ArchitectureSource.mitigates: [SourceMitigates]`, with
    `mitigates: [SourceMitigates] = []`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/ArchitectureLanguageTests.swift`:

```swift
import Testing
import ThreatModelKit
import ArchitectureDSL

struct ArchitectureLanguageTests {
    private func read(_ text: String) -> ArchitectureRead {
        HclArchitectureSource().read(text)
    }

    @Test func aFlowWithNoBodyIsANetworkFlow() throws {
        let source = try #require(read("""
        system "S" {
          component "a" { technology = "t" }
          component "b" { technology = "t" }
          flow a -> b
        }
        """).source)
        #expect(source.flows.first?.kind == "network")
        #expect(source.flows.first?.description == nil)
    }

    @Test func aFlowStatesItsKindAndItsDescription() throws {
        let source = try #require(read("""
        system "S" {
          component "a" { technology = "t" }
          component "b" { technology = "t" }
          flow a -> b {
            kind        = "ipc"
            description = "XPC call"
          }
        }
        """).source)
        #expect(source.flows.first?.kind == "ipc")
        #expect(source.flows.first?.description == "XPC call")
    }

    @Test func aFlowKindOutsideTheVocabularyIsAnError() {
        let read = read("""
        system "S" {
          component "a" { technology = "t" }
          component "b" { technology = "t" }
          flow a -> b { kind = "carrier-pigeon" }
        }
        """)
        #expect(read.hasErrors)
        #expect(read.diagnostics.contains { $0.message.contains("kind is \"carrier-pigeon\"") })
    }

    @Test func aZoneStatesItsBoundary() throws {
        let source = try #require(read("""
        system "S" {
          zone "root" {
            boundary    = "privilege"
            description = "uid 0"
            component "a" { technology = "t" }
          }
        }
        """).source)
        #expect(source.zones.first?.boundary == "privilege")
        #expect(source.zones.first?.description == "uid 0")
    }

    @Test func aComponentStatesThePrivilegeItRunsAt() throws {
        let source = try #require(read("""
        system "S" {
          component "a" {
            technology = "t"
            runs_as    = "root"
          }
        }
        """).source)
        #expect(source.components.first?.runsAs == "root")
    }

    @Test func aComponentHoldsAssets() throws {
        let source = try #require(read("""
        system "S" {
          component "a" {
            technology = "t"
            asset "ssh-keys" { data = "restricted" }
            asset "notes" { }
          }
        }
        """).source)
        #expect(source.components.first?.assets.map(\.name) == ["ssh-keys", "notes"])
        #expect(source.components.first?.assets.map(\.data) == ["restricted", "internal"])
    }

    @Test func aMitigatesEdgeNamesItsThreatsAndItsReduction() throws {
        let source = try #require(read("""
        system "S" {
          component "guard" { technology = "t" }
          component "store" { technology = "t" }
          mitigates guard -> store {
            threats         = ["credential-theft"]
            reduces_risk_by = 80
          }
        }
        """).source)
        #expect(source.mitigates.first?.id == "guard->store")
        #expect(source.mitigates.first?.threatIds == ["credential-theft"])
        #expect(source.mitigates.first?.reducesRiskBy == 80)
    }

    @Test func aMitigatesEdgeWithNoThreatsIsAnError() {
        let read = read("""
        system "S" {
          component "guard" { technology = "t" }
          component "store" { technology = "t" }
          mitigates guard -> store { reduces_risk_by = 80 }
        }
        """)
        #expect(read.hasErrors)
        #expect(read.diagnostics.contains { $0.message.contains("names no threats") })
    }

    @Test func aMitigatesEdgeToAnUndeclaredComponentIsAnError() {
        let read = read("""
        system "S" {
          component "guard" { technology = "t" }
          mitigates guard -> store {
            threats         = ["credential-theft"]
            reduces_risk_by = 80
          }
        }
        """)
        #expect(read.hasErrors)
        #expect(read.diagnostics.contains { $0.message.contains("which this file does not declare") })
    }

    @Test func aRewriteOfWhatItReadProducesTheSameText() throws {
        let text = """
        system "S" {
          component "guard" {
            technology = "t"
            data       = "internal"
            runs_as    = "root"

            asset "ssh-keys" {
              data = "restricted"
            }
          }

          component "store" {
            technology = "t"
            data       = "internal"
          }

          flow guard -> store {
            kind        = "ipc"
            description = "XPC call"
          }

          mitigates guard -> store {
            threats         = ["credential-theft"]
            reduces_risk_by = 80
          }
        }

        """
        let source = try #require(read(text).source)
        #expect(HclArchitectureSource().write(source) == text)
    }
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd ThreatModelKit && swift test --filter ArchitectureLanguageTests`
Expected: FAIL, `value of type 'SourceFlow' has no member 'kind'`.

- [ ] **Step 3: Add the fields to `ArchitectureSource.swift`**

```swift
public struct SourceAsset: Equatable, Sendable {
    public let name: String
    public let data: String

    public init(name: String, data: String = "internal") {
        self.name = name
        self.data = data
    }
}

public struct SourceMitigates: Equatable, Sendable {
    public let sourceId: String
    public let targetId: String
    public let threatIds: [String]
    public let reducesRiskBy: Int

    public init(sourceId: String, targetId: String, threatIds: [String], reducesRiskBy: Int) {
        self.sourceId = sourceId
        self.targetId = targetId
        self.threatIds = threatIds
        self.reducesRiskBy = reducesRiskBy
    }

    /// The identifier, minted the way a flow's is.
    public var id: String { "\(sourceId)->\(targetId)" }
}
```

Add `kind: String` and `description: String?` to `SourceFlow`, `boundary: String`
and `description: String?` to `SourceZone`, `runsAs: String` and
`assets: [SourceAsset]` to `SourceComponent`, and
`mitigates: [SourceMitigates]` to `ArchitectureSource`. Every new parameter
takes the default named in **Interfaces**, so no existing caller breaks.

- [ ] **Step 4: Read the new syntax in `ArchitectureParser.swift`**

Add the two vocabularies beside `Self.networks`:

```swift
    private static let flowKinds: Set<String> = ["network", "ipc", "file", "syscall", "human"]
    private static let boundaries: Set<String> = ["network", "privilege"]
    private static let privilegeLevels: Set<String> = ["user", "admin", "root", "system", "kernel"]
```

Add the `mitigates` case to `parseSystem()`, and widen the message:

```swift
            case "mitigates":
                if let edge = parseMitigates() { mitigates.append(edge) }
            default:
                record("a system holds catalogue, technology, zone, component, flow and mitigates, not \"\(current.text)\"")
```

Declare `var mitigates: [SourceMitigates] = []` beside `var flows`, and pass
`mitigates: mitigates` to the `ArchitectureSource(...)` it returns.

Replace `parseFlow()`:

```swift
    private mutating func parseFlow() -> SourceFlow? {
        advance()
        guard let source = expect(.identifier, "the component the flow starts at") else { return nil }
        guard expect(.arrow, "->") != nil else { return nil }
        guard let target = expect(.identifier, "the component the flow ends at") else { return nil }
        guard current.kind == .leftBrace else {
            return SourceFlow(sourceId: source.text, targetId: target.text)
        }
        advance()

        var kind = "network"
        var description: String?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "kind":
                let token = current
                kind = parseTextAttribute() ?? kind
                expectVocabulary(kind, Self.flowKinds, field: "kind", at: token)
            case "description":
                description = parseTextAttribute()
            default:
                record("a flow holds kind and description, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        return SourceFlow(
            sourceId: source.text,
            targetId: target.text,
            kind: kind,
            description: description
        )
    }
```

Add `parseMitigates()` beside it:

```swift
    private mutating func parseMitigates() -> SourceMitigates? {
        advance()
        guard let source = expect(.identifier, "the component the mitigation comes from") else { return nil }
        guard expect(.arrow, "->") != nil else { return nil }
        guard let target = expect(.identifier, "the component the mitigation protects") else { return nil }
        let name = "\(source.text)->\(target.text)"
        guard expect(.leftBrace, "{") != nil else { return nil }

        var threatIds: [String] = []
        var reducesRiskBy: Int?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "threats":
                threatIds = parseListAttribute()
            case "reduces_risk_by":
                let token = current
                reducesRiskBy = parseNumberAttribute()
                if let percent = reducesRiskBy, percent < 0 || percent > 100 {
                    record("reduces_risk_by is \(percent); it runs from 0 to 100", at: token)
                }
            default:
                record("a mitigates edge holds threats and reduces_risk_by, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard threatIds.isEmpty == false else {
            record("the mitigates edge \"\(name)\" names no threats", at: source)
            return nil
        }
        guard let reducesRiskBy else {
            record("the mitigates edge \"\(name)\" has no reduces_risk_by", at: source)
            return nil
        }
        return SourceMitigates(
            sourceId: source.text,
            targetId: target.text,
            threatIds: threatIds,
            reducesRiskBy: reducesRiskBy
        )
    }
```

Add `boundary` and `description` to `parseZone()`, beside `network`:

```swift
            case "boundary":
                let token = current
                boundary = parseTextAttribute() ?? boundary
                expectVocabulary(boundary, Self.boundaries, field: "boundary", at: token)
            case "description":
                description = parseTextAttribute()
```

with `var boundary = "network"` and `var description: String?` declared above
the loop, both passed to `SourceZone(...)`, and the `default` message widened
to name `boundary` and `description`.

Add `runs_as` and `asset` to `parseComponent()`:

```swift
            case "runs_as":
                let token = current
                runsAs = parseTextAttribute() ?? runsAs
                expectVocabulary(runsAs, Self.privilegeLevels, field: "runs_as", at: token)
            case "asset":
                if let asset = parseAsset() { assets.append(asset) }
```

with `var runsAs = "user"` and `var assets: [SourceAsset] = []` above the loop,
both passed to `SourceComponent(...)`, the `default` message widened, and:

```swift
    private mutating func parseAsset() -> SourceAsset? {
        advance()
        guard let name = expect(.string, "the asset's name") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var data = "internal"
        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "data":
                let token = current
                data = parseTextAttribute() ?? data
                expectVocabulary(data, Self.sensitivities, field: "data", at: token)
            default:
                record("an asset holds data, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")
        return SourceAsset(name: name.text, data: data)
    }
```

Add the checks to `check(_:)`, after the flow checks:

```swift
        var edges: Set<String> = []
        for edge in source.mitigates {
            if componentIds.contains(edge.sourceId) == false {
                record("the mitigates edge starts at \"\(edge.sourceId)\", which this file does not declare", at: tokens[0])
            }
            if componentIds.contains(edge.targetId) == false {
                record("the mitigates edge ends at \"\(edge.targetId)\", which this file does not declare", at: tokens[0])
            }
            if edge.sourceId == edge.targetId {
                record("the mitigates edge \"\(edge.id)\" starts and ends at the same component", at: tokens[0])
            }
            if edges.insert(edge.id).inserted == false {
                record("the mitigates edge \"\(edge.id)\" is declared twice", at: tokens[0])
            }
        }
```

- [ ] **Step 5: Write the new syntax in `ArchitectureWriter.swift`**

In `componentBlock(_:)`, after the `data` attribute:

```swift
        if component.runsAs != "user" { attributes.append(("runs_as", quoted(component.runsAs))) }
        if component.raisesThreats == false { attributes.append(("threats", "false")) }
        lines += indent(aligned(attributes))
        for asset in component.assets {
            lines.append("")
            lines.append("  asset \(quoted(asset.name)) {")
            lines.append("    data = \(quoted(asset.data))")
            lines.append("  }")
        }
```

In the zone loop, after `network`:

```swift
            if zone.boundary != "network" { attributes.append(("boundary", quoted(zone.boundary))) }
            if let description = zone.description {
                attributes.append(("description", quoted(description)))
            }
```

Replace the flow loop, and add the edges after it:

```swift
        for flow in source.flows {
            if flow.kind == "network" && flow.description == nil {
                body.append("flow \(flow.sourceId) -> \(flow.targetId)")
                continue
            }
            body.append("flow \(flow.sourceId) -> \(flow.targetId) {")
            var attributes: [(String, String)] = [("kind", quoted(flow.kind))]
            if let description = flow.description {
                attributes.append(("description", quoted(description)))
            }
            body += indent(aligned(attributes))
            body.append("}")
            body.append("")
        }
        if source.flows.isEmpty == false { body.append("") }

        for edge in source.mitigates {
            body.append("mitigates \(edge.sourceId) -> \(edge.targetId) {")
            body += indent(
                aligned([
                    ("threats", "[" + edge.threatIds.map(quoted).joined(separator: ", ") + "]"),
                    ("reduces_risk_by", String(edge.reducesRiskBy))
                ])
            )
            body.append("}")
            body.append("")
        }
```

- [ ] **Step 6: Carry the values through the import and the builder**

In `ImportArchitecture.execute`, put the new values on the model:

```swift
                Component(
                    id: ComponentId(component.id),
                    technologyId: TechnologyId(component.technologyId),
                    position: positions[component.id] ?? Point(x: 0, y: 0),
                    sensitivity: DataSensitivity(rawValue: component.data) ?? .internalData,
                    customName: component.name,
                    threatsDisabled: component.raisesThreats == false,
                    runsAs: PrivilegeLevel(rawValue: component.runsAs) ?? .default,
                    assets: component.assets.map {
                        Asset(name: $0.name, sensitivity: DataSensitivity(rawValue: $0.data) ?? .internalData)
                    }
                )
```

the zone's `boundary: ZoneBoundary(rawValue: zone.boundary) ?? .default` and
`description: zone.description`, the connection's
`kind: FlowKind(rawValue: flow.kind) ?? .default` and
`description: flow.description`, and after the flow loop:

```swift
        model.mitigatesEdges = source.mitigates.map { edge in
            MitigatesEdge(
                source: ComponentId(edge.sourceId),
                target: ComponentId(edge.targetId),
                threatIds: edge.threatIds.map(ThreatId.init),
                reducesRiskBy: edge.reducesRiskBy
            )
        }
```

In `ArchitectureSourceBuilder.source(from:)`, write the same values back:
`runsAs: component.runsAs.rawValue`,
`assets: component.assets.map { SourceAsset(name: $0.name, data: $0.sensitivity.rawValue) }`,
`boundary: zone.boundary.rawValue`, `description: zone.description`,
`kind: $0.kind.rawValue`, `description: $0.description`, and

```swift
                mitigates: model.mitigatesEdges.map { edge in
                    SourceMitigates(
                        sourceId: edge.source.value,
                        targetId: edge.target.value,
                        threatIds: edge.threatIds.map(\.value),
                        reducesRiskBy: edge.reducesRiskBy
                    )
                }
```

- [ ] **Step 7: Run the suite**

Run: `cd ThreatModelKit && swift test`
Expected: PASS, including the round-trip tests already in
`ArchitectureSourceGatewayContract`.

- [ ] **Step 8: Commit**

```bash
git add ThreatModelKit/Sources/ArchitectureDSL/ArchitectureParser.swift \
        ThreatModelKit/Sources/ArchitectureDSL/ArchitectureWriter.swift \
        ThreatModelKit/Sources/ThreatModelKit/architecture \
        ThreatModelKit/Tests/UnitTests/ArchitectureLanguageTests.swift
git -c commit.gpgsign=false commit -m "feat: the architecture language reads flow kinds, boundaries, privileges, assets and mitigates edges"
```

---

### Task 6: the library language defines kinds, pathways and mitigations

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/LibrarySource.swift`
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/LibraryParser.swift`
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/LibraryWriter.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/Library.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/MergedCatalogue.swift`
- Test: `ThreatModelKit/Tests/UnitTests/LibraryVocabularyTests.swift`

**Interfaces:**
- Consumes: `FlowKind`, `PrivilegeLevel`, `ZoneBoundary`, `Threat.appliesToFlowKinds`,
  `Threat.boundary`, `Threat.appliesToPrivilegeLevels` — all from Task 4.
- Produces:
  - `SourceLibraryThreat.appliesTo: [String]`, `.boundary: String?`,
    `.runsAs: [String]`, `.isPathwayThreat: Bool`, all defaulted to empty,
    `nil`, empty and `false`.
  - `struct SourceLibraryMitigation { let id: String; let name: String; let description: String; let mitigatesThreatIds: [String]; let technologyIds: [String]; let reducesRiskBy: Int }`.
  - `LibrarySource.mitigations: [SourceLibraryMitigation]`, defaulted to empty.
  - `Library.pathwayMitigations: [PathwayMitigationDefinition]`, defaulted to
    empty.
  - Three `LibraryBuildFault` cases: `unknownFlowKind(threatId:value:)`,
    `unknownBoundary(threatId:value:)`, `unknownPrivilegeLevel(threatId:value:)`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/LibraryVocabularyTests.swift`:

```swift
import Testing
import ThreatModelKit
import ArchitectureDSL
import TestSupport

struct LibraryVocabularyTests {
    private func read(_ text: String) -> LibraryRead {
        HclLibrarySource().read(text)
    }

    private let taxonomy = CatalogueFixture.taxonomy()

    @Test func aThreatStatesTheFlowKindsItAppliesTo() throws {
        let source = try #require(read("""
        library "endpoint" {
          threat "dylib-injection" {
            name       = "Dynamic library injection"
            severity   = "high"
            connection = true
            applies_to = ["file", "ipc"]
          }
        }
        """).source)
        #expect(source.threats.first?.appliesTo == ["file", "ipc"])
    }

    @Test func aZoneThreatStatesItsBoundary() throws {
        let source = try #require(read("""
        library "endpoint" {
          threat "privilege-escalation" {
            name     = "Privilege escalation"
            severity = "critical"
            zone     = true
            boundary = "privilege"
          }
        }
        """).source)
        #expect(source.threats.first?.boundary == "privilege")
    }

    @Test func aThreatStatesThePrivilegeLevelsAndThatItIsAPathway() throws {
        let source = try #require(read("""
        library "endpoint" {
          threat "raw-device-read" {
            name     = "Raw device read"
            severity = "critical"
            runs_as  = ["root", "kernel"]
            pathway  = true
          }
        }
        """).source)
        #expect(source.threats.first?.runsAs == ["root", "kernel"])
        #expect(source.threats.first?.isPathwayThreat == true)
    }

    @Test func aLibraryDefinesAPathwayMitigation() throws {
        let source = try #require(read("""
        library "endpoint" {
          mitigation "es-client" {
            name            = "Endpoint Security client"
            description     = "Denies unsigned code"
            mitigates       = ["dylib-injection"]
            provided_by     = ["es"]
            reduces_risk_by = 60
          }
        }
        """).source)
        let mitigation = try #require(source.mitigations.first)
        #expect(mitigation.id == "es-client")
        #expect(mitigation.mitigatesThreatIds == ["dylib-injection"])
        #expect(mitigation.technologyIds == ["es"])
        #expect(mitigation.reducesRiskBy == 60)
    }

    @Test func theBuildPrefixesTheMitigationAndItsTechnologies() throws {
        let source = try #require(read("""
        library "endpoint" {
          technology "es" {
            name     = "Endpoint Security client"
            category = "compute"
          }

          threat "dylib-injection" {
            name       = "Dynamic library injection"
            severity   = "high"
            connection = true
            applies_to = ["file"]
          }

          mitigation "es-client" {
            name            = "Endpoint Security client"
            mitigates       = ["dylib-injection"]
            provided_by     = ["es"]
            reduces_risk_by = 60
          }
        }
        """).source)
        let built = Library.build(from: source, taxonomy: taxonomy)
        let library = try #require(built.library)
        #expect(built.faults.isEmpty)
        #expect(library.threats.first?.appliesToFlowKinds == [.file])
        let mitigation = try #require(library.pathwayMitigations.first)
        #expect(mitigation.id == PathwayMitigationId("endpoint-es-client"))
        #expect(mitigation.mitigatesThreatIds == [ThreatId("endpoint-dylib-injection")])
        #expect(mitigation.technologyIds == [TechnologyId("endpoint-es")])
    }

    @Test func aFlowKindTheApplicationDoesNotHoldIsAFault() throws {
        let source = try #require(read("""
        library "endpoint" {
          threat "t" {
            name       = "T"
            severity   = "high"
            applies_to = ["carrier-pigeon"]
          }
        }
        """).source)
        let built = Library.build(from: source, taxonomy: taxonomy)
        #expect(built.library == nil)
        #expect(built.faults.contains { $0.message.contains("carrier-pigeon") })
    }

    @Test func theMergedCatalogueOffersTheLibrarysMitigations() throws {
        let source = try #require(read("""
        library "endpoint" {
          mitigation "es-client" {
            name            = "Endpoint Security client"
            mitigates       = ["dylib-injection"]
            provided_by     = ["es"]
            reduces_risk_by = 60
          }
        }
        """).source)
        let library = try #require(Library.build(from: source, taxonomy: taxonomy).library)
        let merged = MergedCatalogue(base: CatalogueFixture.catalogue(), store: LibraryStore([library]))
        #expect(merged.pathwayMitigations().count == CatalogueFixture.pathwayMitigations().count + 1)
    }
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd ThreatModelKit && swift test --filter LibraryVocabularyTests`
Expected: FAIL, `value of type 'SourceLibraryThreat' has no member 'appliesTo'`.

- [ ] **Step 3: Add the fields to `LibrarySource.swift`**

Add to `SourceLibraryThreat` the four properties named in **Interfaces**, each
with its default, and add:

```swift
/// A pathway mitigation a library defines.
public struct SourceLibraryMitigation: Equatable, Sendable {
    public let id: String
    public let name: String
    public let description: String
    public let mitigatesThreatIds: [String]
    public let technologyIds: [String]
    public let reducesRiskBy: Int

    public init(
        id: String,
        name: String,
        description: String = "",
        mitigatesThreatIds: [String] = [],
        technologyIds: [String] = [],
        reducesRiskBy: Int = 0
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.mitigatesThreatIds = mitigatesThreatIds
        self.technologyIds = technologyIds
        self.reducesRiskBy = reducesRiskBy
    }
}
```

with `mitigations: [SourceLibraryMitigation] = []` on `LibrarySource`.

- [ ] **Step 4: Read the new attributes in `LibraryParser.swift`**

In `parseThreat()`, add the four cases and widen the `default` message:

```swift
            case "applies_to": appliesTo = parseListAttribute()
            case "boundary": boundary = parseTextAttribute()
            case "runs_as": runsAs = parseListAttribute()
            case "pathway": isPathwayThreat = parseBooleanAttribute() ?? false
```

Declare the four variables above the loop and pass them to
`SourceLibraryThreat(...)`.

Add the `mitigation` case to the library block loop, beside `technology` and
`threat`, with `var mitigations: [SourceLibraryMitigation] = []`, and:

```swift
    private mutating func parseMitigation() -> SourceLibraryMitigation? {
        advance()
        guard let id = expect(.string, "the mitigation's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var name: String?
        var description = ""
        var mitigates: [String] = []
        var providedBy: [String] = []
        var reducesRiskBy: Int?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "name": name = parseTextAttribute()
            case "description": description = parseTextAttribute() ?? ""
            case "mitigates": mitigates = parseListAttribute()
            case "provided_by": providedBy = parseListAttribute()
            case "reduces_risk_by":
                let token = current
                reducesRiskBy = parseNumberAttribute()
                if let percent = reducesRiskBy, percent < 0 || percent > 100 {
                    record("reduces_risk_by is \(percent); it runs from 0 to 100", at: token)
                }
            default:
                record(
                    "a mitigation holds name, description, mitigates, provided_by and "
                        + "reduces_risk_by, not \"\(current.text)\""
                )
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard let name else {
            record("the mitigation \"\(id.text)\" has no name", at: id)
            return nil
        }
        guard mitigates.isEmpty == false else {
            record("the mitigation \"\(id.text)\" names no threats", at: id)
            return nil
        }
        guard providedBy.isEmpty == false else {
            record("the mitigation \"\(id.text)\" names no technologies", at: id)
            return nil
        }
        return SourceLibraryMitigation(
            id: id.text,
            name: name,
            description: description,
            mitigatesThreatIds: mitigates,
            technologyIds: providedBy,
            reducesRiskBy: reducesRiskBy ?? 0
        )
    }
```

- [ ] **Step 5: Write the new attributes in `LibraryWriter.swift`**

In `threatBlock(_:)`, after the `zone` attribute:

```swift
        if threat.isPathwayThreat { attributes.append(("pathway", "true")) }
        if threat.appliesTo.isEmpty == false {
            attributes.append(
                ("applies_to", "[" + threat.appliesTo.map(quoted).joined(separator: ", ") + "]")
            )
        }
        if let boundary = threat.boundary { attributes.append(("boundary", quoted(boundary))) }
        if threat.runsAs.isEmpty == false {
            attributes.append(
                ("runs_as", "[" + threat.runsAs.map(quoted).joined(separator: ", ") + "]")
            )
        }
```

and after the threat loop in `write(_:)`:

```swift
        for mitigation in source.mitigations {
            body.append("mitigation \(quoted(mitigation.id)) {")
            var attributes: [(String, String)] = [("name", quoted(mitigation.name))]
            if mitigation.description.isEmpty == false {
                attributes.append(("description", quoted(mitigation.description)))
            }
            attributes.append(
                ("mitigates", "[" + mitigation.mitigatesThreatIds.map(quoted).joined(separator: ", ") + "]")
            )
            attributes.append(
                ("provided_by", "[" + mitigation.technologyIds.map(quoted).joined(separator: ", ") + "]")
            )
            attributes.append(("reduces_risk_by", String(mitigation.reducesRiskBy)))
            body += indent(aligned(attributes))
            body.append("}")
            body.append("")
        }
```

- [ ] **Step 6: Build the values in `Library.swift`**

Add the three fault cases and their messages, then in `build(from:taxonomy:)`
map each threat's new fields, recording a fault for a value the application
does not hold:

```swift
            let flowKinds = threat.appliesTo.compactMap { raw -> FlowKind? in
                guard let kind = FlowKind(rawValue: raw) else {
                    faults.append(.unknownFlowKind(threatId: threat.id, value: raw))
                    return nil
                }
                return kind
            }
            let levels = threat.runsAs.compactMap { raw -> PrivilegeLevel? in
                guard let level = PrivilegeLevel(rawValue: raw) else {
                    faults.append(.unknownPrivilegeLevel(threatId: threat.id, value: raw))
                    return nil
                }
                return level
            }
            var boundary: ZoneBoundary?
            if let raw = threat.boundary {
                boundary = ZoneBoundary(rawValue: raw)
                if boundary == nil {
                    faults.append(.unknownBoundary(threatId: threat.id, value: raw))
                }
            }
```

and pass `appliesToFlowKinds: flowKinds`, `boundary: boundary`,
`appliesToPrivilegeLevels: levels` and
`isPathwayThreat: threat.isPathwayThreat` to `Threat(...)`.

Build the mitigations, prefixing every id the library declares:

```swift
        let mitigations = source.mitigations.map { mitigation in
            PathwayMitigationDefinition(
                id: PathwayMitigationId(prefixed(mitigation.id)),
                label: mitigation.name,
                description: mitigation.description,
                mitigatesThreatIds: mitigation.mitigatesThreatIds.map {
                    ThreatId(declared.contains($0) ? prefixed($0) : $0)
                },
                technologyIds: mitigation.technologyIds.map {
                    TechnologyId(declaredTechnologies.contains($0) ? prefixed($0) : $0)
                }
            )
        }
```

with `let declaredTechnologies = Set(source.technologies.map(\.id))` beside
`declared`, and `pathwayMitigations: mitigations` on the returned `Library`.

WARNING: `PathwayMitigationDefinition` holds no percentage. The percentage a
library states is the default the user's settings start from; carry it by
adding `reducesRiskBy` to the definition and defaulting it to the application's
own default where the settings hold nothing.

- [ ] **Step 7: Offer them from the merged catalogue**

In `MergedCatalogue.swift`, replace `pathwayMitigations()`:

```swift
    /// The vendored mitigations and every mitigation the libraries define.
    public func pathwayMitigations() -> [PathwayMitigationDefinition] {
        base.pathwayMitigations() + store.all().flatMap(\.pathwayMitigations)
    }
```

and delete the comment above it that says a library defines none.

- [ ] **Step 8: Run the suite**

Run: `cd ThreatModelKit && swift test`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add ThreatModelKit/Sources/ArchitectureDSL/LibraryParser.swift \
        ThreatModelKit/Sources/ArchitectureDSL/LibraryWriter.swift \
        ThreatModelKit/Sources/ThreatModelKit/architecture/domain/LibrarySource.swift \
        ThreatModelKit/Sources/ThreatModelKit/catalogue \
        ThreatModelKit/Tests/UnitTests/LibraryVocabularyTests.swift
git -c commit.gpgsign=false commit -m "feat: a library defines flow kinds, boundaries, pathway threats and pathway mitigations"
```

---

### Task 7: the controls language carries a recommendation, and the reference states every new word

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ControlsSource.swift`
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/ControlsParser.swift`
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/ControlsWriter.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/CompileControls.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/ApplyControlAnswers.swift`
- Modify: `docs/LANGUAGE.md`
- Test: `ThreatModelKit/Tests/UnitTests/RecommendationLanguageTests.swift`

**Interfaces:**
- Consumes: `Recommendation` and `ThreatModel.recommendations` from Task 4.
- Produces:
  - `struct SourceRecommendation { let text: String; let note: String? }`.
  - `SourceThreatAnswer.recommendations: [SourceRecommendation]`, defaulted to
    empty.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/RecommendationLanguageTests.swift`:

```swift
import Testing
import ThreatModelKit
import ArchitectureDSL
import TestSupport

struct RecommendationLanguageTests {
    private func read(_ text: String) -> ControlsRead {
        HclControlsSource().read(text)
    }

    @Test func aThreatCarriesARecommendation() throws {
        let source = try #require(read("""
        controls for "S" {
          threat "credential-theft" on component "c1" {
            recommendation "Protect the managed preferences plist" {
              note = "Deny write from anything but the MDM daemon."
            }
          }
        }
        """).source)
        let answer = try #require(source.answers.first)
        #expect(answer.recommendations.first?.text == "Protect the managed preferences plist")
        #expect(answer.recommendations.first?.note == "Deny write from anything but the MDM daemon.")
    }

    @Test func aRecommendationNeedsNoNote() throws {
        let source = try #require(read("""
        controls for "S" {
          threat "credential-theft" on component "c1" {
            recommendation "Deny reads of /dev/rdisk**" { }
          }
        }
        """).source)
        #expect(source.answers.first?.recommendations.first?.note == nil)
    }

    @Test func aRecommendationIsNotAnAnswer() throws {
        let source = try #require(read("""
        controls for "S" {
          threat "credential-theft" on component "c1" {
            recommendation "Deny reads of /dev/rdisk**" { }
          }
        }
        """).source)
        #expect(source.answers.first?.isAnswered == false)
    }

    @Test func aRewriteKeepsTheRecommendation() throws {
        let text = """
        controls for "S" {
          threat "credential-theft" on component "c1" {
            recommendation "Deny reads of /dev/rdisk**" {
              note = "An endpoint rule, not a control the catalogue offers."
            }
          }
        }

        """
        let source = try #require(read(text).source)
        #expect(HclControlsSource().write(source) == text)
    }

    @Test func theCompileKeepsARecommendationWholeAcrossARewrite() throws {
        let architecture = """
        system "S" {
          component "c1" { technology = "aws-ec2" data = "confidential" }
        }
        """
        let controls = """
        controls for "S" {
          threat "credential-theft" on component "c1" {
            recommendation "Deny reads of /dev/rdisk**" { }
          }
        }
        """
        let response = CompileControls(
            catalogue: CatalogueFixture.catalogue(),
            architectureSources: HclArchitectureSource(),
            controlsSources: HclControlsSource(),
            layout: LayOutModel()
        ).execute(CompileControlsRequest(architectureText: architecture, controlsText: controls))

        guard case .compiled(let text, _, _, _) = response else {
            Issue.record("the compile refused the file")
            return
        }
        #expect(text.contains("recommendation \"Deny reads of /dev/rdisk**\""))
    }
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd ThreatModelKit && swift test --filter RecommendationLanguageTests`
Expected: FAIL, `value of type 'SourceThreatAnswer' has no member 'recommendations'`.

- [ ] **Step 3: Add the value to `ControlsSource.swift`**

```swift
/// What a person says should be done about a threat.
///
/// It answers nothing. `isAnswered` ignores it, so `threatmodeller check`
/// still exits 1 for a threat that holds a recommendation and no answer.
public struct SourceRecommendation: Equatable, Sendable {
    public let text: String
    public let note: String?

    public init(text: String, note: String? = nil) {
        self.text = text
        self.note = note
    }
}
```

Add `public let recommendations: [SourceRecommendation]` to
`SourceThreatAnswer`, with the initialiser parameter
`recommendations: [SourceRecommendation] = []` placed before `isStale`. Leave
`isAnswered` as it is.

- [ ] **Step 4: Read the block in `ControlsParser.swift`**

In `parseThreat(isStale:)`, add the case and widen the `default` message:

```swift
            case "recommendation":
                if let recommendation = parseRecommendation() { recommendations.append(recommendation) }
```

with `var recommendations: [SourceRecommendation] = []` above the loop and
`recommendations: recommendations` passed to `SourceThreatAnswer(...)`, and:

```swift
    private mutating func parseRecommendation() -> SourceRecommendation? {
        advance()
        guard let text = expect(.string, "what the recommendation says") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var note: String?
        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "note": note = parseTextAttribute()
            default:
                record("a recommendation holds note, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")
        return SourceRecommendation(text: text.text, note: note)
    }
```

- [ ] **Step 5: Write the block in `ControlsWriter.swift`**

In `threatBlock(_:)`, after the compensating loop:

```swift
        for recommendation in answer.recommendations {
            if body.isEmpty == false { body.append("") }
            body.append("recommendation \(quoted(recommendation.text)) {")
            if let note = recommendation.note, note.isEmpty == false {
                body += indent(aligned([("note", quoted(note))]))
            }
            body.append("}")
        }
```

- [ ] **Step 6: Keep it across a compile, and put it on the model**

In `CompileControls.execute`, add `recommendations: previous?.recommendations ?? []`
to the live `SourceThreatAnswer(...)`, and the same to the stale one it builds
from `previous`.

In `ApplyControlAnswers.execute`, collect them beside the compensating
controls:

```swift
        var recommendations: [ThreatKey: [Recommendation]] = [:]
```

then inside the answer loop:

```swift
            if answer.recommendations.isEmpty == false {
                recommendations[answer.key] = answer.recommendations.map {
                    Recommendation(text: $0.text, note: $0.note)
                }
            }
```

and write `model.recommendations = recommendations` where the use case already
writes `compensatingControls`.

- [ ] **Step 7: State every new word in `docs/LANGUAGE.md`**

Make these edits. Quote the identifiers exactly.

1. Section 2.6, the architecture keyword list: add `mitigates`, `boundary`,
   `runs_as`, `asset`, `threats`, `reduces_risk_by`. Add `recommendation` to
   the controls keyword list.
2. Section 4.1, the grammar: replace `FlowStatement` and add the new blocks.

```
SystemEntry  = CatalogueAttr
             | TechnologyBlock
             | ZoneBlock
             | ComponentBlock
             | FlowStatement
             | MitigatesBlock ;

ZoneEntry = "kind"            "=" String
          | "network"         "=" String
          | "boundary"        "=" String
          | "name"            "=" String
          | "description"     "=" String
          | "reduces_risk"    "=" Boolean
          | "reduces_risk_by" "=" Number
          | ComponentBlock ;

ComponentBlock = "component" String "{" { ComponentEntry } "}" ;
ComponentEntry = "technology" "=" String
               | "name"       "=" String
               | "data"       "=" String
               | "runs_as"    "=" String
               | "threats"    "=" Boolean
               | AssetBlock ;

AssetBlock = "asset" String "{" [ "data" "=" String ] "}" ;

FlowStatement = "flow" Identifier "->" Identifier [ "{" { FlowEntry } "}" ] ;
FlowEntry     = "kind"        "=" String
              | "description" "=" String ;

MitigatesBlock = "mitigates" Identifier "->" Identifier "{" { MitigatesEntry } "}" ;
MitigatesEntry = "threats"         "=" StringList
               | "reduces_risk_by" "=" Number ;
```

3. Section 4.4: add the `boundary` and `description` rows to the zone table.
   State that a `privilege` zone raises the privilege threat set and a
   `network` zone raises the network threat set, and that neither raises the
   other's.
4. Section 4.5: add the `runs_as` row and an `asset` subsection. State that a
   component scores at the highest sensitivity among its own `data` and every
   asset it holds, and that an asset never lowers what the component states.
5. Section 4.6: state that a flow may take a body, that `kind` runs over
   `network`, `ipc`, `file`, `syscall` and `human`, that a flow with no body is
   a network flow, and that a flow whose two ends run at different `runs_as`
   levels raises the privilege threat set as well.
6. A new section 4.7, `mitigates`, before the identity section. State the
   syntax, the two required attributes, the two errors, and that two edges on
   one threat give the stronger reduction, not the sum. Renumber the sections
   after it.
7. Section 5.3: add a `recommendation` subsection. State that it takes a label
   and an optional `note`, that a threat may hold more than one, that a
   compile keeps it whole, and that it answers nothing.
8. Section 6.3: add the `applies_to`, `boundary`, `runs_as` and `pathway` rows
   to the threat table, add the `mitigation` block and its five attributes, and
   **delete** the sentence "A library cannot define a pathway mitigation, and
   cannot mark a threat as a pathway threat."
9. Section 10, the grammar in full: repeat every rule changed above.

- [ ] **Step 8: Run the suite**

Run: `cd ThreatModelKit && swift test`
Expected: PASS.

- [ ] **Step 9: Check the reference states no removed rule**

Run: `grep -n "cannot define a pathway" docs/LANGUAGE.md`
Expected: no output.

- [ ] **Step 10: Commit**

```bash
git add ThreatModelKit/Sources/ArchitectureDSL/ControlsParser.swift \
        ThreatModelKit/Sources/ArchitectureDSL/ControlsWriter.swift \
        ThreatModelKit/Sources/ThreatModelKit/architecture \
        ThreatModelKit/Tests/UnitTests/RecommendationLanguageTests.swift \
        docs/LANGUAGE.md
git -c commit.gpgsign=false commit -m "feat: a threat carries a recommendation, and the reference states every new word"
```

---

## Wave 3: the behaviour behind the vocabularies

### Task 8: a threat is raised only where it applies

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ThreatApplicability.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ThreatApplicabilityTests.swift`

**Interfaces:**
- Consumes: `Threat.appliesToFlowKinds`, `Threat.boundary`,
  `Threat.appliesToPrivilegeLevels`, `FlowKind`, `ZoneBoundary`,
  `PrivilegeLevel` — all from Task 4. The three call sites in `ThreatResolver`
  already exist; **do not change `ThreatResolver.swift` in this task.**
- Produces: the three functions keep the signatures Task 4 minted.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/ThreatApplicabilityTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct ThreatApplicabilityTests {
    private func threat(
        appliesTo: [FlowKind] = [],
        boundary: ZoneBoundary? = nil,
        runsAs: [PrivilegeLevel] = []
    ) -> Threat {
        Threat(
            id: ThreatId("t"),
            name: "T",
            description: "",
            severity: CatalogueFixture.high,
            isConnectionThreat: true,
            appliesToFlowKinds: appliesTo,
            boundary: boundary,
            appliesToPrivilegeLevels: runsAs
        )
    }

    @Test func aThreatThatNamesNoKindIsANetworkThreat() {
        let untagged = threat()
        #expect(ThreatApplicability.appliesToConnection(threat: untagged, kind: .network, crossesPrivilege: false))
        #expect(ThreatApplicability.appliesToConnection(threat: untagged, kind: .ipc, crossesPrivilege: false) == false)
        #expect(ThreatApplicability.appliesToConnection(threat: untagged, kind: .file, crossesPrivilege: false) == false)
    }

    @Test func aThreatIsRaisedOnTheKindsItNames() {
        let tagged = threat(appliesTo: [.file, .ipc])
        #expect(ThreatApplicability.appliesToConnection(threat: tagged, kind: .ipc, crossesPrivilege: false))
        #expect(ThreatApplicability.appliesToConnection(threat: tagged, kind: .network, crossesPrivilege: false) == false)
    }

    @Test func aPrivilegeThreatIsRaisedOnlyWhereTheFlowCrossesALevel() {
        let crossing = threat(boundary: .privilege)
        #expect(ThreatApplicability.appliesToConnection(threat: crossing, kind: .syscall, crossesPrivilege: true))
        #expect(ThreatApplicability.appliesToConnection(threat: crossing, kind: .syscall, crossesPrivilege: false) == false)
    }

    @Test func aZoneRaisesOnlyTheThreatsOfItsOwnBoundary() {
        #expect(ThreatApplicability.appliesToZone(threat: threat(), boundary: .network))
        #expect(ThreatApplicability.appliesToZone(threat: threat(), boundary: .privilege) == false)
        #expect(ThreatApplicability.appliesToZone(threat: threat(boundary: .privilege), boundary: .privilege))
        #expect(ThreatApplicability.appliesToZone(threat: threat(boundary: .privilege), boundary: .network) == false)
    }

    @Test func aComponentThreatThatNamesNoLevelIsRaisedAtEveryLevel() {
        #expect(ThreatApplicability.appliesToComponent(threat: threat(), runsAs: .user))
        #expect(ThreatApplicability.appliesToComponent(threat: threat(), runsAs: .kernel))
    }

    @Test func aComponentThreatIsRaisedOnlyAtTheLevelsItNames() {
        let rootOnly = threat(runsAs: [.root, .kernel])
        #expect(ThreatApplicability.appliesToComponent(threat: rootOnly, runsAs: .root))
        #expect(ThreatApplicability.appliesToComponent(threat: rootOnly, runsAs: .user) == false)
    }
}

struct ThreatApplicabilityInTheResolverTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func component(_ id: String) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: .confidential
        )
    }

    @Test func aLocalFlowRaisesNoNetworkThreat() {
        let model = ThreatModel(
            components: [component("a"), component("b")],
            connections: [
                Connection(
                    id: ConnectionId("a->b"),
                    source: ComponentId("a"),
                    target: ComponentId("b"),
                    kind: .ipc
                )
            ]
        )
        let resolved = ThreatResolver(model: model, catalogue: catalogue).resolve()
        #expect(resolved.contains { $0.threat.id == ThreatId("connection-mitm") } == false)
        #expect(resolved.contains { $0.threat.id == ThreatId("connection-dos") } == false)
    }

    @Test func aNetworkFlowStillRaisesTheNetworkThreats() {
        let model = ThreatModel(
            components: [component("a"), component("b")],
            connections: [
                Connection(id: ConnectionId("a->b"), source: ComponentId("a"), target: ComponentId("b"))
            ]
        )
        let resolved = ThreatResolver(model: model, catalogue: catalogue).resolve()
        #expect(resolved.contains { $0.threat.id == ThreatId("connection-mitm") })
    }
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd ThreatModelKit && swift test --filter ThreatApplicability`
Expected: FAIL. The stubs return `true`, so
`aThreatThatNamesNoKindIsANetworkThreat` and `aLocalFlowRaisesNoNetworkThreat`
report an unexpected `true`.

- [ ] **Step 3: Write the three rules**

Replace the body of `ThreatApplicability.swift`:

```swift
/// Whether a threat is raised at all.
///
/// Spec sections 4.3, 5.1 and 5.2. The rules keep the vendored catalogue
/// correct without editing it: a threat that states no kind and no boundary
/// means what it meant before this application knew about kinds.
public enum ThreatApplicability {
    /// A component threat that names no level is raised at every level.
    public static func appliesToComponent(threat: Threat, runsAs: PrivilegeLevel) -> Bool {
        threat.appliesToPrivilegeLevels.isEmpty
            || threat.appliesToPrivilegeLevels.contains(runsAs)
    }

    /// A privilege threat is raised only where the flow crosses a level, and
    /// its kinds do not matter. Every other threat is raised on the kinds it
    /// names, and a threat that names none is a network threat.
    public static func appliesToConnection(
        threat: Threat,
        kind: FlowKind,
        crossesPrivilege: Bool
    ) -> Bool {
        if threat.boundary == .privilege { return crossesPrivilege }
        if threat.appliesToFlowKinds.isEmpty { return kind == .network }
        return threat.appliesToFlowKinds.contains(kind)
    }

    /// A zone raises the threats of its own boundary and no others. A threat
    /// that states no boundary is a network threat.
    public static func appliesToZone(threat: Threat, boundary: ZoneBoundary) -> Bool {
        (threat.boundary ?? .network) == boundary
    }
}
```

- [ ] **Step 4: Run it and see it pass**

Run: `cd ThreatModelKit && swift test --filter ThreatApplicability`
Expected: PASS.

- [ ] **Step 5: Run the whole suite**

Run: `cd ThreatModelKit && swift test`
Expected: PASS. A test that draws a flow and expects a connection threat still
passes, because a flow with no stated kind is a network flow.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ThreatApplicability.swift \
        ThreatModelKit/Tests/UnitTests/ThreatApplicabilityTests.swift
git -c commit.gpgsign=false commit -m "feat: a threat is raised only on the kinds, boundaries and levels it names"
```

---

### Task 9: a mitigates edge lowers a score, and the report names what it rests on

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ComponentMitigations.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ProtectionDependencies.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/AssessThreatModel.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ComponentMitigationTests.swift`

**Interfaces:**
- Consumes: `MitigatesEdge`, `ComponentMitigation`,
  `ResolvedThreat.mitigatedByComponents`, `ThreatModel.mitigatesEdges` — all
  from Task 4. The call site in `ThreatResolver` already exists; **do not
  change `ThreatResolver.swift` in this task.**
- Produces:
  - `ComponentMitigations.apply` keeps its Task 4 signature and starts
    reducing.
  - `struct UnansweredThreat { let threatId: String; let name: String; let residualScore: Int; let levelLabel: String }`.
  - `struct ProtectionDependency { let protectorId: String; let protectorName: String; let protects: [String]; let unanswered: [UnansweredThreat] }`.
  - `enum ProtectionDependencies { static func derive(from: [ResolvedThreat], edges: [MitigatesEdge], nameOf: (ComponentId) -> String) -> [ProtectionDependency] }`.
  - `AssessThreatModelResponse.protectionDependencies: [ProtectionDependency]`
    and `AssessThreatModelResponse.warnings: [String]`, both defaulted to empty.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/ComponentMitigationTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct ComponentMitigationTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func component(_ id: String, _ technology: String = "aws-ec2") -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId(technology),
            position: Point(x: 0, y: 0),
            sensitivity: .confidential
        )
    }

    private func model(_ edges: [MitigatesEdge]) -> ThreatModel {
        ThreatModel(
            name: "S",
            components: [component("guard", "aws-waf"), component("store")],
            mitigatesEdges: edges
        )
    }

    private func credentialTheft(_ model: ThreatModel) -> ResolvedThreat {
        ThreatResolver(model: model, catalogue: catalogue).resolve()
            .first { $0.threat.id == ThreatId("credential-theft") && $0.source.id == "component:store" }!
    }

    @Test func noEdgeLeavesTheScoreAlone() {
        #expect(credentialTheft(model([])).score.value == 12)
    }

    @Test func anEdgeLowersTheThreatItNamesOnTheComponentItProtects() {
        let threat = credentialTheft(model([
            MitigatesEdge(
                source: ComponentId("guard"),
                target: ComponentId("store"),
                threatIds: [ThreatId("credential-theft")],
                reducesRiskBy: 75
            )
        ]))
        #expect(threat.score.value == 3)
        #expect(threat.mitigatedByComponents.first?.protectorName == "WAF")
        #expect(threat.mitigatedByComponents.first?.reducesRiskBy == 75)
    }

    @Test func anEdgeNamingAnotherThreatChangesNothing() {
        let threat = credentialTheft(model([
            MitigatesEdge(
                source: ComponentId("guard"),
                target: ComponentId("store"),
                threatIds: [ThreatId("dos-attack")],
                reducesRiskBy: 75
            )
        ]))
        #expect(threat.score.value == 12)
    }

    @Test func twoEdgesGiveTheStrongerAndNotTheSum() {
        let threat = credentialTheft(model([
            MitigatesEdge(
                source: ComponentId("guard"),
                target: ComponentId("store"),
                threatIds: [ThreatId("credential-theft")],
                reducesRiskBy: 25
            ),
            MitigatesEdge(
                source: ComponentId("store"),
                target: ComponentId("store"),
                threatIds: [ThreatId("credential-theft")],
                reducesRiskBy: 50
            )
        ]))
        #expect(threat.score.value == 6)
    }

    @Test func theScoreNeverFallsBelowOne() {
        let threat = credentialTheft(model([
            MitigatesEdge(
                source: ComponentId("guard"),
                target: ComponentId("store"),
                threatIds: [ThreatId("credential-theft")],
                reducesRiskBy: 100
            )
        ]))
        #expect(threat.score.value == 1)
    }

    @Test func theAssessmentNamesWhatTheReductionRestsOn() throws {
        let held = model([
            MitigatesEdge(
                source: ComponentId("guard"),
                target: ComponentId("store"),
                threatIds: [ThreatId("credential-theft")],
                reducesRiskBy: 75
            )
        ])
        let response = AssessThreatModel(
            models: InMemoryThreatModelGateway(held),
            catalogue: catalogue
        ).execute(AssessThreatModelRequest())

        let dependency = try #require(response.protectionDependencies.first)
        #expect(dependency.protectorName == "WAF")
        #expect(dependency.protects == ["credential-theft on store"])
        #expect(dependency.unanswered.isEmpty)
        #expect(response.warnings.isEmpty)
    }

    @Test func anUnansweredThreatOnTheProtectorIsAWarning() throws {
        let held = ThreatModel(
            name: "S",
            components: [component("guard"), component("store")],
            mitigatesEdges: [
                MitigatesEdge(
                    source: ComponentId("guard"),
                    target: ComponentId("store"),
                    threatIds: [ThreatId("credential-theft")],
                    reducesRiskBy: 75
                )
            ]
        )
        let response = AssessThreatModel(
            models: InMemoryThreatModelGateway(held),
            catalogue: catalogue
        ).execute(AssessThreatModelRequest())

        #expect(response.protectionDependencies.first?.unanswered.isEmpty == false)
        #expect(response.warnings.contains {
            $0.contains("risk reductions depend on") && $0.contains("EC2")
        })
    }
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd ThreatModelKit && swift test --filter ComponentMitigationTests`
Expected: FAIL, `anEdgeLowersTheThreatItNamesOnTheComponentItProtects` reads 12
where it expects 3.

- [ ] **Step 3: Write the reduction**

Replace the body of `ComponentMitigations.apply` in
`ComponentMitigations.swift`:

```swift
/// The stage between the pathway mitigation and the compensating control.
///
/// Spec section 6.2. Two edges that both answer one threat give the stronger
/// reduction, not the sum, which is the rule the pathway mitigations and the
/// compensating controls already follow.
public enum ComponentMitigations {
    public static func apply(
        score: Int,
        threatId: ThreatId,
        target: ComponentId,
        edges: [MitigatesEdge],
        nameOf: (ComponentId) -> String
    ) -> (score: Int, by: [ComponentMitigation]) {
        let answering = edges.filter { $0.target == target && $0.answers(threatId) }
        guard answering.isEmpty == false else { return (score, []) }

        let strongest = answering.map(\.reducesRiskBy).max() ?? 0
        let reduced = max(1, Int((Double(score) * (1 - Double(strongest) / 100)).rounded()))

        return (
            reduced,
            answering.map {
                ComponentMitigation(
                    protectorId: $0.source,
                    protectorName: nameOf($0.source),
                    reducesRiskBy: $0.reducesRiskBy
                )
            }
        )
    }
}
```

- [ ] **Step 4: Write the derived tamper surface**

Create `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ProtectionDependencies.swift`:

```swift
/// A threat on a protector that nobody has answered.
public struct UnansweredThreat: Equatable, Sendable {
    public let threatId: String
    public let name: String
    public let residualScore: Int
    public let levelLabel: String

    public init(threatId: String, name: String, residualScore: Int, levelLabel: String) {
        self.threatId = threatId
        self.name = name
        self.residualScore = residualScore
        self.levelLabel = levelLabel
    }
}

/// What one protector's reductions rest on.
public struct ProtectionDependency: Equatable, Sendable {
    public let protectorId: String
    public let protectorName: String
    /// The reductions this protector gives, as "<threat id> on <component id>".
    public let protects: [String]
    public let unanswered: [UnansweredThreat]

    public init(
        protectorId: String,
        protectorName: String,
        protects: [String],
        unanswered: [UnansweredThreat]
    ) {
        self.protectorId = protectorId
        self.protectorName = protectorName
        self.protects = protects
        self.unanswered = unanswered
    }
}

/// Derives the tamper surface of every `mitigates` edge.
///
/// Spec section 6.3: the surface is reported, never scored. Scaling a
/// reduction by the protector's own residual score would invent arithmetic
/// nobody can defend in a review.
public enum ProtectionDependencies {
    /// One entry per protector, in the order the edges are declared.
    public static func derive(
        from resolved: [ResolvedThreat],
        edges: [MitigatesEdge],
        nameOf: (ComponentId) -> String
    ) -> [ProtectionDependency] {
        var order: [ComponentId] = []
        var protects: [ComponentId: [String]] = [:]

        for edge in edges {
            if protects[edge.source] == nil { order.append(edge.source) }
            protects[edge.source, default: []] += edge.threatIds.map {
                "\($0.value) on \(edge.target.value)"
            }
        }

        return order.map { protector in
            ProtectionDependency(
                protectorId: protector.value,
                protectorName: nameOf(protector),
                protects: protects[protector] ?? [],
                unanswered: unanswered(on: protector, in: resolved)
            )
        }
    }

    /// The threats raised on the protector that no control and no compensating
    /// control answers.
    private static func unanswered(
        on protector: ComponentId,
        in resolved: [ResolvedThreat]
    ) -> [UnansweredThreat] {
        resolved
            .filter { $0.source.id == "component:\(protector.value)" }
            .filter { threat in
                threat.compensating.isEmpty
                    && threat.controls.contains { $0.status.isAnswered } == false
            }
            .map {
                UnansweredThreat(
                    threatId: $0.threat.id.value,
                    name: $0.threat.name,
                    residualScore: $0.score.value,
                    levelLabel: $0.score.level.label
                )
            }
    }

    /// The sentence the assessment states for a protector carrying an
    /// unanswered threat at high or critical.
    public static func warnings(for dependencies: [ProtectionDependency]) -> [String] {
        dependencies.compactMap { dependency in
            let serious = dependency.unanswered.filter {
                $0.levelLabel == "High" || $0.levelLabel == "Critical"
            }
            guard serious.isEmpty == false else { return nil }
            return "\(dependency.protects.count) risk reductions depend on "
                + "\"\(dependency.protectorName)\", which has \(serious.count) "
                + "unanswered threats"
        }
    }
}
```

- [ ] **Step 5: State them in the assessment**

In `AssessThreatModel.swift`, add to `AssessThreatModelResponse`:

```swift
    /// What each `mitigates` edge rests on. Empty when the model draws none.
    public let protectionDependencies: [ProtectionDependency]
    /// What a reader must know before they trust a reduction.
    public let warnings: [String]
```

with the initialiser parameters `protectionDependencies: [ProtectionDependency] = []`
and `warnings: [String] = []`, and in `execute`:

```swift
        let model = models.current()
        let lookup = TechnologyLookup(model: model, catalogue: catalogue)
        let resolved = ThreatResolver(model: model, catalogue: catalogue).resolve()
        let nameOf: (ComponentId) -> String = { id in
            guard let component = model.components.first(where: { $0.id == id }) else {
                return id.value
            }
            return component.customName
                ?? lookup.findById(component.technologyId)?.name
                ?? component.technologyId.value
        }
        let dependencies = ProtectionDependencies.derive(
            from: resolved,
            edges: model.mitigatesEdges,
            nameOf: nameOf
        )
```

and pass `protectionDependencies: dependencies` and
`warnings: ProtectionDependencies.warnings(for: dependencies)` to the response.
Replace the existing `ThreatResolver(model: models.current(), ...)` line with
the `resolved` value above, so the model is read once.

- [ ] **Step 6: Run the suite**

Run: `cd ThreatModelKit && swift test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/assessment \
        ThreatModelKit/Tests/UnitTests/ComponentMitigationTests.swift
git -c commit.gpgsign=false commit -m "feat: a mitigates edge lowers a score, and the assessment names what it rests on"
```

---

### Task 10: the document carries the new values

**Files:**
- Modify: `ThreatModelKit/Sources/FileGateways/DocumentJSON.swift`
- Modify: `ThreatModelKit/Sources/FileGateways/ThreatModelCodec.swift`
- Test: `ThreatModelKit/Tests/UnitTests/DocumentFormatVersionFourTests.swift`

**Interfaces:**
- Consumes: `Connection.kind`, `Connection.description`, `Component.runsAs`,
  `Component.assets`, `Zone.boundary`, `Zone.description`,
  `ThreatModel.mitigatesEdges`, `ThreatModel.recommendations` — all from
  Task 4.
- Produces: `ThreatModelCodec.formatVersion == 4`, and
  `readableFormatVersions` holding 1, 2, 3 and 4.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/DocumentFormatVersionFourTests.swift`:

```swift
import Testing
import Foundation
import ThreatModelKit
import FileGateways
import TestSupport

struct DocumentFormatVersionFourTests {
    private func model() -> ThreatModel {
        ThreatModel(
            name: "S",
            components: [
                Component(
                    id: ComponentId("guard"),
                    technologyId: TechnologyId("aws-waf"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .internalData,
                    runsAs: .root,
                    assets: [Asset(name: "ssh-keys", sensitivity: .restricted)]
                ),
                Component(
                    id: ComponentId("store"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 200, y: 0),
                    sensitivity: .confidential
                )
            ],
            connections: [
                Connection(
                    id: ConnectionId("guard->store"),
                    source: ComponentId("guard"),
                    target: ComponentId("store"),
                    kind: .ipc,
                    description: "XPC call"
                )
            ],
            zones: [
                Zone(
                    id: ZoneId("root"),
                    rect: Rect(x: 0, y: 0, width: 400, height: 300),
                    boundary: .privilege,
                    description: "uid 0"
                )
            ],
            recommendations: [
                ThreatKey(threatId: "credential-theft", sourceId: "component:store"):
                    [Recommendation(text: "Deny reads of /dev/rdisk**", note: "An endpoint rule.")]
            ],
            mitigatesEdges: [
                MitigatesEdge(
                    source: ComponentId("guard"),
                    target: ComponentId("store"),
                    threatIds: [ThreatId("credential-theft")],
                    reducesRiskBy: 80
                )
            ]
        )
    }

    @Test func aRoundTripKeepsEveryNewValue() throws {
        let data = try ThreatModelCodec().encode(model())
        let read = try ThreatModelCodec().decode(data)

        #expect(read.connections.first?.kind == .ipc)
        #expect(read.connections.first?.description == "XPC call")
        #expect(read.components.first?.runsAs == .root)
        #expect(read.components.first?.assets == [Asset(name: "ssh-keys", sensitivity: .restricted)])
        #expect(read.zones.first?.boundary == .privilege)
        #expect(read.zones.first?.description == "uid 0")
        #expect(read.mitigatesEdges.first?.reducesRiskBy == 80)
        #expect(read.recommendations.values.first?.first?.text == "Deny reads of /dev/rdisk**")
    }

    @Test func theFormatVersionIsFour() throws {
        let data = try ThreatModelCodec().encode(model())
        let text = try #require(String(data: data, encoding: .utf8))
        #expect(text.contains("\"formatVersion\" : 4"))
    }

    @Test func aVersionThreeDocumentStillReads() throws {
        let text = """
        {
          "formatVersion" : 3,
          "name" : "S",
          "createdAt" : 0,
          "updatedAt" : 0,
          "components" : [],
          "connections" : [],
          "zones" : [],
          "customTechnologies" : [],
          "severityOverrides" : {},
          "implementedControls" : [],
          "pathwayMitigations" : { "isMasterEnabled" : false, "configs" : {} }
        }
        """
        let read = try ThreatModelCodec().decode(Data(text.utf8))
        #expect(read.name == "S")
        #expect(read.mitigatesEdges.isEmpty)
    }
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd ThreatModelKit && swift test --filter DocumentFormatVersionFourTests`
Expected: FAIL, `theFormatVersionIsFour` reads 3.

- [ ] **Step 3: Add the fields to `DocumentJSON.swift`**

Every new field is optional, so a version 3 file still decodes.

```swift
struct AssetJSON: Codable {
    let name: String
    let sensitivity: String
}

struct MitigatesEdgeJSON: Codable {
    let source: String
    let target: String
    let threatIds: [String]
    let reducesRiskBy: Int
}

struct RecommendationJSON: Codable {
    let text: String
    let note: String?
}
```

On `ComponentJSON` add `let runsAs: String?` and `let assets: [AssetJSON]?`.
On `ConnectionJSON` add `let kind: String?` and `let description: String?`.
On `ZoneJSON` add `let boundary: String?` and `let description: String?`.
On `DocumentJSON` add:

```swift
    /// Version 4 adds these three. A version 1, 2 or 3 file has none.
    let mitigatesEdges: [MitigatesEdgeJSON]?
    let recommendations: [String: [RecommendationJSON]]?
```

- [ ] **Step 4: Read and write them in `ThreatModelCodec.swift`**

Set `public static let formatVersion = 4` and add `4` to
`readableFormatVersions`. In the encoder, fill every new field. In the decoder,
map each one through its `rawValue` initialiser and fall back to the default:

```swift
                runsAs: PrivilegeLevel(rawValue: component.runsAs ?? "") ?? .default,
                assets: (component.assets ?? []).map {
                    Asset(
                        name: $0.name,
                        sensitivity: DataSensitivity(rawValue: $0.sensitivity) ?? .internalData
                    )
                }
```

```swift
                kind: FlowKind(rawValue: connection.kind ?? "") ?? .default,
                description: connection.description
```

```swift
                boundary: ZoneBoundary(rawValue: zone.boundary ?? "") ?? .default,
                description: zone.description
```

```swift
        model.mitigatesEdges = (document.mitigatesEdges ?? []).map {
            MitigatesEdge(
                source: ComponentId($0.source),
                target: ComponentId($0.target),
                threatIds: $0.threatIds.map(ThreatId.init),
                reducesRiskBy: $0.reducesRiskBy
            )
        }
        model.recommendations = (document.recommendations ?? [:]).reduce(into: [:]) { held, pair in
            held[ThreatKey(pair.key)] = pair.value.map {
                Recommendation(text: $0.text, note: $0.note)
            }
        }
```

Add the same three new fields to `SelectionJSON`'s connections and components,
so a copy and a paste keep a flow's kind and a component's privilege.

- [ ] **Step 5: Run the suite**

Run: `cd ThreatModelKit && swift test`
Expected: PASS, including `ThreatModelGatewayContract`.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/FileGateways \
        ThreatModelKit/Tests/UnitTests/DocumentFormatVersionFourTests.swift
git -c commit.gpgsign=false commit -m "feat: the document carries flow kinds, privileges, assets, boundaries and mitigates edges"
```

---

### Task 11: the window edits a flow kind, a boundary and a privilege

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/SetConnectionProperties.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/ViewThreatModel.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/SetComponentProperties.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/SetZoneProperties.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`
- Create: `threatmodeller/canvas/ConnectionPanel.swift`
- Modify: `threatmodeller/canvas/ComponentPanel.swift`
- Modify: `threatmodeller/canvas/ZonePanel.swift`
- Modify: `threatmodeller/canvas/CanvasView.swift`
- Modify: `threatmodeller/ThreatModelSession.swift`
- Test: `ThreatModelKit/Tests/UnitTests/SetConnectionPropertiesTests.swift`

**Interfaces:**
- Consumes: `FlowKind`, `PrivilegeLevel`, `ZoneBoundary` from Task 4.
- Produces:
  - `SetConnectionPropertiesRequest(connectionId: String, kind: String, description: String?)`
    and `enum SetConnectionPropertiesResponse { case updated, unknownConnection, unknownKind }`.
  - `SetComponentPropertiesRequest.runsAs: String`, added as the last
    parameter with no default, and the response case `unknownPrivilegeLevel`.
  - `SetZonePropertiesRequest.boundary: String`, added as the last parameter
    with no default, and the response case `unknownBoundary`.
  - `ViewedConnection.kindId: String`, `ViewedConnection.description: String?`,
    `ViewedComponent.runsAsId: String`, `ViewedZone.boundaryId: String`.

**Out of scope:** editing an asset in the window. An asset is written in the
`.arch` file and read by the report. State that limit in the commit body.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/SetConnectionPropertiesTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct SetConnectionPropertiesTests {
    private func gateway() -> InMemoryThreatModelGateway {
        InMemoryThreatModelGateway(
            ThreatModel(
                components: [
                    Component(id: ComponentId("a"), technologyId: TechnologyId("aws-ec2"), position: Point(x: 0, y: 0)),
                    Component(id: ComponentId("b"), technologyId: TechnologyId("aws-ec2"), position: Point(x: 100, y: 0))
                ],
                connections: [
                    Connection(id: ConnectionId("a->b"), source: ComponentId("a"), target: ComponentId("b"))
                ]
            )
        )
    }

    @Test func itSetsTheKindAndTheDescription() {
        let models = gateway()
        let response = SetConnectionProperties(models: models).execute(
            SetConnectionPropertiesRequest(connectionId: "a->b", kind: "ipc", description: "XPC call")
        )
        #expect(response == .updated)
        #expect(models.current().connections.first?.kind == .ipc)
        #expect(models.current().connections.first?.description == "XPC call")
    }

    @Test func anEmptyDescriptionIsNoDescription() {
        let models = gateway()
        _ = SetConnectionProperties(models: models).execute(
            SetConnectionPropertiesRequest(connectionId: "a->b", kind: "ipc", description: "  ")
        )
        #expect(models.current().connections.first?.description == nil)
    }

    @Test func itRefusesAKindTheApplicationDoesNotHold() {
        let models = gateway()
        let response = SetConnectionProperties(models: models).execute(
            SetConnectionPropertiesRequest(connectionId: "a->b", kind: "carrier-pigeon", description: nil)
        )
        #expect(response == .unknownKind)
        #expect(models.current().connections.first?.kind == .network)
    }

    @Test func itRefusesAConnectionTheModelDoesNotHold() {
        let response = SetConnectionProperties(models: gateway()).execute(
            SetConnectionPropertiesRequest(connectionId: "x->y", kind: "ipc", description: nil)
        )
        #expect(response == .unknownConnection)
    }

    @Test func theViewStatesTheKindThePrivilegeAndTheBoundary() throws {
        let models = gateway()
        _ = SetConnectionProperties(models: models).execute(
            SetConnectionPropertiesRequest(connectionId: "a->b", kind: "file", description: nil)
        )
        let view = ViewThreatModel(models: models, catalogue: CatalogueFixture.catalogue())
            .execute(ViewThreatModelRequest())
        #expect(view.connections.first?.kindId == "file")
        #expect(view.components.first?.runsAsId == "user")
    }
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd ThreatModelKit && swift test --filter SetConnectionPropertiesTests`
Expected: FAIL, `cannot find 'SetConnectionProperties' in scope`.

- [ ] **Step 3: Write the use case**

Create `SetConnectionProperties.swift`, following the shape
`SetZoneProperties.swift` already uses:

```swift
public protocol SetConnectionPropertiesUseCase {
    func execute(_ request: SetConnectionPropertiesRequest) -> SetConnectionPropertiesResponse
}

public struct SetConnectionPropertiesRequest: Equatable, Sendable {
    public let connectionId: String
    /// A flow kind: network, ipc, file, syscall or human.
    public let kind: String
    /// Why the flow is there, or nil. An empty text is the same as nil.
    public let description: String?

    public init(connectionId: String, kind: String, description: String?) {
        self.connectionId = connectionId
        self.kind = kind
        self.description = description
    }
}

public enum SetConnectionPropertiesResponse: Equatable, Sendable {
    case updated
    case unknownConnection
    case unknownKind
}

/// Changes what a flow is and why it is there.
///
/// The kind decides which threats the flow raises, so the sidebar rescores as
/// soon as a user changes it.
public struct SetConnectionProperties: SetConnectionPropertiesUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetConnectionPropertiesRequest) -> SetConnectionPropertiesResponse {
        let id = ConnectionId(request.connectionId)

        return models.mutate { model in
            guard let index = model.connections.firstIndex(where: { $0.id == id }) else {
                return .unknownConnection
            }
            guard let kind = FlowKind(rawValue: request.kind) else { return .unknownKind }

            let trimmed = request.description?.trimmingWhitespace() ?? ""
            model.connections[index].kind = kind
            model.connections[index].description = trimmed.isEmpty ? nil : trimmed
            return .updated
        }
    }
}
```

`mutate` is how every write use case changes the model: it reads, changes and
writes in one step, and it records the undo. Read `SetZoneProperties.swift`
for the same shape.

- [ ] **Step 4: State the values in the view**

In `ViewThreatModel.swift`, add `public let kindId: String` and
`public let description: String?` to `ViewedConnection`,
`public let runsAsId: String` to `ViewedComponent`, and
`public let boundaryId: String` to `ViewedZone`, filling each from the model.
Give each a default in the initialiser so the existing tests still build.

- [ ] **Step 5: Widen the two property use cases**

`SetComponentPropertiesRequest` takes `runsAs: String` as its last parameter.
`SetComponentProperties` returns `.unknownPrivilegeLevel` for a value outside
the ladder, and otherwise writes `component.runsAs`.

`SetZonePropertiesRequest` takes `boundary: String` as its last parameter.
`SetZoneProperties` returns `.unknownBoundary` for a value outside the two,
and otherwise writes `zone.boundary`.

Update every caller the compiler names, including `UseCaseFactory.swift` and
`ThreatModelSession.swift`.

- [ ] **Step 6: Add the pickers**

Create `threatmodeller/canvas/ConnectionPanel.swift`, following
`ZonePanel.swift` line for line:

```swift
import SwiftUI
import ThreatModelKit

/// The bar under the canvas, shown while exactly one flow is selected.
///
/// The kind decides which threats the flow raises, so the threat list changes
/// as the user changes the picker.
struct ConnectionPanel: View {
    let session: ThreatModelSession
    let connection: ViewedConnection

    private static let kinds = [
        ("network", "Network"),
        ("ipc", "Local IPC"),
        ("file", "File"),
        ("syscall", "System Call"),
        ("human", "Human")
    ]

    var body: some View {
        HStack(alignment: .center, spacing: 16) {
            Picker("Kind", selection: kind) {
                ForEach(Self.kinds, id: \.0) { Text($0.1).tag($0.0) }
            }
            .labelsHidden()
            .frame(width: 160)
            .accessibilityIdentifier("connection-kind")

            TextField("Description", text: description)
                .textFieldStyle(.roundedBorder)
                .frame(width: 280)
                .accessibilityIdentifier("connection-description")

            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.bar)
    }

    private var kind: Binding<String> {
        Binding(
            get: { connection.kindId },
            set: { session.setConnectionProperties(connectionId: connection.id, kind: $0, description: connection.description) }
        )
    }

    private var description: Binding<String> {
        Binding(
            get: { connection.description ?? "" },
            set: { session.setConnectionProperties(connectionId: connection.id, kind: connection.kindId, description: $0) }
        )
    }
}
```

Add `setConnectionProperties(connectionId:kind:description:)` to
`ThreatModelSession.swift`, beside `setZoneProperties`.

In `ComponentPanel.swift`, add the privilege picker after the sensitivity
picker, writing through the widened `SetComponentProperties`:

```swift
    private static let privileges = [
        ("user", "User"),
        ("admin", "Administrator"),
        ("root", "Root"),
        ("system", "System"),
        ("kernel", "Kernel")
    ]
```

```swift
            Picker("Runs as", selection: runsAs) {
                ForEach(Self.privileges, id: \.0) { Text($0.1).tag($0.0) }
            }
            .labelsHidden()
            .frame(width: 150)
            .accessibilityIdentifier("component-runs-as")
```

In `ZonePanel.swift`, add the boundary picker before the network picker, and
show the network picker only while the boundary is `network`:

```swift
    private static let boundaries = [("network", "Network"), ("privilege", "Privilege")]
```

```swift
            Picker("Boundary", selection: boundary) {
                ForEach(Self.boundaries, id: \.0) { Text($0.1).tag($0.0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 180)
            .accessibilityIdentifier("zone-boundary")
```

In `CanvasView.swift`, show the new panel where the other two are chosen:

```swift
            if let component = selectedComponent {
                ComponentPanel(session: session, component: component)
            } else if let zone = selectedZone {
                ZonePanel(session: session, zone: zone)
            } else if let connection = selectedConnection {
                ConnectionPanel(session: session, connection: connection)
            }
```

with:

```swift
    /// The one flow the panel edits, or nil while none or many are selected.
    private var selectedConnection: ViewedConnection? {
        guard canvas.selectedConnectionIds.count == 1,
              let connectionId = canvas.selectedConnectionIds.first else { return nil }
        return session.model.connections.first { $0.id == connectionId }
    }
```

Read how `selectedZone` reaches the view model in the same file and follow it
exactly, rather than the line above, when the two differ.

- [ ] **Step 7: Run both suites**

```bash
cd ThreatModelKit && swift test && cd ..
xcodebuild clean -project threatmodeller.xcodeproj -scheme threatmodeller \
  -destination 'platform=macOS'
xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller \
  -destination 'platform=macOS'
```
Expected: PASS. `ViewRenderTests` draws the panels; add a case for
`ConnectionPanel` beside the cases for the other two.

- [ ] **Step 8: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/modelling \
        ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift \
        ThreatModelKit/Tests/UnitTests/SetConnectionPropertiesTests.swift \
        threatmodeller
git -c commit.gpgsign=false commit -m "feat: the window edits a flow kind, a zone boundary and a component privilege"
```

---

### Task 12: the endpoint library

**Files:**
- Create: `libraries/endpoint.lib`
- Create: `libraries/README.md`
- Test: `ThreatModelKit/Tests/UnitTests/EndpointLibraryTests.swift`

**Interfaces:**
- Consumes: the `.lib` attributes `applies_to`, `boundary`, `runs_as`,
  `pathway` and the `mitigation` block, from Task 6.
- Produces: a library whose label is `endpoint`. Nothing in this plan consumes
  it; a user copies the file into a project's `library` directory.

**Do not** put this file under
`ThreatModelKit/Sources/CatalogueGateways/Resources/Library/`. That directory
is the vendored third-party catalogue and is checksum-locked.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/EndpointLibraryTests.swift`:

```swift
import Testing
import Foundation
import ThreatModelKit
import ArchitectureDSL
import TestSupport

struct EndpointLibraryTests {
    /// The file sits at the repository root, four directories above this
    /// source file.
    private func text() throws -> String {
        let here = URL(fileURLWithPath: #filePath)
        let root = here.deletingLastPathComponent()   // UnitTests
            .deletingLastPathComponent()              // Tests
            .deletingLastPathComponent()              // ThreatModelKit
            .deletingLastPathComponent()              // the repository
        return try String(contentsOf: root.appending(path: "libraries/endpoint.lib"), encoding: .utf8)
    }

    @Test func theLibraryReadsWithNoFault() throws {
        let read = HclLibrarySource().read(try text())
        #expect(read.diagnostics.isEmpty)
        let source = try #require(read.source)
        #expect(source.label == "endpoint")
    }

    @Test func theLibraryBuildsAgainstTheTaxonomy() throws {
        let source = try #require(HclLibrarySource().read(try text()).source)
        let built = Library.build(from: source, taxonomy: CatalogueFixture.taxonomy())
        #expect(built.faults.isEmpty)
        let library = try #require(built.library)
        #expect(library.technologies.count >= 10)
        #expect(library.threats.count >= 10)
        #expect(library.pathwayMitigations.isEmpty == false)
    }

    @Test func everyConnectionThreatStatesTheKindsItAppliesTo() throws {
        let source = try #require(HclLibrarySource().read(try text()).source)
        for threat in source.threats where threat.isConnectionThreat {
            #expect(threat.appliesTo.isEmpty == false || threat.boundary != nil)
        }
    }

    @Test func aRewriteOfTheLibraryProducesTheSameText() throws {
        let text = try text()
        let source = try #require(HclLibrarySource().read(text).source)
        #expect(HclLibrarySource().write(source) == text)
    }
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd ThreatModelKit && swift test --filter EndpointLibraryTests`
Expected: FAIL, the file does not exist.

- [ ] **Step 3: Write the library**

Create `libraries/endpoint.lib`. Use the categories the taxonomy holds; read
`ThreatModelKit/Sources/CatalogueGateways/Resources/Library/taxonomy.json` for
the category ids and the severity ids, and use those exact strings.

The file holds ten technologies:

| Technology id | Name |
| --- | --- |
| `system-extension` | System Extension |
| `es-client` | Endpoint Security Client |
| `keychain` | Keychain |
| `mdm-channel` | MDM Channel |
| `tcc` | TCC |
| `gatekeeper` | Gatekeeper |
| `launchd` | launchd |
| `kernel-extension` | Kernel Extension |
| `xpc-service` | XPC Service |
| `unix-socket` | Unix Domain Socket |

and ten threats, each stating its kinds, its boundary and its levels:

| Threat id | Severity | `connection` | `zone` | `applies_to` | `boundary` | `runs_as` | `pathway` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `raw-device-read` | critical | false | false | — | — | `root`, `kernel` | true |
| `dylib-injection` | high | true | false | `file`, `ipc` | — | — | true |
| `persistence` | high | false | false | — | — | `user`, `admin`, `root` | true |
| `tcc-bypass` | high | true | false | `ipc`, `syscall` | — | — | false |
| `profile-injection` | critical | false | false | — | — | `root`, `system` | true |
| `privilege-escalation` | critical | true | true | — | `privilege` | — | true |
| `sandbox-escape` | high | true | true | — | `privilege` | — | true |
| `boundary-bypass` | medium | true | true | — | `privilege` | — | false |
| `keychain-item-theft` | critical | false | false | — | — | — | true |
| `unsigned-code-load` | high | true | false | `file` | — | — | true |

Every threat states `name`, `description`, `severity`, `stride`, at least one
`mitre` block and at least two `control` statements. Write the controls for a
host, never for a cloud: "Deny the write with an Endpoint Security rule", not
"Deploy load balancers with DDoS protection".

The file holds two mitigations:

```hcl
  mitigation "es-client-protection" {
    name            = "Endpoint Security client"
    description     = "Denies unsigned code and watches the file system"
    mitigates       = ["dylib-injection", "unsigned-code-load", "persistence"]
    provided_by     = ["es-client"]
    reduces_risk_by = 60
  }

  mitigation "gatekeeper-assessment" {
    name            = "Gatekeeper assessment"
    description     = "Refuses to run code that is neither signed nor notarised"
    mitigates       = ["unsigned-code-load"]
    provided_by     = ["gatekeeper"]
    reduces_risk_by = 40
  }
```

- [ ] **Step 4: Write `libraries/README.md`**

State three things: what the library is for, how to use it, and that it is not
vendored.

```markdown
# The libraries this repository ships

A library is a `.lib` file. `docs/LANGUAGE.md` section 6 states the language.

## `endpoint.lib`

Technologies and threats for a macOS endpoint: a system extension, the
Endpoint Security client, the keychain, an MDM channel, TCC, Gatekeeper,
launchd, a kernel extension, an XPC service and a unix domain socket.

Copy it into a project to use it:

```
cp libraries/endpoint.lib <project>/threatmodel/library/
```

The file is this repository's own content. It is not vendored, it is not in
`library.lock.json`, and `threatmodeller library verify` says nothing about
it.
```

- [ ] **Step 5: Run the test**

Run: `cd ThreatModelKit && swift test --filter EndpointLibraryTests`
Expected: PASS. When `aRewriteOfTheLibraryProducesTheSameText` fails, write the
file in the canonical shape the writer produces rather than changing the
writer.

- [ ] **Step 6: Check the vendored catalogue is untouched**

Run: `scripts/update-catalogue.sh verify`
Expected: it reports that the files and the lock file agree.

- [ ] **Step 7: Commit**

```bash
git add libraries ThreatModelKit/Tests/UnitTests/EndpointLibraryTests.swift
git -c commit.gpgsign=false commit -m "feat: an endpoint library of macOS technologies and host threats"
```

---

## Wave 4: the four report sections

### Task 13: the report tree holds four more sections

This is the contract task of wave 4. Every builder it creates returns nothing,
and every Markdown section it creates writes nothing, so the report is
unchanged when this task commits.

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/ReportSections.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/RecommendationsReport.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/ProtectionDependenciesReport.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/AttackPaths.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/ReportRollups.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownRecommendations.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownProtectionDependencies.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownAttackPaths.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownRollups.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/Report.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/BuildThreatModelReport.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/ExportModelAsMarkdown.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ReportSectionsTests.swift`

**Interfaces:**
- Consumes: `ThreatModel.recommendations` (Task 4),
  `AssessThreatModelResponse.protectionDependencies` (Task 9),
  `ReportThreat.inherentScore` (Task 2), `Connection.kind` (Task 4).
- Produces, and nothing may change after this task commits:
  - `struct ReportRecommendation { let text: String; let note: String?; let threatName: String; let sourceName: String; let riskScore: Int }`
  - `struct ReportProtectionDependency { let protectorName: String; let protects: [String]; let unanswered: [ReportUnansweredThreat] }`
  - `struct ReportUnansweredThreat { let name: String; let riskScore: Int; let riskLevel: String }`
  - `struct ReportAttackPathHop { let componentName: String; let flowKindLabel: String?; let worstThreatName: String?; let riskScore: Int; let reducedBy: [String] }`
  - `struct ReportAttackPath { let startName: String; let endName: String; let hops: [ReportAttackPathHop]; let worstScore: Int }`
  - `struct ReportZoneRollup { let zoneName: String; let componentCount: Int; let byLevel: [ReportCount]; let worstScore: Int }`
  - `struct ReportRollupTables { let byZone: [ReportZoneRollup]; let topResidual: [ReportThreat]; let bySourceKind: [ReportCount] }`
  - On `ReportThreat`: `sourceId: String`, which is the identifier
    `ThreatResolver` mints (`component:<id>`, `connection:<id>`, `zone:<id>`),
    not the display name. It takes the initialiser parameter
    `sourceId: String = ""`, so no existing caller breaks.
    `BuildThreatModelReport` fills it from `assessed.source.id`. Task 14 keys
    the recommendations on it.
  - On `ReportComponent`: `assetNames: [String]`, defaulted to empty, filled
    from `component.assets.map(\.name)`. Spec section 11.
  - On `Report`: `recommendations: [ReportRecommendation]`,
    `protectionDependencies: [ReportProtectionDependency]`,
    `attackPaths: [ReportAttackPath]`, `attackPathsNotListed: Int`,
    `rollups: ReportRollupTables`. Every one takes an initialiser parameter
    with an empty default.
  - `enum RecommendationsReport { static func build(threats: [ReportThreat], recommendations: [ThreatKey: [Recommendation]]) -> [ReportRecommendation] }`
  - `enum ProtectionDependenciesReport { static func build(_ dependencies: [ProtectionDependency]) -> [ReportProtectionDependency] }`
  - `enum AttackPaths { static func build(components: [Component], connections: [Connection], zones: [Zone], threats: [ReportThreat], nameOf: (ComponentId) -> String) -> (paths: [ReportAttackPath], notListed: Int) }`
  - `enum ReportRollups { static func build(threats: [ReportThreat], zones: [ReportZone]) -> ReportRollupTables }`
  - `enum MarkdownRecommendations { static func lines(_ recommendations: [ReportRecommendation]) -> [String] }`,
    and the same shape for `MarkdownProtectionDependencies`,
    `MarkdownAttackPaths` (which also takes `notListed: Int`) and
    `MarkdownRollups`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/ReportSectionsTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct ReportSectionsTests {
    @Test func aReportWithNoNewDataHoldsEmptySections() {
        let report = BuildThreatModelReport(
            models: InMemoryThreatModelGateway(ThreatModel()),
            catalogue: CatalogueFixture.catalogue()
        ).execute(BuildThreatModelReportRequest()).report

        #expect(report.recommendations.isEmpty)
        #expect(report.protectionDependencies.isEmpty)
        #expect(report.attackPaths.isEmpty)
        #expect(report.attackPathsNotListed == 0)
        #expect(report.rollups.byZone.isEmpty)
        #expect(report.rollups.topResidual.isEmpty)
    }

    @Test func theMarkdownStillEndsWithTheThreats() {
        let markdown = ExportModelAsMarkdown(
            reports: BuildThreatModelReport(
                models: InMemoryThreatModelGateway(ThreatModel()),
                catalogue: CatalogueFixture.catalogue()
            )
        ).execute(ExportModelAsMarkdownRequest()).markdown
        #expect(markdown.contains("## Threats"))
    }
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd ThreatModelKit && swift test --filter ReportSectionsTests`
Expected: FAIL, `value of type 'Report' has no member 'recommendations'`.

- [ ] **Step 3: Write the section value types**

Create `ReportSections.swift` holding the seven structs named in
**Interfaces**, each with a memberwise `public init` and every collection
defaulted to empty. Give `ReportRollupTables` an empty static value:

```swift
public extension ReportRollupTables {
    static let empty = ReportRollupTables(byZone: [], topResidual: [], bySourceKind: [])
}
```

- [ ] **Step 4: Write the four builders as stubs**

`RecommendationsReport.swift`:

```swift
/// Turns the recommendations on the model into the report's section.
///
/// Task 14 fills this in.
public enum RecommendationsReport {
    public static func build(
        threats: [ReportThreat],
        recommendations: [ThreatKey: [Recommendation]]
    ) -> [ReportRecommendation] {
        []
    }
}
```

Write `ProtectionDependenciesReport.swift`, `AttackPaths.swift` and
`ReportRollups.swift` the same way, each with the signature named in
**Interfaces**, each returning nothing, and each saying which task fills it
in.

- [ ] **Step 5: Write the four Markdown sections as stubs**

`MarkdownRecommendations.swift`:

```swift
/// The report's Recommendations section. Task 14 fills this in.
public enum MarkdownRecommendations {
    public static func lines(_ recommendations: [ReportRecommendation]) -> [String] {
        []
    }
}
```

Write the other three the same way. `MarkdownAttackPaths.lines` takes
`(_ paths: [ReportAttackPath], notListed: Int)`.

- [ ] **Step 6: Add the fields and wire the builders**

Add the five fields to `Report`, each defaulted.

In `BuildThreatModelReport.execute`, after the threats are built, call the four
builders and pass their results to `Report(...)`. Hold the assessment in a
value so the dependencies are read once:

```swift
        let threats = assessment.threats.map { ... }   // the existing map
        let attack = AttackPaths.build(
            components: model.components,
            connections: model.connections,
            zones: model.zones,
            threats: threats,
            nameOf: { nameById[$0] ?? $0.value }
        )
```

```swift
                recommendations: RecommendationsReport.build(
                    threats: threats,
                    recommendations: model.recommendations
                ),
                protectionDependencies: ProtectionDependenciesReport.build(
                    assessment.protectionDependencies
                ),
                attackPaths: attack.paths,
                attackPathsNotListed: attack.notListed,
                rollups: ReportRollups.build(threats: threats, zones: zones)
```

where `zones` is the `[ReportZone]` the use case already builds. Hoist the
threats and the zones out of the `Report(...)` call so both are named values.

- [ ] **Step 7: Show the assets on the component table**

In `Report.swift` add `assetNames` to `ReportComponent`, in
`BuildThreatModelReport` fill it from `component.assets.map(\.name)`, and in
`ExportModelAsMarkdown.components(_:)` widen the table:

```swift
        lines.append("| Name | Technology | Sensitivity | Zone | Assets |")
        lines.append("| --- | --- | --- | --- | --- |")
        for component in components {
            lines.append(
                "| \(Markdown.cell(component.name))"
                    + " | \(Markdown.cell(component.technologyId))"
                    + " | \(Markdown.cell(component.sensitivityLabel))"
                    + " | \(Markdown.cell(component.zoneName ?? "\u{2014}"))"
                    + " | \(Markdown.cell(component.assetNames.joined(separator: ", ")))" 
                    + " |"
            )
        }
```

- [ ] **Step 8: Add the four call sites to the Markdown**

In `ExportModelAsMarkdown.execute`, between the summary and the components:

```swift
        lines += summary(report.summary)
        lines += MarkdownRollups.lines(report.rollups)
        lines += components(report.components)
        lines += connections(report.connections)
        lines += zones(report.zones)
        lines += MarkdownAttackPaths.lines(report.attackPaths, notListed: report.attackPathsNotListed)
        lines += MarkdownProtectionDependencies.lines(report.protectionDependencies)
        lines += MarkdownRecommendations.lines(report.recommendations)
        lines += threats(report.threats)
```

- [ ] **Step 9: Run the suite**

Run: `cd ThreatModelKit && swift test`
Expected: PASS. Every new section writes nothing, so the only changed line of
the Markdown is the component table's new column. Update the expected text in
`ReportRendererTests`.

- [ ] **Step 10: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/reporting \
        ThreatModelKit/Tests/UnitTests/ReportSectionsTests.swift
git -c commit.gpgsign=false commit -m "feat: the report tree holds the recommendation, dependency, attack path and rollup sections"
```

---

### Task 14: the report states the recommendations and what each reduction rests on

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/RecommendationsReport.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/ProtectionDependenciesReport.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownRecommendations.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownProtectionDependencies.swift`
- Test: `ThreatModelKit/Tests/UnitTests/RecommendationsSectionTests.swift`

**Interfaces:**
- Consumes: the two builder signatures and the two Markdown signatures Task 13
  minted. **Do not change `Report.swift`, `BuildThreatModelReport.swift` or
  `ExportModelAsMarkdown.swift`.**

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/RecommendationsSectionTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct RecommendationsSectionTests {
    private func threat(_ id: String, _ source: String, _ score: Int) -> ReportThreat {
        ReportThreat(
            threatId: id,
            name: id.capitalized,
            description: "",
            severityLabel: "High",
            riskScore: score,
            riskLevel: "high",
            strideLabels: [],
            mitreTechniqueIds: [],
            sourceName: source,
            sourceKind: "Component",
            controls: [],
            pathwayMitigationLabels: [],
            sourceId: "component:\(source)"
        )
    }

    @Test func aRecommendationCarriesItsThreatAndItsScore() {
        let built = RecommendationsReport.build(
            threats: [threat("credential-theft", "store", 8)],
            recommendations: [
                ThreatKey(threatId: "credential-theft", sourceId: "component:store"):
                    [Recommendation(text: "Deny reads of /dev/rdisk**", note: "An endpoint rule.")]
            ]
        )
        #expect(built.count == 1)
        #expect(built.first?.text == "Deny reads of /dev/rdisk**")
        #expect(built.first?.threatName == "Credential-theft")
        #expect(built.first?.riskScore == 8)
    }

    @Test func theWorstThreatComesFirst() {
        let built = RecommendationsReport.build(
            threats: [threat("a", "one", 4), threat("b", "two", 12)],
            recommendations: [
                ThreatKey(threatId: "a", sourceId: "component:one"): [Recommendation(text: "first")],
                ThreatKey(threatId: "b", sourceId: "component:two"): [Recommendation(text: "second")]
            ]
        )
        #expect(built.map(\.text) == ["second", "first"])
    }

    @Test func theMarkdownWritesNothingWhenThereAreNone() {
        #expect(MarkdownRecommendations.lines([]).isEmpty)
    }

    @Test func theMarkdownNamesTheThreatAndPrintsTheNote() {
        let lines = MarkdownRecommendations.lines([
            ReportRecommendation(
                text: "Deny reads of /dev/rdisk**",
                note: "An endpoint rule.",
                threatName: "Raw device read",
                sourceName: "store",
                riskScore: 12
            )
        ])
        #expect(lines.first == "## Recommendations")
        #expect(lines.contains("- **Deny reads of /dev/rdisk\\*\\***"))
        #expect(lines.contains("  - Raw device read on store, risk 12"))
        #expect(lines.contains("  - An endpoint rule."))
    }

    @Test func theDependencySectionNamesTheProtectorAndWhatIsUnanswered() {
        let lines = MarkdownProtectionDependencies.lines([
            ReportProtectionDependency(
                protectorName: "ClearanceKit",
                protects: ["credential-theft on store"],
                unanswered: [
                    ReportUnansweredThreat(name: "Tampering", riskScore: 12, riskLevel: "critical")
                ]
            )
        ])
        #expect(lines.first == "## Protection dependencies")
        #expect(lines.contains("### ClearanceKit"))
        #expect(lines.contains("- Answers: credential-theft on store"))
        #expect(lines.contains("- Unanswered on this component: Tampering (critical, 12)"))
    }
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd ThreatModelKit && swift test --filter RecommendationsSectionTests`
Expected: FAIL, the builders return nothing.

- [ ] **Step 3: Write the two builders**

`RecommendationsReport.swift`:

```swift
/// Turns the recommendations on the model into the report's section.
///
/// Spec section 8.2: worst first, so the reader starts with the work that
/// matters. A recommendation whose threat the model no longer raises is left
/// out, the way an answer to a threat nobody raises is left out.
public enum RecommendationsReport {
    public static func build(
        threats: [ReportThreat],
        recommendations: [ThreatKey: [Recommendation]]
    ) -> [ReportRecommendation] {
        var built: [ReportRecommendation] = []

        for threat in threats {
            let key = ThreatKey(threatId: threat.threatId, sourceId: threat.sourceId)
            for recommendation in recommendations[key] ?? [] {
                built.append(
                    ReportRecommendation(
                        text: recommendation.text,
                        note: recommendation.note,
                        threatName: threat.name,
                        sourceName: threat.sourceName,
                        riskScore: threat.riskScore
                    )
                )
            }
        }

        return built.sorted { left, right in
            if left.riskScore != right.riskScore { return left.riskScore > right.riskScore }
            return left.text < right.text
        }
    }
}
```

The key must be the one `ApplyControlAnswers` wrote, so it reads
`threat.sourceId`, which Task 13 added, and never the display name.

`ProtectionDependenciesReport.swift`:

```swift
/// Turns the derived tamper surface into the report's section.
public enum ProtectionDependenciesReport {
    public static func build(_ dependencies: [ProtectionDependency]) -> [ReportProtectionDependency] {
        dependencies.map { dependency in
            ReportProtectionDependency(
                protectorName: dependency.protectorName,
                protects: dependency.protects,
                unanswered: dependency.unanswered.map {
                    ReportUnansweredThreat(
                        name: $0.name,
                        riskScore: $0.residualScore,
                        riskLevel: $0.levelLabel.lowercased()
                    )
                }
            )
        }
    }
}
```

- [ ] **Step 4: Write the two Markdown sections**

`MarkdownRecommendations.swift`:

```swift
/// The report's Recommendations section.
///
/// Spec section 8.2. This is the most actionable page of the report, so it
/// sits above the threat list and states the risk beside each line.
public enum MarkdownRecommendations {
    public static func lines(_ recommendations: [ReportRecommendation]) -> [String] {
        guard recommendations.isEmpty == false else { return [] }

        var lines = ["## Recommendations", ""]
        for recommendation in recommendations {
            lines.append("- **\(Markdown.cell(recommendation.text))**")
            lines.append(
                "  - \(recommendation.threatName) on \(recommendation.sourceName),"
                    + " risk \(recommendation.riskScore)"
            )
            if let note = recommendation.note {
                lines.append("  - \(note)")
            }
        }
        lines.append("")
        return lines
    }
}
```

`MarkdownProtectionDependencies.swift`:

```swift
/// The report's Protection dependencies section.
///
/// Spec section 6.3: what each reduction rests on. A protector carrying an
/// unanswered threat is where the whole reduction fails, and this section
/// says so rather than folding a guess into the score.
public enum MarkdownProtectionDependencies {
    public static func lines(_ dependencies: [ReportProtectionDependency]) -> [String] {
        guard dependencies.isEmpty == false else { return [] }

        var lines = ["## Protection dependencies", ""]
        for dependency in dependencies {
            lines.append("### \(dependency.protectorName)")
            lines.append("")
            for answered in dependency.protects {
                lines.append("- Answers: \(answered)")
            }
            if dependency.unanswered.isEmpty {
                lines.append("- Nothing on this component is unanswered.")
            } else {
                for threat in dependency.unanswered {
                    lines.append(
                        "- Unanswered on this component: \(threat.name)"
                            + " (\(threat.riskLevel), \(threat.riskScore))"
                    )
                }
            }
            lines.append("")
        }
        return lines
    }
}
```

- [ ] **Step 5: Run the suite**

Run: `cd ThreatModelKit && swift test`
Expected: PASS. `ReportRendererTests` pins the Markdown; add the two new
sections to the expected text there.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/reporting \
        ThreatModelKit/Tests/UnitTests/RecommendationsSectionTests.swift
git -c commit.gpgsign=false commit -m "feat: the report states the recommendations and the protection dependencies"
```

---

### Task 15: the report shows the attack paths

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/AttackPaths.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownAttackPaths.swift`
- Test: `ThreatModelKit/Tests/UnitTests/AttackPathTests.swift`

**Interfaces:**
- Consumes: `AttackPaths.build` and `MarkdownAttackPaths.lines`, both minted by
  Task 13, and `ZoneContainment`, `Connection.kind`,
  `Component.effectiveSensitivity`. **Do not change `Report.swift`,
  `BuildThreatModelReport.swift` or `ExportModelAsMarkdown.swift`.**

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/AttackPathTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct AttackPathTests {
    private func component(
        _ id: String,
        _ sensitivity: DataSensitivity = .internalData
    ) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: sensitivity
        )
    }

    private func flow(_ source: String, _ target: String, _ kind: FlowKind = .network) -> Connection {
        Connection(
            id: ConnectionId("\(source)->\(target)"),
            source: ComponentId(source),
            target: ComponentId(target),
            kind: kind
        )
    }

    private func threat(_ name: String, _ source: String, _ score: Int) -> ReportThreat {
        ReportThreat(
            threatId: name,
            name: name,
            description: "",
            severityLabel: "High",
            riskScore: score,
            riskLevel: "high",
            strideLabels: [],
            mitreTechniqueIds: [],
            sourceName: source,
            sourceKind: "Component",
            controls: [],
            pathwayMitigationLabels: []
        )
    }

    private func build(
        components: [Component],
        connections: [Connection],
        threats: [ReportThreat] = []
    ) -> (paths: [ReportAttackPath], notListed: Int) {
        AttackPaths.build(
            components: components,
            connections: connections,
            zones: [],
            threats: threats,
            nameOf: { $0.value }
        )
    }

    @Test func aModelWithNoSensitiveComponentHasNoPath() {
        let built = build(
            components: [component("a"), component("b")],
            connections: [flow("a", "b")]
        )
        #expect(built.paths.isEmpty)
    }

    @Test func aPathRunsFromAnEntryComponentToASensitiveOne() throws {
        let built = build(
            components: [component("actor"), component("api"), component("store", .restricted)],
            connections: [flow("actor", "api"), flow("api", "store")]
        )
        let path = try #require(built.paths.first)
        #expect(path.startName == "actor")
        #expect(path.endName == "store")
        #expect(path.hops.map(\.componentName) == ["actor", "api", "store"])
    }

    @Test func aHopNamesTheFlowKindItArrivedBy() throws {
        let built = build(
            components: [component("actor"), component("store", .restricted)],
            connections: [flow("actor", "store", .ipc)]
        )
        let path = try #require(built.paths.first)
        #expect(path.hops.first?.flowKindLabel == nil)
        #expect(path.hops.last?.flowKindLabel == "Local IPC")
    }

    @Test func aPathScoresAtItsWorstHop() throws {
        let built = build(
            components: [component("actor"), component("store", .restricted)],
            connections: [flow("actor", "store")],
            threats: [threat("weak", "actor", 3), threat("bad", "store", 12)]
        )
        let path = try #require(built.paths.first)
        #expect(path.worstScore == 12)
        #expect(path.hops.last?.worstThreatName == "bad")
    }

    @Test func aCycleStopsTheWalk() {
        let built = build(
            components: [component("a"), component("b"), component("store", .restricted)],
            connections: [flow("a", "b"), flow("b", "a"), flow("b", "store")]
        )
        #expect(built.paths.isEmpty == false)
        #expect(built.paths.allSatisfy { $0.hops.count <= AttackPaths.maximumHops })
    }

    @Test func theMarkdownStatesWhatItDidNotList() {
        let lines = MarkdownAttackPaths.lines([], notListed: 4)
        #expect(lines.contains("4 further paths are not listed."))
    }

    @Test func theMarkdownDrawsThePath() {
        let lines = MarkdownAttackPaths.lines(
            [
                ReportAttackPath(
                    startName: "actor",
                    endName: "store",
                    hops: [
                        ReportAttackPathHop(
                            componentName: "actor",
                            flowKindLabel: nil,
                            worstThreatName: nil,
                            riskScore: 0,
                            reducedBy: []
                        ),
                        ReportAttackPathHop(
                            componentName: "store",
                            flowKindLabel: "Local IPC",
                            worstThreatName: "Raw device read",
                            riskScore: 12,
                            reducedBy: ["ClearanceKit"]
                        )
                    ],
                    worstScore: 12
                )
            ],
            notListed: 0
        )
        #expect(lines.first == "## Attack paths")
        #expect(lines.contains("### actor \u{2192} store (worst 12)"))
        #expect(lines.contains("1. actor"))
        #expect(lines.contains("2. store, by Local IPC \u{2014} Raw device read (12), reduced by ClearanceKit"))
    }
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd ThreatModelKit && swift test --filter AttackPathTests`
Expected: FAIL, the builder returns nothing.

- [ ] **Step 3: Write the walk**

Replace `AttackPaths.swift`:

```swift
/// Every way in, to everything worth taking.
///
/// Spec section 9. The report already scores each threat on its own; this is
/// the story that joins them, which is what a reader asks for first: how does
/// an attacker get from the outside to the restricted data, and what stops
/// them on the way.
public enum AttackPaths {
    /// A path longer than this is a story nobody reads.
    public static let maximumHops = 6
    /// The report lists this many, worst first, and states what it dropped.
    public static let maximumPaths = 20

    public static func build(
        components: [Component],
        connections: [Connection],
        zones: [Zone],
        threats: [ReportThreat],
        nameOf: (ComponentId) -> String
    ) -> (paths: [ReportAttackPath], notListed: Int) {
        guard components.isEmpty == false else { return ([], 0) }

        var forward: [ComponentId: [Connection]] = [:]
        var hasInbound: Set<ComponentId> = []
        for connection in connections {
            forward[connection.source, default: []].append(connection)
            hasInbound.insert(connection.target)
        }

        let publicZones = zones.filter { $0.networkZone == .publicZone }
        let starts = components.filter { component in
            hasInbound.contains(component.id) == false
                || ZoneContainment.zone(holding: component.centre, in: publicZones) != nil
        }
        let ends = Set(
            components
                .filter { $0.effectiveSensitivity == .confidential || $0.effectiveSensitivity == .restricted }
                .map(\.id)
        )
        guard ends.isEmpty == false else { return ([], 0) }

        var found: [ReportAttackPath] = []

        func walk(
            _ component: ComponentId,
            _ arrivedBy: Connection?,
            _ hops: [ReportAttackPathHop],
            _ seen: Set<ComponentId>
        ) {
            let hop = self.hop(
                component,
                arrivedBy: arrivedBy,
                threats: threats,
                nameOf: nameOf
            )
            let path = hops + [hop]

            if ends.contains(component) && path.count > 1 {
                found.append(
                    ReportAttackPath(
                        startName: path[0].componentName,
                        endName: hop.componentName,
                        hops: path,
                        worstScore: path.map(\.riskScore).max() ?? 0
                    )
                )
            }
            guard path.count < maximumHops else { return }

            for next in forward[component] ?? [] where seen.contains(next.target) == false {
                walk(next.target, next, path, seen.union([next.target]))
            }
        }

        for start in starts {
            walk(start.id, nil, [], [start.id])
        }

        let ordered = found.sorted { left, right in
            if left.worstScore != right.worstScore { return left.worstScore > right.worstScore }
            if left.hops.count != right.hops.count { return left.hops.count < right.hops.count }
            return left.endName < right.endName
        }

        return (
            Array(ordered.prefix(maximumPaths)),
            max(0, ordered.count - maximumPaths)
        )
    }

    /// One step of the story: what the attacker reached, how they got there,
    /// and the worst thing that is still open on it.
    private static func hop(
        _ component: ComponentId,
        arrivedBy: Connection?,
        threats: [ReportThreat],
        nameOf: (ComponentId) -> String
    ) -> ReportAttackPathHop {
        let name = nameOf(component)
        let worst = threats
            .filter { $0.sourceKind == "Component" && $0.sourceName == name }
            .max { $0.riskScore < $1.riskScore }

        return ReportAttackPathHop(
            componentName: name,
            flowKindLabel: arrivedBy.map(\.kind.label),
            worstThreatName: worst?.name,
            riskScore: worst?.riskScore ?? 0,
            reducedBy: worst?.pathwayMitigationLabels ?? []
        )
    }
}
```

- [ ] **Step 4: Write the Markdown section**

Replace `MarkdownAttackPaths.swift`:

```swift
/// The report's Attack paths section.
///
/// WARNING: the walk is bounded. When it drops a path the section says so,
/// because a silent truncation reads as full coverage.
public enum MarkdownAttackPaths {
    public static func lines(_ paths: [ReportAttackPath], notListed: Int) -> [String] {
        guard paths.isEmpty == false || notListed > 0 else { return [] }

        var lines = ["## Attack paths", ""]
        for path in paths {
            lines.append("### \(path.startName) \u{2192} \(path.endName) (worst \(path.worstScore))")
            lines.append("")
            for (index, hop) in path.hops.enumerated() {
                var line = "\(index + 1). \(hop.componentName)"
                if let kind = hop.flowKindLabel { line += ", by \(kind)" }
                if let threat = hop.worstThreatName {
                    line += " \u{2014} \(threat) (\(hop.riskScore))"
                }
                if hop.reducedBy.isEmpty == false {
                    line += ", reduced by \(hop.reducedBy.joined(separator: ", "))"
                }
                lines.append(line)
            }
            lines.append("")
        }
        if notListed > 0 {
            lines.append("\(notListed) further paths are not listed.")
            lines.append("")
        }
        return lines
    }
}
```

- [ ] **Step 5: Run the suite**

Run: `cd ThreatModelKit && swift test`
Expected: PASS. Update the expected Markdown in `ReportRendererTests`.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/reporting \
        ThreatModelKit/Tests/UnitTests/AttackPathTests.swift
git -c commit.gpgsign=false commit -m "feat: the report shows the attack paths from an entry to sensitive data"
```

---

### Task 16: the report rolls the threats up

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/ReportRollups.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownRollups.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ReportRollupTests.swift`

**Interfaces:**
- Consumes: `ReportRollups.build` and `MarkdownRollups.lines`, both minted by
  Task 13. **Do not change `Report.swift`, `BuildThreatModelReport.swift` or
  `ExportModelAsMarkdown.swift`.**

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/ReportRollupTests.swift`:

```swift
import Testing
import ThreatModelKit

struct ReportRollupTests {
    private func threat(
        _ name: String,
        source: String,
        kind: String = "Component",
        score: Int,
        level: String = "high"
    ) -> ReportThreat {
        ReportThreat(
            threatId: name,
            name: name,
            description: "",
            severityLabel: "High",
            riskScore: score,
            riskLevel: level,
            strideLabels: [],
            mitreTechniqueIds: [],
            sourceName: source,
            sourceKind: kind,
            controls: [],
            pathwayMitigationLabels: []
        )
    }

    private func zone(_ name: String, _ holds: [String]) -> ReportZone {
        ReportZone(
            name: name,
            networkZoneLabel: "Private Zone",
            networkTypeLabel: "Generic Network",
            componentNames: holds,
            riskReductionPercent: 20
        )
    }

    @Test func aZoneRollupCountsWhatItHolds() throws {
        let tables = ReportRollups.build(
            threats: [
                threat("a", source: "api", score: 12, level: "critical"),
                threat("b", source: "api", score: 4, level: "medium"),
                threat("c", source: "outside", score: 8)
            ],
            zones: [zone("App VPC", ["api"])]
        )
        let rollup = try #require(tables.byZone.first)
        #expect(rollup.zoneName == "App VPC")
        #expect(rollup.componentCount == 1)
        #expect(rollup.worstScore == 12)
        #expect(rollup.byLevel.contains { $0.label == "critical" && $0.count == 1 })
    }

    @Test func theTopResidualTableHoldsTheWorstTwentyWorstFirst() {
        let threats = (1...25).map { threat("t\($0)", source: "api", score: $0) }
        let tables = ReportRollups.build(threats: threats, zones: [])
        #expect(tables.topResidual.count == 20)
        #expect(tables.topResidual.first?.riskScore == 25)
        #expect(tables.topResidual.last?.riskScore == 6)
    }

    @Test func theCountsBySourceKindNameTheThree() {
        let tables = ReportRollups.build(
            threats: [
                threat("a", source: "api", kind: "Component", score: 4),
                threat("b", source: "api->db", kind: "Connection", score: 4),
                threat("c", source: "vpc", kind: "Zone", score: 4),
                threat("d", source: "api", kind: "Component", score: 4)
            ],
            zones: []
        )
        #expect(tables.bySourceKind == [
            ReportCount(label: "Component", count: 2),
            ReportCount(label: "Connection", count: 1),
            ReportCount(label: "Zone", count: 1)
        ])
    }

    @Test func theMarkdownWritesNothingForAnEmptyModel() {
        #expect(MarkdownRollups.lines(ReportRollupTables.empty).isEmpty)
    }

    @Test func theMarkdownDrawsTheTopResidualTable() {
        let lines = MarkdownRollups.lines(
            ReportRollupTables(
                byZone: [],
                topResidual: [threat("Raw device read", source: "store", score: 12, level: "critical")],
                bySourceKind: []
            )
        )
        #expect(lines.contains("## Top residual risk"))
        #expect(lines.contains("| Raw device read | store | 12 | 12 | critical |"))
    }
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd ThreatModelKit && swift test --filter ReportRollupTests`
Expected: FAIL, the builder returns empty tables.

- [ ] **Step 3: Write the builder**

Replace `ReportRollups.swift`:

```swift
/// The three tables a reader looks at before the threat list.
///
/// Spec section 10. A report of 147 threats with no rollup is a file nobody
/// reads to the end.
public enum ReportRollups {
    /// The top residual table holds this many rows.
    public static let topCount = 20

    public static func build(threats: [ReportThreat], zones: [ReportZone]) -> ReportRollupTables {
        ReportRollupTables(
            byZone: zones.map { zone in
                let held = Set(zone.componentNames)
                let raised = threats.filter { held.contains($0.sourceName) }
                return ReportZoneRollup(
                    zoneName: zone.name,
                    componentCount: zone.componentNames.count,
                    byLevel: counts(of: raised.map(\.riskLevel)),
                    worstScore: raised.map(\.riskScore).max() ?? 0
                )
            },
            topResidual: Array(
                threats.sorted { left, right in
                    if left.riskScore != right.riskScore { return left.riskScore > right.riskScore }
                    return left.name < right.name
                }.prefix(topCount)
            ),
            bySourceKind: ["Component", "Connection", "Zone"].compactMap { kind in
                let count = threats.filter { $0.sourceKind == kind }.count
                return count > 0 ? ReportCount(label: kind, count: count) : nil
            }
        )
    }

    /// Worst level first, which is the order the risk ladder runs in.
    private static func counts(of levels: [String]) -> [ReportCount] {
        var held: [String: Int] = [:]
        for level in levels { held[level, default: 0] += 1 }
        return ["critical", "high", "medium", "low"].compactMap { level in
            held[level].map { ReportCount(label: level, count: $0) }
        }
    }
}
```

- [ ] **Step 4: Write the Markdown section**

Replace `MarkdownRollups.swift`:

```swift
/// The report's rollup tables, above the component list.
public enum MarkdownRollups {
    public static func lines(_ tables: ReportRollupTables) -> [String] {
        var lines: [String] = []

        if tables.bySourceKind.isEmpty == false {
            lines.append("## Where the risk sits")
            lines.append("")
            for count in tables.bySourceKind {
                lines.append("- \(count.label): \(count.count)")
            }
            lines.append("")
        }

        if tables.byZone.isEmpty == false {
            lines.append("## By zone")
            lines.append("")
            lines.append("| Zone | Components | Worst | Levels |")
            lines.append("| --- | --- | --- | --- |")
            for rollup in tables.byZone {
                let levels = rollup.byLevel.map { "\($0.label) \($0.count)" }.joined(separator: ", ")
                lines.append(
                    "| \(Markdown.cell(rollup.zoneName)) | \(rollup.componentCount)"
                        + " | \(rollup.worstScore) | \(levels.isEmpty ? "none" : levels) |"
                )
            }
            lines.append("")
        }

        if tables.topResidual.isEmpty == false {
            lines.append("## Top residual risk")
            lines.append("")
            lines.append("| Threat | Raised by | Residual | Before controls | Level |")
            lines.append("| --- | --- | --- | --- | --- |")
            for threat in tables.topResidual {
                lines.append(
                    "| \(Markdown.cell(threat.name)) | \(Markdown.cell(threat.sourceName))"
                        + " | \(threat.riskScore) | \(threat.inherentScore) | \(threat.riskLevel) |"
                )
            }
            lines.append("")
        }

        return lines
    }
}
```

- [ ] **Step 5: Run the suite**

Run: `cd ThreatModelKit && swift test`
Expected: PASS. Update the expected Markdown in `ReportRendererTests`.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/reporting \
        ThreatModelKit/Tests/UnitTests/ReportRollupTests.swift
git -c commit.gpgsign=false commit -m "feat: the report rolls the threats up by zone, by source and by residual risk"
```

---

## Wave 5: the whole thing, end to end

### Task 17: an endpoint model, from source to report

This task runs alone. It proves the seventeen commits work as one thing, and
it is the acceptance test a reviewer reads first.

**Files:**
- Create: `ThreatModelKit/Tests/AcceptanceTests/ModellingAnEndpointTests.swift`
- Modify: `README.md`
- Test: the file above

**Interfaces:**
- Consumes: every type the sixteen tasks before it produced. It adds none.

- [ ] **Step 1: Write the failing acceptance test**

Create `ThreatModelKit/Tests/AcceptanceTests/ModellingAnEndpointTests.swift`.
Read `ModellingFromSourceTests.swift` first and follow how it builds its
dependencies; the test below states what to prove, in that file's shape.

```swift
import Testing
import ThreatModelKit
import ArchitectureDSL
import TestSupport

/// A macOS endpoint, and the security product that protects it.
///
/// This is the model that showed every fault the spec lists. It is here so a
/// change that brings one back fails a test somebody reads.
struct ModellingAnEndpointTests {
    private let architecture = """
    system "Endpoint" {
      zone "user" {
        boundary = "privilege"
        name     = "uid 501"

        component "devtools" {
          technology = "aws-ec2"
          data       = "internal"
          runs_as    = "user"
        }
      }

      zone "root" {
        boundary = "privilege"
        name     = "uid 0"

        component "guard" {
          technology = "aws-waf"
          runs_as    = "root"
        }

        component "secrets" {
          technology = "aws-ec2"
          data       = "confidential"
          runs_as    = "root"

          asset "ssh-keys" { data = "restricted" }
        }
      }

      flow devtools -> secrets {
        kind        = "ipc"
        description = "XPC call to read a secret"
      }

      mitigates guard -> secrets {
        threats         = ["credential-theft"]
        reduces_risk_by = 80
      }
    }
    """

    private func model() throws -> ThreatModel {
        let models = InMemoryThreatModelGateway()
        let response = ImportArchitecture(
            models: models,
            catalogue: CatalogueFixture.catalogue(),
            sources: HclArchitectureSource(),
            layout: LayOutModel()
        ).execute(ImportArchitectureRequest(text: architecture))
        guard case .imported = response else {
            Issue.record("the import refused the file: \(response)")
            throw ImportFault.refused
        }
        return models.current()
    }

    private enum ImportFault: Error { case refused }

    @Test func theLocalFlowRaisesNoThreatAboutTls() throws {
        let resolved = ThreatResolver(model: try model(), catalogue: CatalogueFixture.catalogue()).resolve()
        #expect(resolved.contains { $0.threat.id == ThreatId("connection-mitm") } == false)
    }

    @Test func theSecretStoreScoresAtItsHighestAsset() throws {
        let resolved = ThreatResolver(model: try model(), catalogue: CatalogueFixture.catalogue()).resolve()
        let threat = try #require(
            resolved.first { $0.source.id == "component:secrets" && $0.threat.id == ThreatId("misconfiguration") }
        )
        #expect(threat.sensitivity == .restricted)
    }

    @Test func theProtectorLowersTheThreatItAnswers() throws {
        let resolved = ThreatResolver(model: try model(), catalogue: CatalogueFixture.catalogue()).resolve()
        let threat = try #require(
            resolved.first { $0.source.id == "component:secrets" && $0.threat.id == ThreatId("credential-theft") }
        )
        #expect(threat.mitigatedByComponents.first?.protectorName == "WAF")
        #expect(threat.score.value < threat.scoreBeforeControls)
    }

    @Test func theReportNamesTheProtectionDependencyAndTheAttackPath() throws {
        let models = InMemoryThreatModelGateway(try model())
        let report = BuildThreatModelReport(models: models, catalogue: CatalogueFixture.catalogue())
            .execute(BuildThreatModelReportRequest()).report

        #expect(report.protectionDependencies.contains { $0.protectorName == "WAF" })
        #expect(report.attackPaths.contains { $0.endName == "secrets" })
        #expect(report.rollups.topResidual.isEmpty == false)
    }

    @Test func aCompileAnswersEveryThreatItRaisesAndKeepsARecommendation() throws {
        let controls = """
        controls for "Endpoint" {
          threat "credential-theft" on component "secrets" {
            recommendation "Protect the managed preferences plist" { }
          }
        }
        """
        let response = CompileControls(
            catalogue: CatalogueFixture.catalogue(),
            architectureSources: HclArchitectureSource(),
            controlsSources: HclControlsSource(),
            layout: LayOutModel()
        ).execute(
            CompileControlsRequest(architectureText: architecture, controlsText: controls)
        )

        guard case .compiled(let text, _, _, let stale) = response else {
            Issue.record("the compile refused the files: \(response)")
            return
        }
        #expect(stale == 0)
        #expect(text.contains("recommendation \"Protect the managed preferences plist\""))
        #expect(text.contains("on flow \"devtools->secrets\""))
    }
}
```

- [ ] **Step 2: Run it and see it fail or pass**

Run: `cd ThreatModelKit && swift test --filter ModellingAnEndpointTests`
Expected: PASS. A failure here names a real gap between two tasks, not a gap
in this test. Fix the task that owns the file, never this test.

- [ ] **Step 3: Run everything**

```bash
cd ThreatModelKit && swift test && cd ..
xcodebuild clean -project threatmodeller.xcodeproj -scheme threatmodeller \
  -destination 'platform=macOS'
xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller \
  -destination 'platform=macOS'
scripts/update-catalogue.sh verify
```
Expected: three green runs. Report any failure at the top of the hand-over,
with the exact message.

- [ ] **Step 4: State the new shapes in `README.md`**

Add one short section, "Modelling a host", stating four things: a flow states
its kind, a zone states its boundary, a component states the privilege it runs
at, and one component may mitigate a named threat on another. Point at
`docs/LANGUAGE.md` for the grammar and at `libraries/endpoint.lib` for the
endpoint technologies.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Tests/AcceptanceTests/ModellingAnEndpointTests.swift README.md
git -c commit.gpgsign=false commit -m "test: an endpoint model, from source to report"
```

- [ ] **Step 6: Open the pull request**

```bash
git push -u origin endpoint-modelling
gh pr create --title "Host and endpoint modelling" \
  --body "Implements docs/superpowers/specs/2026-09-10-endpoint-modelling-design.md."
```

---

## What this plan leaves out

State these limits in the pull request body. Each one is a decision, not an
oversight.

| Left out | Why |
| --- | --- |
| A report diff between two runs | It needs a stored baseline artefact, which is its own design. |
| Per-asset threat resolution | One asset list per component removes the "one blob" fault. Resolving a threat per asset is a different design. |
| Editing an asset in the window | An asset is written in the `.arch` file and read by the report. |
| The four new sections in the PDF | The PDF gains the inherent score only. The sections are Markdown and report tree. |
| Answer templates and answer reuse | Task 8 removes the reason for most of them: a local flow stops raising the threats a user was answering `not_applicable` dozens of times. |
| Keeping comments through a rewrite | `description` on a flow and on a zone carries the rationale as data the model keeps. |
