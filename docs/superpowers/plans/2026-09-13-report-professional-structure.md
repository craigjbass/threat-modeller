# Report Professional Structure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the exported report explain itself — an executive summary, a methodology built from the model's own numbers, a diagram legend, a glossary, a curated findings section, a narrative attack paths section, and the bulk moved to appendices.

**Architecture:** `BuildThreatModelReport` computes every new value type and puts it on `Report`. A `Markdown*` writer prints it and decides nothing. `ExportModelAsHtml` converts that Markdown, so the HTML page follows with no change of its own. The second PDF renderer is deleted and the PDF is printed from the HTML page.

**Tech Stack:** Swift 6, SwiftUI, the `ThreatModelKit` local package, the `Testing` framework (`import Testing`, `@Test`, `#expect`), AppKit and WebKit in the application target.

**Spec:** `docs/superpowers/specs/2026-09-13-report-professional-structure-design.md`

## Global Constraints

- Write every comment, commit message and document in the project's plain register: short common words, active voice, present tense, one word for one meaning. The one exception is the executive summary's own generated sentences, which read as a consultancy deliverable.
- Test first. Write the failing test, run it, see it fail, then write the code.
- `ReportThreat.riskLevel` holds `RiskLevel.rawValue` — `"low"`, `"medium"`, `"high"`, `"critical"` — not the label. Rank it with `RiskLevel(rawValue:)?.rank`.
- `ThreatModel.effectiveRiskTolerance` is the tolerance a check uses: what the file states, or `.low`.
- Every new property on an existing public struct takes a default value in the initialiser. The initialisers have many call sites in the tests, and a new required parameter breaks all of them.
- Run the package tests with `cd ThreatModelKit && swift test`. Filter with `--filter <SuiteName>`.
- After adding a file to `ThreatModelKit`, run `xcodebuild clean -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'` once before the application tests.
- The report tests assert with `contains`, not line-for-line equality. Keep that style.
- Commit after every task.

---

## File structure

| File | Responsibility |
| --- | --- |
| `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/Report.swift` | the new value types and the new properties on `Report` |
| `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/AttackPaths.swift` | the curation: five paths, the shared prefix, the dropped list |
| `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/BuildThreatModelReport.swift` | builds every new value type |
| `.../reporting/usecase/MarkdownExecutiveSummary.swift` | prints `## Executive summary` |
| `.../reporting/usecase/MarkdownMethodology.swift` | prints `## Methodology` and `### Diagram legend` |
| `.../reporting/usecase/MarkdownFindings.swift` | prints `## Findings` |
| `.../reporting/usecase/MarkdownGlossary.swift` | prints `## Glossary` |
| `.../reporting/usecase/MarkdownAttackPaths.swift` | prints `## Attack paths` and `## Appendix C` |
| `.../reporting/usecase/MarkdownRecommendations.swift` | prints `## Recommendations`, worst first |
| `.../reporting/usecase/ExportModelAsMarkdown.swift` | the section order and the appendix headings |
| `threatmodeller/reporting/HtmlPdfPrinter.swift` | prints an HTML page to PDF data with `WKWebView` |

---

### Task 1: The report carries the risk tolerance and the findings cut

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/Report.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/BuildThreatModelReport.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ReportFindingsTests.swift` (create)

**Interfaces:**
- Consumes: `ThreatModel.effectiveRiskTolerance`, `RiskLevel.rank`, `ReportThreat.riskLevel`.
- Produces: `ReportFindingsCut(above:notShown:)`, `Report.findings: ReportFindingsCut`, `Report.toleranceLabel: String`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/ReportFindingsTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

/// The findings section carries what sits above the project's tolerance, and
/// says how many more qualified than it could show.
struct ReportFindingsTests {
    private func threat(_ name: String, _ score: Int, _ level: String) -> ReportThreat {
        ReportThreat(
            threatId: name,
            name: name,
            description: "",
            severityLabel: "High",
            riskScore: score,
            riskLevel: level,
            strideLabels: [],
            mitreTechniqueIds: [],
            sourceName: "EC2",
            sourceKind: "Component",
            controls: [],
            pathwayMitigationLabels: []
        )
    }

    @Test func keepsOnlyWhatRanksAboveTheTolerance() {
        let cut = ReportFindingsCut.build(
            from: [threat("a", 13, "critical"), threat("b", 9, "high"), threat("c", 5, "medium")],
            tolerance: .medium
        )

        #expect(cut.above.map(\.name) == ["a", "b"])
        #expect(cut.notShown == 0)
    }

    @Test func keepsNothingWhenEveryThreatSitsInsideTheTolerance() {
        let cut = ReportFindingsCut.build(
            from: [threat("a", 13, "critical"), threat("b", 5, "medium")],
            tolerance: .critical
        )

        #expect(cut.above.isEmpty)
        #expect(cut.notShown == 0)
    }

    @Test func showsTwentyFiveAndCountsTheRest() {
        let many = (1...30).map { threat("t\($0)", 13, "critical") }

        let cut = ReportFindingsCut.build(from: many, tolerance: .low)

        #expect(cut.above.count == 25)
        #expect(cut.notShown == 5)
    }

    @Test func theReportCarriesTheCutAndTheToleranceLabel() {
        let app = TestDependencies()
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "restricted")
        )

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report

        #expect(report.toleranceLabel == "Low")
        #expect(report.findings.above.isEmpty == false)
    }
}
```

- [ ] **Step 2: Run the test and see it fail**

Run: `cd ThreatModelKit && swift test --filter ReportFindingsTests`
Expected: FAIL, `cannot find 'ReportFindingsCut' in scope`.

- [ ] **Step 3: Add the type and the properties**

In `Report.swift`, above `public struct ReportSummary`:

```swift
/// The threats a findings section shows, and how many more qualified.
///
/// A model whose tolerance is `low` raises nearly every threat above it, so
/// the cut is bounded. The overflow count is stated, because a silent
/// truncation reads as full coverage.
public struct ReportFindingsCut: Equatable, Sendable {
    /// The threats above the project's tolerance, worst first.
    public let above: [ReportThreat]
    /// How many more qualified and did not fit.
    public let notShown: Int

    public init(above: [ReportThreat] = [], notShown: Int = 0) {
        self.above = above
        self.notShown = notShown
    }

    /// The most a findings section shows.
    public static let maximum = 25

    /// Every threat ranking above the tolerance, worst first, capped.
    public static func build(from threats: [ReportThreat], tolerance: RiskLevel) -> ReportFindingsCut {
        let qualifying = threats.filter { threat in
            guard let level = RiskLevel(rawValue: threat.riskLevel) else { return false }
            return level.rank > tolerance.rank
        }
        return ReportFindingsCut(
            above: Array(qualifying.prefix(maximum)),
            notShown: max(0, qualifying.count - maximum)
        )
    }
}
```

In `Report`, add two stored properties beside `assumedMitigations`:

```swift
    /// The threats a reader must act on, and how many more qualified.
    public let findings: ReportFindingsCut
    /// The risk level the project accepts, for the reader.
    public let toleranceLabel: String
```

Add them to the initialiser, with defaults, and assign them:

```swift
        findings: ReportFindingsCut = ReportFindingsCut(),
        toleranceLabel: String = RiskLevel.low.label
```

```swift
        self.findings = findings
        self.toleranceLabel = toleranceLabel
```

- [ ] **Step 4: Build the cut in the use case**

In `BuildThreatModelReport.execute`, after `let threats = assessment.threats.map { … }`:

```swift
        let tolerance = model.effectiveRiskTolerance
```

and in the `Report(…)` call, beside `assumedMitigations: assumedMitigations`:

```swift
                findings: ReportFindingsCut.build(from: threats, tolerance: tolerance),
                toleranceLabel: tolerance.label
```

- [ ] **Step 5: Run the tests and see them pass**

Run: `cd ThreatModelKit && swift test --filter ReportFindingsTests`
Expected: PASS, 4 tests.

Run: `cd ThreatModelKit && swift test`
Expected: PASS, every suite.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/reporting ThreatModelKit/Tests/UnitTests/ReportFindingsTests.swift
git commit -m "feat: the report knows what sits above the project's risk tolerance"
```

---

### Task 2: The executive summary's data

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/Report.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/BuildThreatModelReport.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ReportExecutiveSummaryTests.swift` (create)

**Interfaces:**
- Consumes: `ReportFindingsCut` from Task 1, `Report.threats`, `Report.recommendations`, `ReportThreat.controls`, `ReportThreat.compensating`.
- Produces: `ReportExecutiveSummary(verdict:toleranceLabel:topRisks:topActions:unansweredCount:totalThreats:)` and `Report.executiveSummary`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/ReportExecutiveSummaryTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

/// The summary a reader gets in ninety seconds: the verdict, the worst three,
/// the first three things to do, and how much is unanswered.
struct ReportExecutiveSummaryTests {
    private func threat(
        _ name: String,
        _ score: Int,
        _ level: String,
        controls: [ReportControl] = [],
        compensating: [ReportCompensatingControl] = []
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
            sourceName: "EC2",
            sourceKind: "Component",
            controls: controls,
            pathwayMitigationLabels: [],
            compensating: compensating
        )
    }

    private func recommendation(_ text: String, _ score: Int) -> ReportRecommendation {
        ReportRecommendation(
            text: text,
            note: nil,
            threatName: "t",
            sourceName: "EC2",
            riskScore: score
        )
    }

    @Test func statesNoExposureWhenNothingRanksAboveTheTolerance() {
        let summary = ReportExecutiveSummary.build(
            threats: [threat("a", 5, "medium")],
            recommendations: [],
            tolerance: .medium
        )

        #expect(summary.verdict == "No residual exposure exceeds the project's medium risk tolerance.")
    }

    @Test func namesOneExposureInTheSingular() {
        let summary = ReportExecutiveSummary.build(
            threats: [threat("a", 13, "critical"), threat("b", 5, "medium")],
            recommendations: [],
            tolerance: .medium
        )

        #expect(
            summary.verdict
                == "The assessment identifies a single residual exposure above the project's medium risk tolerance."
        )
    }

    @Test func countsManyExposures() {
        let summary = ReportExecutiveSummary.build(
            threats: [threat("a", 13, "critical"), threat("b", 9, "high")],
            recommendations: [],
            tolerance: .medium
        )

        #expect(
            summary.verdict
                == "The assessment identifies 2 residual exposures above the project's medium risk tolerance."
        )
    }

    @Test func takesTheWorstThreeRisksAndTheWorstThreeActions() {
        let summary = ReportExecutiveSummary.build(
            threats: [
                threat("a", 13, "critical"),
                threat("b", 9, "high"),
                threat("c", 8, "high"),
                threat("d", 7, "medium")
            ],
            recommendations: [
                recommendation("one", 13),
                recommendation("two", 9),
                recommendation("three", 8),
                recommendation("four", 7)
            ],
            tolerance: .low
        )

        #expect(summary.topRisks.map(\.name) == ["a", "b", "c"])
        #expect(summary.topActions.map(\.text) == ["one", "two", "three"])
    }

    @Test func countsAThreatNobodyHasAnswered() {
        let answered = threat(
            "answered", 9, "high",
            controls: [ReportControl(description: "c", isImplemented: true, statusLabel: "Implemented")]
        )
        let compensated = threat(
            "compensated", 9, "high",
            compensating: [ReportCompensatingControl(label: "watched", reducesRiskBy: 40, rationale: "why")]
        )
        let open = threat(
            "open", 9, "high",
            controls: [ReportControl(description: "c", isImplemented: false, statusLabel: "Not implemented")]
        )

        let summary = ReportExecutiveSummary.build(
            threats: [answered, compensated, open],
            recommendations: [],
            tolerance: .low
        )

        #expect(summary.unansweredCount == 1)
        #expect(summary.totalThreats == 3)
    }

    @Test func theReportCarriesIt() {
        let app = TestDependencies()
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "restricted")
        )

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report

        #expect(report.executiveSummary.totalThreats == report.threats.count)
        #expect(report.executiveSummary.toleranceLabel == "Low")
    }
}
```

- [ ] **Step 2: Run the test and see it fail**

Run: `cd ThreatModelKit && swift test --filter ReportExecutiveSummaryTests`
Expected: FAIL, `cannot find 'ReportExecutiveSummary' in scope`.

- [ ] **Step 3: Add the type**

In `Report.swift`, below `ReportFindingsCut`:

```swift
/// What a reader who reads one page reads.
///
/// The sentences here are the one place the report writes as a consultancy
/// deliverable rather than in the tool's plain register.
public struct ReportExecutiveSummary: Equatable, Sendable {
    /// One sentence on the posture, against the project's own tolerance.
    public let verdict: String
    public let toleranceLabel: String
    /// The three worst threats by residual score.
    public let topRisks: [ReportThreat]
    /// The three recommendations answering the worst threats.
    public let topActions: [ReportRecommendation]
    /// How many threats hold no answered control and no compensating control.
    public let unansweredCount: Int
    public let totalThreats: Int

    public init(
        verdict: String = "",
        toleranceLabel: String = RiskLevel.low.label,
        topRisks: [ReportThreat] = [],
        topActions: [ReportRecommendation] = [],
        unansweredCount: Int = 0,
        totalThreats: Int = 0
    ) {
        self.verdict = verdict
        self.toleranceLabel = toleranceLabel
        self.topRisks = topRisks
        self.topActions = topActions
        self.unansweredCount = unansweredCount
        self.totalThreats = totalThreats
    }

    /// How many of each the summary names.
    public static let topCount = 3

    public static func build(
        threats: [ReportThreat],
        recommendations: [ReportRecommendation],
        tolerance: RiskLevel
    ) -> ReportExecutiveSummary {
        let cut = ReportFindingsCut.build(from: threats, tolerance: tolerance)
        let above = cut.above.count + cut.notShown
        let word = tolerance.label.lowercased()

        let verdict: String
        switch above {
        case 0:
            verdict = "No residual exposure exceeds the project's \(word) risk tolerance."
        case 1:
            verdict = "The assessment identifies a single residual exposure above"
                + " the project's \(word) risk tolerance."
        default:
            verdict = "The assessment identifies \(above) residual exposures above"
                + " the project's \(word) risk tolerance."
        }

        return ReportExecutiveSummary(
            verdict: verdict,
            toleranceLabel: tolerance.label,
            topRisks: Array(threats.prefix(topCount)),
            topActions: Array(
                recommendations.sorted { $0.riskScore > $1.riskScore }.prefix(topCount)
            ),
            unansweredCount: threats.filter { isUnanswered($0) }.count,
            totalThreats: threats.count
        )
    }

    /// A threat nobody has answered: no control carries an answer, and no
    /// compensating control stands.
    private static func isUnanswered(_ threat: ReportThreat) -> Bool {
        guard threat.compensating.isEmpty else { return false }
        return threat.controls.contains { $0.statusLabel != "Not implemented" } == false
    }
}
```

- [ ] **Step 4: Put it on `Report` and build it**

In `Report`, beside `findings`:

```swift
    /// The one page a reader reads first.
    public let executiveSummary: ReportExecutiveSummary
```

In the initialiser: `executiveSummary: ReportExecutiveSummary = ReportExecutiveSummary(),` and `self.executiveSummary = executiveSummary`.

In `BuildThreatModelReport.execute`, the recommendations are built inline in the `Report(…)` call. Lift them to a local first, above the `return`:

```swift
        let recommendations = RecommendationsReport.build(
            threats: threats,
            recommendations: model.recommendations
        )
```

Use `recommendations: recommendations` in the `Report(…)` call, and add:

```swift
                executiveSummary: ReportExecutiveSummary.build(
                    threats: threats,
                    recommendations: recommendations,
                    tolerance: tolerance
                ),
```

- [ ] **Step 5: Run the tests and see them pass**

Run: `cd ThreatModelKit && swift test --filter ReportExecutiveSummaryTests`
Expected: PASS, 6 tests.

Run: `cd ThreatModelKit && swift test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/reporting ThreatModelKit/Tests/UnitTests/ReportExecutiveSummaryTests.swift
git commit -m "feat: the report states a verdict, the worst risks and the first actions"
```

---

### Task 3: The executive summary section

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownExecutiveSummary.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/ExportModelAsMarkdown.swift`
- Test: `ThreatModelKit/Tests/UnitTests/MarkdownExecutiveSummaryTests.swift` (create)

**Interfaces:**
- Consumes: `ReportExecutiveSummary` from Task 2, `ReportComponent.sensitivityLabel`, `ReportComponent.privilegeLabel`.
- Produces: `MarkdownExecutiveSummary.lines(_ summary: ReportExecutiveSummary, components: [ReportComponent]) -> [String]`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/MarkdownExecutiveSummaryTests.swift`:

```swift
import Testing
import ThreatModelKit

struct MarkdownExecutiveSummaryTests {
    private func threat(_ name: String, _ score: Int, _ level: String, on element: String) -> ReportThreat {
        ReportThreat(
            threatId: name,
            name: name,
            description: "",
            severityLabel: "Critical",
            riskScore: score,
            riskLevel: level,
            strideLabels: [],
            mitreTechniqueIds: [],
            sourceName: element,
            sourceKind: "Component",
            controls: [],
            pathwayMitigationLabels: []
        )
    }

    private let pipeline = ReportComponent(
        id: "build",
        name: "Build pipeline",
        technologyId: "github-actions",
        categoryId: "ci",
        sensitivityLabel: "Confidential",
        zoneName: nil,
        privilegeLabel: "Root"
    )

    @Test func writesTheVerdictTheRisksTheActionsAndTheCount() {
        let summary = ReportExecutiveSummary(
            verdict: "The assessment identifies a single residual exposure above the project's medium risk tolerance.",
            toleranceLabel: "Medium",
            topRisks: [threat("Package substitution", 13, "critical", on: "Build pipeline")],
            topActions: [
                ReportRecommendation(
                    text: "Pin every package to a hash",
                    note: nil,
                    threatName: "Package substitution",
                    sourceName: "Build pipeline",
                    riskScore: 13
                )
            ],
            unansweredCount: 47,
            totalThreats: 330
        )

        let lines = MarkdownExecutiveSummary.lines(summary, components: [pipeline])
        let text = lines.joined(separator: "\n")

        #expect(lines.first == "## Executive summary")
        #expect(text.contains("a single residual exposure"))
        #expect(text.contains("**Highest residual risk**"))
        #expect(text.contains("1. Package substitution \u{2014} Build pipeline \u{2014} Critical (13 of 16)."))
        #expect(text.contains("The element holds Confidential data and runs as Root."))
        #expect(text.contains("**Do first**"))
        #expect(text.contains("1. Pin every package to a hash \u{2014} answers Package substitution on Build pipeline (13 of 16)."))
        #expect(text.contains("47 of 330 threats hold no answered control and no compensating control."))
    }

    @Test func writesTheVerdictAloneWhenNothingIsWorthListing() {
        let summary = ReportExecutiveSummary(
            verdict: "No residual exposure exceeds the project's low risk tolerance.",
            toleranceLabel: "Low",
            unansweredCount: 0,
            totalThreats: 0
        )

        let text = MarkdownExecutiveSummary.lines(summary, components: []).joined(separator: "\n")

        #expect(text.contains("No residual exposure"))
        #expect(text.contains("**Highest residual risk**") == false)
        #expect(text.contains("**Do first**") == false)
        #expect(text.contains("0 of 0 threats hold no answered control and no compensating control."))
    }

    @Test func namesNoSensitivityForAnElementTheInventoryDoesNotHold() {
        let summary = ReportExecutiveSummary(
            verdict: "v",
            topRisks: [threat("t", 9, "high", on: "Nowhere")],
            totalThreats: 1
        )

        let text = MarkdownExecutiveSummary.lines(summary, components: []).joined(separator: "\n")

        #expect(text.contains("1. t \u{2014} Nowhere \u{2014} High (9 of 16)."))
        #expect(text.contains("The element holds") == false)
    }
}
```

- [ ] **Step 2: Run the test and see it fail**

Run: `cd ThreatModelKit && swift test --filter MarkdownExecutiveSummaryTests`
Expected: FAIL, `cannot find 'MarkdownExecutiveSummary' in scope`.

- [ ] **Step 3: Write the writer**

Create `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownExecutiveSummary.swift`:

```swift
/// The report's Executive summary section.
///
/// This section writes for a reader who reads one page and no more, so its
/// sentences read as a deliverable rather than in the tool's plain register.
/// Every number in it comes from `ReportExecutiveSummary`; this writer counts
/// nothing itself.
public enum MarkdownExecutiveSummary {
    public static func lines(
        _ summary: ReportExecutiveSummary,
        components: [ReportComponent]
    ) -> [String] {
        var lines = ["## Executive summary", "", summary.verdict, ""]

        if summary.topRisks.isEmpty == false {
            lines.append("**Highest residual risk**")
            lines.append("")
            for (index, threat) in summary.topRisks.enumerated() {
                let level = RiskLevel(rawValue: threat.riskLevel)?.label ?? threat.riskLevel
                lines.append(
                    "\(index + 1). \(threat.name) \u{2014} \(threat.sourceName)"
                        + " \u{2014} \(level) (\(threat.riskScore) of 16)."
                )
                if let element = components.first(where: { $0.name == threat.sourceName }) {
                    lines.append(
                        "   The element holds \(element.sensitivityLabel) data"
                            + " and runs as \(element.privilegeLabel)."
                    )
                }
            }
            lines.append("")
        }

        if summary.topActions.isEmpty == false {
            lines.append("**Do first**")
            lines.append("")
            for (index, action) in summary.topActions.enumerated() {
                lines.append(
                    "\(index + 1). \(action.text) \u{2014} answers \(action.threatName)"
                        + " on \(action.sourceName) (\(action.riskScore) of 16)."
                )
            }
            lines.append("")
        }

        lines.append(
            "\(summary.unansweredCount) of \(summary.totalThreats) threats hold"
                + " no answered control and no compensating control."
        )
        lines.append("")
        return lines
    }
}
```

- [ ] **Step 4: Write the section into the report**

In `ExportModelAsMarkdown.execute`, immediately after the catalogue tag block and before `lines += summary(report.summary)`:

```swift
        lines += MarkdownExecutiveSummary.lines(
            report.executiveSummary,
            components: report.components
        )
```

- [ ] **Step 5: Run the tests and see them pass**

Run: `cd ThreatModelKit && swift test --filter MarkdownExecutiveSummaryTests`
Expected: PASS, 3 tests.

Run: `cd ThreatModelKit && swift test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/reporting ThreatModelKit/Tests/UnitTests/MarkdownExecutiveSummaryTests.swift
git commit -m "feat: the report opens with an executive summary"
```

---

### Task 4: The methodology's data

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/Report.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/BuildThreatModelReport.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ReportMethodologyTests.swift` (create)

**Interfaces:**
- Consumes: `RiskScore.level`, `ControlCoverage.maxReduction`, `Likelihood.allTiers`, `ReportZone.riskReductionPercent`.
- Produces: `ReportLevelThreshold(label:lowest:highest:)`, `ReportMethodology(levelThresholds:controlCapPercent:likelihoodTiers:zoneReductions:toleranceLabel:)`, `Report.methodology`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/ReportMethodologyTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

/// The methodology states the numbers this run actually used, so a reader can
/// check the arithmetic rather than trust it.
struct ReportMethodologyTests {
    @Test func derivesTheThresholdsFromTheScoringItself() {
        let methodology = ReportMethodology.build(zones: [], tolerance: .low)

        #expect(
            methodology.levelThresholds.map(\.label) == ["Low", "Medium", "High", "Critical"]
        )
        #expect(methodology.levelThresholds[0].lowest == 1)
        #expect(methodology.levelThresholds[0].highest == 3)
        #expect(methodology.levelThresholds[1].lowest == 4)
        #expect(methodology.levelThresholds[1].highest == 7)
        #expect(methodology.levelThresholds[2].lowest == 8)
        #expect(methodology.levelThresholds[2].highest == 11)
        #expect(methodology.levelThresholds[3].lowest == 12)
        #expect(methodology.levelThresholds[3].highest == 16)
    }

    @Test func statesTheControlCapAndTheLikelihoodTiers() {
        let methodology = ReportMethodology.build(zones: [], tolerance: .medium)

        #expect(methodology.controlCapPercent == 70)
        #expect(methodology.likelihoodTiers.map(\.label) == ["Commodity", "Targeted", "Research"])
        #expect(methodology.likelihoodTiers.map(\.count) == [100, 60, 25])
        #expect(methodology.toleranceLabel == "Medium")
    }

    @Test func namesOnlyTheZonesThatReduceRisk() {
        let reducing = ReportZone(
            name: "Private",
            networkZoneLabel: "Private",
            networkTypeLabel: "Generic",
            componentNames: [],
            riskReductionPercent: 30
        )
        let plain = ReportZone(
            name: "Public",
            networkZoneLabel: "Public",
            networkTypeLabel: "Generic",
            componentNames: [],
            riskReductionPercent: nil
        )

        let methodology = ReportMethodology.build(zones: [reducing, plain], tolerance: .low)

        #expect(methodology.zoneReductions.map(\.label) == ["Private"])
        #expect(methodology.zoneReductions.map(\.count) == [30])
    }

    @Test func theReportCarriesIt() {
        let app = TestDependencies()
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "restricted")
        )

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report

        #expect(report.methodology.controlCapPercent == 70)
        #expect(report.methodology.toleranceLabel == "Low")
    }
}
```

- [ ] **Step 2: Run the test and see it fail**

Run: `cd ThreatModelKit && swift test --filter ReportMethodologyTests`
Expected: FAIL, `cannot find 'ReportMethodology' in scope`.

- [ ] **Step 3: Add the types**

In `Report.swift`, below `ReportExecutiveSummary`:

```swift
/// One risk level and the scores that reach it.
public struct ReportLevelThreshold: Equatable, Sendable {
    public let label: String
    public let lowest: Int
    public let highest: Int

    public init(label: String, lowest: Int, highest: Int) {
        self.label = label
        self.lowest = lowest
        self.highest = highest
    }
}

/// What the numbers in this report mean, taken from the code that made them.
public struct ReportMethodology: Equatable, Sendable {
    public let levelThresholds: [ReportLevelThreshold]
    /// The most the implemented controls take off, as a percentage.
    public let controlCapPercent: Int
    /// Each likelihood tier and its factor. The `count` is a percentage, not
    /// a tally.
    public let likelihoodTiers: [ReportCount]
    /// Each zone that reduces risk, and by how much. The `count` is a
    /// percentage, not a tally.
    public let zoneReductions: [ReportCount]
    public let toleranceLabel: String

    public init(
        levelThresholds: [ReportLevelThreshold] = [],
        controlCapPercent: Int = 0,
        likelihoodTiers: [ReportCount] = [],
        zoneReductions: [ReportCount] = [],
        toleranceLabel: String = RiskLevel.low.label
    ) {
        self.levelThresholds = levelThresholds
        self.controlCapPercent = controlCapPercent
        self.likelihoodTiers = likelihoodTiers
        self.zoneReductions = zoneReductions
        self.toleranceLabel = toleranceLabel
    }

    /// The highest score the base arithmetic can reach: four severity ranks
    /// multiplied by four sensitivity ranks.
    public static let highestScore = 16

    /// Reads the thresholds out of `RiskScore.level` rather than repeating
    /// them. A second copy would disagree with the scoring the day a
    /// threshold moves.
    public static func build(zones: [ReportZone], tolerance: RiskLevel) -> ReportMethodology {
        var lowestByLevel: [RiskLevel: Int] = [:]
        var highestByLevel: [RiskLevel: Int] = [:]
        for score in 1...highestScore {
            let level = RiskScore(value: score).level
            if lowestByLevel[level] == nil { lowestByLevel[level] = score }
            highestByLevel[level] = score
        }

        return ReportMethodology(
            levelThresholds: RiskLevel.allCases
                .sorted { $0.rank < $1.rank }
                .compactMap { level in
                    guard let lowest = lowestByLevel[level],
                          let highest = highestByLevel[level] else { return nil }
                    return ReportLevelThreshold(label: level.label, lowest: lowest, highest: highest)
                },
            controlCapPercent: Int((ControlCoverage.maxReduction * 100).rounded()),
            likelihoodTiers: Likelihood.allTiers.map {
                ReportCount(label: $0.label, count: Int(($0.factor * 100).rounded()))
            },
            zoneReductions: zones.compactMap { zone in
                zone.riskReductionPercent.map { ReportCount(label: zone.name, count: $0) }
            },
            toleranceLabel: tolerance.label
        )
    }
}
```

`RiskLevel` must be `Hashable` for the dictionaries. It already conforms to `Equatable` through its raw value; add `Hashable` to its declaration in `assessment/domain/RiskScore.swift`:

```swift
public enum RiskLevel: String, CaseIterable, Equatable, Hashable, Sendable {
```

- [ ] **Step 4: Put it on `Report` and build it**

In `Report`, beside `executiveSummary`:

```swift
    /// What the scores mean, and how they were reached.
    public let methodology: ReportMethodology
```

In the initialiser: `methodology: ReportMethodology = ReportMethodology(),` and `self.methodology = methodology`.

In `BuildThreatModelReport.execute`, in the `Report(…)` call:

```swift
                methodology: ReportMethodology.build(zones: zones, tolerance: tolerance),
```

- [ ] **Step 5: Run the tests and see them pass**

Run: `cd ThreatModelKit && swift test --filter ReportMethodologyTests`
Expected: PASS, 4 tests.

Run: `cd ThreatModelKit && swift test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit ThreatModelKit/Tests/UnitTests/ReportMethodologyTests.swift
git commit -m "feat: the report carries the scale it scored against"
```

---

### Task 5: The methodology section and the diagram legend

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownMethodology.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/ExportModelAsMarkdown.swift`
- Test: `ThreatModelKit/Tests/UnitTests/MarkdownMethodologyTests.swift` (create)

**Interfaces:**
- Consumes: `ReportMethodology` from Task 4.
- Produces: `MarkdownMethodology.lines(_ methodology: ReportMethodology) -> [String]`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/MarkdownMethodologyTests.swift`:

```swift
import Testing
import ThreatModelKit

struct MarkdownMethodologyTests {
    private let methodology = ReportMethodology(
        levelThresholds: [
            ReportLevelThreshold(label: "Low", lowest: 1, highest: 3),
            ReportLevelThreshold(label: "Critical", lowest: 12, highest: 16)
        ],
        controlCapPercent: 70,
        likelihoodTiers: [ReportCount(label: "Targeted", count: 60)],
        zoneReductions: [ReportCount(label: "Private", count: 30)],
        toleranceLabel: "Medium"
    )

    @Test func statesTheArithmeticInTheOrderTheStagesRun() {
        let text = MarkdownMethodology.lines(methodology).joined(separator: "\n")

        #expect(text.hasPrefix("## Methodology"))
        #expect(text.contains("severity rank multiplied by the data sensitivity rank"))
        #expect(text.contains("| Low | 1 | 3 |"))
        #expect(text.contains("| Critical | 12 | 16 |"))
        #expect(text.contains("Private reduces the risk of what it holds by 30%."))
        #expect(text.contains("capped at 70%"))
        #expect(text.contains("Targeted 60%"))
        #expect(text.contains("The project's risk tolerance is Medium."))
        #expect(text.contains("A score never falls below 1."))
    }

    @Test func omitsTheZoneLineWhenNoZoneReducesRisk() {
        let text = MarkdownMethodology.lines(
            ReportMethodology(
                levelThresholds: [ReportLevelThreshold(label: "Low", lowest: 1, highest: 3)],
                controlCapPercent: 70,
                likelihoodTiers: [],
                zoneReductions: [],
                toleranceLabel: "Low"
            )
        ).joined(separator: "\n")

        #expect(text.contains("reduces the risk of what it holds") == false)
    }

    @Test func writesTheDiagramLegend() {
        let text = MarkdownMethodology.lines(methodology).joined(separator: "\n")

        #expect(text.contains("### Diagram legend"))
        #expect(text.contains("| Red, orange, yellow, green |"))
        #expect(text.contains("| Purple dashed line |"))
        #expect(text.contains("| Dashed guard marker |"))
        #expect(text.contains("| Badge on an element |"))
    }
}
```

- [ ] **Step 2: Run the test and see it fail**

Run: `cd ThreatModelKit && swift test --filter MarkdownMethodologyTests`
Expected: FAIL, `cannot find 'MarkdownMethodology' in scope`.

- [ ] **Step 3: Write the writer**

Create `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownMethodology.swift`:

```swift
/// The report's Methodology section, and the legend for its pictures.
///
/// The stages are written in the order `ThreatResolver` runs them, so a reader
/// can follow one threat through the arithmetic from end to end.
public enum MarkdownMethodology {
    public static func lines(_ methodology: ReportMethodology) -> [String] {
        var lines = ["## Methodology", ""]

        lines.append(
            "A threat's base score is its severity rank multiplied by the data"
                + " sensitivity rank of what it puts at risk, from 1 to"
                + " \(ReportMethodology.highestScore)."
        )
        lines.append("")

        lines.append("| Level | Lowest score | Highest score |")
        lines.append("| --- | --- | --- |")
        for threshold in methodology.levelThresholds {
            lines.append("| \(threshold.label) | \(threshold.lowest) | \(threshold.highest) |")
        }
        lines.append("")

        lines.append("The stages run in this order, and each one takes the score the one before it left.")
        lines.append("")

        for zone in methodology.zoneReductions {
            lines.append("1. \(Markdown.cell(zone.label)) reduces the risk of what it holds by \(zone.count)%.")
        }
        if methodology.zoneReductions.isEmpty == false {
            lines.append(
                "   A flow between two private zones takes the smaller of the two reductions."
            )
        }

        lines.append(
            "1. The implemented controls take off their share of the score,"
                + " capped at \(methodology.controlCapPercent)%. The share is the"
                + " implemented controls divided by the applicable ones, and a"
                + " control marked not applicable leaves the divisor. A control"
                + " marked accepted stays in the divisor and lowers nothing."
        )
        lines.append(
            "1. A pathway mitigation and a `mitigates` edge each take off the"
                + " percentage they state. Two that answer one threat give the"
                + " stronger reduction, never the sum."
        )
        if methodology.likelihoodTiers.isEmpty == false {
            let tiers = methodology.likelihoodTiers
                .map { "\($0.label) \($0.count)%" }
                .joined(separator: ", ")
            lines.append(
                "1. The likelihood multiplies the score: \(tiers), or the"
                    + " percentage a finding states."
            )
        }
        lines.append(
            "1. A compensating control multiplies the score by the reduction it"
                + " states. Two give the stronger reduction, never the sum."
        )
        lines.append("1. A score never falls below 1.")
        lines.append("")

        lines.append(
            "The project's risk tolerance is \(methodology.toleranceLabel)."
                + " A likelihood finding answers a threat only when the threat"
                + " sits at or below that level."
        )
        lines.append(
            "\"If the assumptions hold\" is the same arithmetic with every"
                + " assumed `mitigates` edge counted as in place."
        )
        lines.append("")

        lines += legend()
        return lines
    }

    /// Fixed text. Every row states what the drawing code does, not what a
    /// reader might expect it to do.
    private static func legend() -> [String] {
        [
            "### Diagram legend",
            "",
            "| Mark | Meaning |",
            "| --- | --- |",
            "| Red, orange, yellow, green | Critical, High, Medium, Low |",
            "| Dashed tinted box | a zone, tinted by the worst risk inside it |",
            "| Purple dashed line | a control protecting an element; it carries no data |",
            "| Grey boundary crossing | a trust boundary crossing with no guard on it |",
            "| Dashed guard marker | a guard the model assumes rather than adopts |",
            "| Thick ring | the element the picture is about |",
            "| Badge on an element | how many threats are still open on that element |",
            "| Arrowhead | the direction the data flows |",
            ""
        ]
    }
}
```

- [ ] **Step 4: Check every legend row against the drawing code**

Read `ThreatModelKit/Sources/DiagramRendering/DiagramDrawing.swift`,
`DiagramBuilderParts.swift` and `ThreatDiagrams.swift`. Confirm each row:

- `DiagramColour.forLevel` gives red, orange, yellow and green.
- The zone box draws with `dash: [2, 4]` and a tint.
- The protects line uses `.protects` with `dash: [5, 4]`.
- A boundary run with no guards draws in `.quiet`.
- An assumed guard marker draws with `dash: [3, 3]`.
- `DiagramBuilder.focusWidth` thickens the element the picture is about.
- `ThreatDiagrams` writes the badge caption about threats still open.

Correct any row the code contradicts, and correct the test with it. Do not
leave a row the code does not do.

- [ ] **Step 5: Write the section into the report**

In `ExportModelAsMarkdown.execute`, after the `MarkdownRollups.lines(…)` and
`MarkdownThreatPictures.lines(…)` calls:

```swift
        lines += MarkdownMethodology.lines(report.methodology)
```

- [ ] **Step 6: Run the tests and see them pass**

Run: `cd ThreatModelKit && swift test --filter MarkdownMethodologyTests`
Expected: PASS, 3 tests.

Run: `cd ThreatModelKit && swift test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/reporting ThreatModelKit/Tests/UnitTests/MarkdownMethodologyTests.swift
git commit -m "feat: the report states its scale, its arithmetic and its legend"
```

---

### Task 6: The findings section

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownThreatStanza.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownFindings.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/ExportModelAsMarkdown.swift`
- Test: `ThreatModelKit/Tests/UnitTests/MarkdownFindingsTests.swift` (create)

**Interfaces:**
- Consumes: `ReportFindingsCut` from Task 1, `Report.toleranceLabel`.
- Produces: `MarkdownThreatStanza.lines(_ threat: ReportThreat) -> [String]` and `MarkdownFindings.lines(_ cut: ReportFindingsCut, toleranceLabel: String) -> [String]`.

The stanza the `## Threats` section writes today is lifted out of
`ExportModelAsMarkdown.threats(_:)` into `MarkdownThreatStanza`, unchanged, so
the findings section and the threat register write one stanza and not two that
drift.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/MarkdownFindingsTests.swift`:

```swift
import Testing
import ThreatModelKit

struct MarkdownFindingsTests {
    private func threat(_ name: String, _ score: Int) -> ReportThreat {
        ReportThreat(
            threatId: name,
            name: name,
            description: "It can happen.",
            severityLabel: "Critical",
            riskScore: score,
            riskLevel: "critical",
            strideLabels: ["Tampering"],
            mitreTechniqueIds: ["T1195"],
            sourceName: "Build pipeline",
            sourceKind: "Component",
            controls: [ReportControl(description: "Pin hashes", isImplemented: false)],
            pathwayMitigationLabels: []
        )
    }

    @Test func writesEveryThreatAboveToleranceInFull() {
        let lines = MarkdownFindings.lines(
            ReportFindingsCut(above: [threat("Package substitution", 13)], notShown: 0),
            toleranceLabel: "Medium"
        )
        let text = lines.joined(separator: "\n")

        #expect(lines.first == "## Findings")
        #expect(text.contains("Every threat above the project's Medium risk tolerance."))
        #expect(text.contains("### Package substitution \u{2014} Build pipeline"))
        #expect(text.contains("It can happen."))
        #expect(text.contains("- Severity: Critical"))
        #expect(text.contains("- STRIDE: Tampering"))
        #expect(text.contains("- MITRE ATT&CK: T1195"))
        #expect(text.contains("- [ ] Pin hashes \u{2014} Not implemented"))
    }

    @Test func saysHowManyMoreQualified() {
        let text = MarkdownFindings.lines(
            ReportFindingsCut(above: [threat("a", 13)], notShown: 5),
            toleranceLabel: "Low"
        ).joined(separator: "\n")

        #expect(text.contains("5 more qualify and are in Appendix A."))
    }

    @Test func saysSoWhenNothingSitsAboveTheTolerance() {
        let text = MarkdownFindings.lines(
            ReportFindingsCut(above: [], notShown: 0),
            toleranceLabel: "High"
        ).joined(separator: "\n")

        #expect(text.contains("No threat sits above the project's High risk tolerance."))
        #expect(text.contains("###") == false)
    }
}
```

- [ ] **Step 2: Run the test and see it fail**

Run: `cd ThreatModelKit && swift test --filter MarkdownFindingsTests`
Expected: FAIL, `cannot find 'MarkdownFindings' in scope`.

- [ ] **Step 3: Lift the stanza out of `ExportModelAsMarkdown`**

Create `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownThreatStanza.swift`.
Move the body of the `for threat in threats` loop from
`ExportModelAsMarkdown.threats(_:)` into it, with no change of wording:

```swift
/// One threat, written the same way wherever the report writes it.
///
/// The findings section and the threat register both write this, so a threat
/// a reader finds in one reads the same in the other.
public enum MarkdownThreatStanza {
    public static func lines(_ threat: ReportThreat) -> [String] {
        var lines: [String] = []
        lines.append("### \(threat.name) \u{2014} \(threat.sourceName)")
        lines.append("")
        lines.append(threat.description)
        lines.append("")
        lines.append("- Raised by: \(threat.sourceKind)")
        lines.append("- Severity: \(threat.severityLabel)")
        if threat.inherentScore == threat.riskScore {
            lines.append("- Risk: \(threat.riskLevel) (\(threat.riskScore))")
        } else {
            lines.append(
                "- Risk: \(threat.riskLevel) (\(threat.riskScore)),"
                    + " before controls \(threat.inherentScore)"
            )
        }
        // A finding is worth printing even when the stage floored at 1
        // both before and after: the tier, the rationale and the
        // sources are the evidence this block exists to publish, and a
        // threat that already scored 1 must not hide them.
        if threat.likelihoodRationale != nil || threat.likelihoodLabel != Likelihood.commodity.label {
            let scoreChanged = threat.scoreBeforeLikelihood != threat.riskScore
            lines.append(
                "- Likelihood: \(threat.likelihoodLabel)"
                    + (scoreChanged
                        ? " (\(threat.scoreBeforeLikelihood) \u{2192} \(threat.riskScore))"
                        : "")
            )
            if let rationale = threat.likelihoodRationale {
                lines.append("  - Rationale: \(rationale)")
            }
            lines += Markdown.sourceLines(threat.likelihoodSources)
        }
        if let decision = threat.severityDecision {
            lines.append("- Severity decided: \(decision.fromLabel) \u{2192} \(decision.toLabel)")
            lines.append("  - Rationale: \(decision.rationale)")
            lines += Markdown.sourceLines(decision.sources)
        }
        if threat.scoreIfAssumptionsHold != threat.riskScore {
            lines.append("- If the assumptions hold: \(threat.scoreIfAssumptionsHold)")
        }
        if threat.strideLabels.isEmpty == false {
            lines.append("- STRIDE: \(threat.strideLabels.joined(separator: ", "))")
        }
        if threat.mitreTechniqueIds.isEmpty == false {
            lines.append("- MITRE ATT&CK: \(threat.mitreTechniqueIds.joined(separator: ", "))")
        }
        for compensating in threat.compensating {
            lines.append(
                "- Compensated by: \(compensating.label)"
                    + " (\(compensating.reducesRiskBy)%,"
                    + " \(threat.scoreBeforeCompensation) \u{2192} \(threat.riskScore))"
            )
            lines.append("  - Rationale: \(compensating.rationale)")
            lines += Markdown.sourceLines(compensating.sources)
        }
        if threat.pathwayMitigationLabels.isEmpty == false {
            lines.append(
                "- Answered upstream by: "
                    + threat.pathwayMitigationLabels.joined(separator: ", ")
            )
        }
        if threat.mitigatedByComponentLabels.isEmpty == false {
            lines.append(
                "- Reduced by: "
                    + threat.mitigatedByComponentLabels.joined(separator: ", ")
            )
        }
        if threat.controls.isEmpty == false {
            lines.append("")
            lines.append("Controls:")
            lines.append("")
            for control in threat.controls {
                lines.append(
                    "- [\(control.isImplemented ? "x" : " ")] \(control.description)"
                        + " \u{2014} \(control.statusLabel)"
                )
            }
        }
        lines.append("")
        return lines
    }
}
```

`Markdown` is `internal` to the module, so `MarkdownThreatStanza.lines` must be
`public` while its body uses `Markdown` — that is allowed inside one module.

Replace the loop body in `ExportModelAsMarkdown.threats(_:)` with:

```swift
        for threat in threats {
            lines += MarkdownThreatStanza.lines(threat)
        }
```

- [ ] **Step 4: Write the findings writer**

Create `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownFindings.swift`:

```swift
/// The report's Findings section: what a reader must act on.
///
/// WARNING: the cut is bounded. When it drops a qualifying threat the section
/// says so and names where the rest are, because a silent truncation reads as
/// full coverage.
public enum MarkdownFindings {
    public static func lines(_ cut: ReportFindingsCut, toleranceLabel: String) -> [String] {
        var lines = ["## Findings", ""]

        guard cut.above.isEmpty == false else {
            lines.append("No threat sits above the project's \(toleranceLabel) risk tolerance.")
            lines.append("")
            return lines
        }

        var opening = "Every threat above the project's \(toleranceLabel) risk tolerance."
        if cut.notShown > 0 {
            opening += " \(cut.notShown) more qualify and are in Appendix A."
        }
        lines.append(opening)
        lines.append("")

        for threat in cut.above {
            lines += MarkdownThreatStanza.lines(threat)
        }
        return lines
    }
}
```

- [ ] **Step 5: Write the section into the report**

In `ExportModelAsMarkdown.execute`, after the `MarkdownMethodology.lines(…)` call:

```swift
        lines += MarkdownFindings.lines(report.findings, toleranceLabel: report.toleranceLabel)
```

- [ ] **Step 6: Run the tests and see them pass**

Run: `cd ThreatModelKit && swift test --filter MarkdownFindingsTests`
Expected: PASS, 3 tests.

Run: `cd ThreatModelKit && swift test`
Expected: PASS. The existing report tests still find `## Threats`, because the
register has not moved yet.

- [ ] **Step 7: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/reporting ThreatModelKit/Tests/UnitTests/MarkdownFindingsTests.swift
git commit -m "feat: the report puts what needs action in front of the register"
```

---

### Task 7: The glossary

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownGlossary.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/ExportModelAsMarkdown.swift`
- Test: `ThreatModelKit/Tests/UnitTests/MarkdownGlossaryTests.swift` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: `MarkdownGlossary.lines() -> [String]`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/MarkdownGlossaryTests.swift`:

```swift
import Testing
import ThreatModelKit

struct MarkdownGlossaryTests {
    @Test func definesEveryWordTheReportUsesForItself() {
        let lines = MarkdownGlossary.lines()
        let text = lines.joined(separator: "\n")

        #expect(lines.first == "## Glossary")
        for word in [
            "Answered", "Implemented", "Not applicable", "Accepted",
            "Compensating control", "Pathway mitigation", "Mitigates edge",
            "Adopted", "Assumed", "Inherent score", "Residual score",
            "If the assumptions hold", "Risk tolerance", "Prior", "Raised by"
        ] {
            #expect(text.contains("| \(word) |"), "the glossary does not define \(word)")
        }
    }
}
```

- [ ] **Step 2: Run the test and see it fail**

Run: `cd ThreatModelKit && swift test --filter MarkdownGlossaryTests`
Expected: FAIL, `cannot find 'MarkdownGlossary' in scope`.

- [ ] **Step 3: Write the writer**

Create `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownGlossary.swift`:

```swift
/// The report's Glossary section.
///
/// Every word here is one the tool uses for itself. A reader who has never
/// used the tool needs them to read the rest of the report.
public enum MarkdownGlossary {
    public static func lines() -> [String] {
        var lines = ["## Glossary", "", "| Word | What it means |", "| --- | --- |"]
        for entry in entries {
            lines.append("| \(entry.word) | \(entry.meaning) |")
        }
        lines.append("")
        return lines
    }

    private static let entries: [(word: String, meaning: String)] = [
        ("Answered", "a person has said something about the threat: a control is implemented, not applicable or accepted, or a compensating control stands"),
        ("Implemented", "the control is in place, and it lowers the score"),
        ("Not applicable", "the control does not apply here, and it leaves the share the other controls divide"),
        ("Accepted", "the team takes the risk. The threat counts as answered and the score stays where it is"),
        ("Not implemented", "nobody has answered the control. This is what a control starts as"),
        ("Compensating control", "something the team does that answers a threat the catalogue's own controls do not"),
        ("Pathway mitigation", "a reduction a component upstream gives to everything downstream of it"),
        ("Mitigates edge", "one element stated to lower a named threat on another element"),
        ("Adopted", "the mitigation is in place today"),
        ("Assumed", "the team plans the mitigation and has not put it in place. It never lowers the residual score"),
        ("Inherent score", "the score before any control lowered it"),
        ("Residual score", "the score left after every stage has run. This is the number a reader acts on"),
        ("If the assumptions hold", "the residual score with every assumed mitigation counted as in place"),
        ("Risk tolerance", "the risk level the project accepts. A likelihood finding answers a threat only at or below it"),
        ("Prior", "the likelihood the threat catalogue states before anybody finds evidence about this system"),
        ("Raised by", "what put the threat in the model: a component, a connection or a zone")
    ]
}
```

- [ ] **Step 4: Write the section into the report**

In `ExportModelAsMarkdown.execute`, after the `MarkdownAssumptions.lines(…)` call:

```swift
        lines += MarkdownGlossary.lines()
```

- [ ] **Step 5: Run the tests and see them pass**

Run: `cd ThreatModelKit && swift test --filter MarkdownGlossaryTests`
Expected: PASS, 1 test.

Run: `cd ThreatModelKit && swift test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/reporting ThreatModelKit/Tests/UnitTests/MarkdownGlossaryTests.swift
git commit -m "feat: the report defines the words it uses for itself"
```

---

### Task 8: The attack path curation

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/AttackPaths.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/ReportSections.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/Report.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/BuildThreatModelReport.swift`
- Modify: `ThreatModelKit/Tests/UnitTests/AttackPathTests.swift`
- Test: `ThreatModelKit/Tests/UnitTests/AttackPathCurationTests.swift` (create)

**Interfaces:**
- Consumes: `ReportThreat.likelihoodLabel`.
- Produces: `ReportAttackPath.likelihoodLabel`, `ReportAttackPathSummary(startName:endName:worstScore:)`, `AttackPaths.build(…) -> (paths: [ReportAttackPath], prefix: [ReportAttackPathHop], notListed: [ReportAttackPathSummary])`, `Report.attackPathPrefix`, `Report.attackPathsNotListed: [ReportAttackPathSummary]`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/AttackPathCurationTests.swift`:

```swift
import Testing
import ThreatModelKit

/// Five paths a reader can follow, not twenty that repeat their first two
/// steps.
struct AttackPathCurationTests {
    private func hop(_ name: String, _ score: Int = 0) -> ReportAttackPathHop {
        ReportAttackPathHop(
            componentName: name,
            flowKindLabel: nil,
            worstThreatName: nil,
            riskScore: score,
            reducedBy: []
        )
    }

    private func path(_ names: [String], _ worst: Int) -> ReportAttackPath {
        ReportAttackPath(
            startName: names.first ?? "",
            endName: names.last ?? "",
            hops: names.map { hop($0) },
            worstScore: worst
        )
    }

    @Test func statesTheSharedPrefixOnceAndTrimsItFromEveryPath() {
        let curated = AttackPaths.curate([
            path(["Internet", "GUI", "Store"], 13),
            path(["Internet", "GUI", "Queue"], 9)
        ])

        #expect(curated.prefix.map(\.componentName) == ["Internet", "GUI"])
        #expect(curated.paths[0].hops.map(\.componentName) == ["Store"])
        #expect(curated.paths[1].hops.map(\.componentName) == ["Queue"])
    }

    @Test func statesNoPrefixWhenThePathsShareNoFirstHop() {
        let curated = AttackPaths.curate([
            path(["Internet", "Store"], 13),
            path(["Laptop", "Store"], 9)
        ])

        #expect(curated.prefix.isEmpty)
        #expect(curated.paths[0].hops.count == 2)
    }

    @Test func keepsAPathTheTrimWouldEmpty() {
        let curated = AttackPaths.curate([
            path(["Internet", "GUI"], 13),
            path(["Internet", "GUI", "Store"], 9)
        ])

        // Trimming the whole of the first path leaves no story, so the
        // prefix stops one hop short of the shortest path.
        #expect(curated.prefix.map(\.componentName) == ["Internet"])
        #expect(curated.paths[0].hops.map(\.componentName) == ["GUI"])
        #expect(curated.paths[1].hops.map(\.componentName) == ["GUI", "Store"])
    }

    @Test func listsFiveAndSummarisesTheRest() {
        let many = (1...8).map { path(["Internet", "Target\($0)"], 16 - $0) }

        let curated = AttackPaths.curate(many)

        #expect(curated.paths.count == 5)
        #expect(curated.notListed.count == 3)
        #expect(curated.notListed.first?.endName == "Target6")
        #expect(curated.notListed.first?.worstScore == 10)
    }

    @Test func writesNoPrefixForASinglePath() {
        let curated = AttackPaths.curate([path(["Internet", "GUI", "Store"], 13)])

        #expect(curated.prefix.isEmpty)
        #expect(curated.paths[0].hops.count == 3)
    }
}
```

- [ ] **Step 2: Run the test and see it fail**

Run: `cd ThreatModelKit && swift test --filter AttackPathCurationTests`
Expected: FAIL, `type 'AttackPaths' has no member 'curate'`.

- [ ] **Step 3: Add the summary type and the likelihood label**

In `ReportSections.swift`, beside `ReportAttackPath`:

```swift
/// A path the narrative did not carry, in one line.
public struct ReportAttackPathSummary: Equatable, Sendable {
    public let startName: String
    public let endName: String
    public let worstScore: Int

    public init(startName: String, endName: String, worstScore: Int) {
        self.startName = startName
        self.endName = endName
        self.worstScore = worstScore
    }
}
```

Add to `ReportAttackPath`, with a default so every call site keeps working:

```swift
    /// The likelihood tier of the hop that set `worstScore`. Empty when no
    /// threat set it.
    public let likelihoodLabel: String
```

```swift
        worstScore: Int,
        likelihoodLabel: String = ""
```

```swift
        self.likelihoodLabel = likelihoodLabel
```

- [ ] **Step 4: Write the curation**

In `AttackPaths.swift`, change `maximumPaths`:

```swift
    /// The narrative carries this many, worst first, and states what it left.
    public static let narratedPaths = 5
    /// The trace keeps this many before it curates them.
    public static let maximumPaths = 20
```

Add the curation, above `hop(_:arrivedBy:threats:nameOf:)`:

```swift
    /// Turns a list of traced paths into a story: five paths, the steps they
    /// all share stated once, and a line for everything left.
    public static func curate(
        _ ordered: [ReportAttackPath]
    ) -> (paths: [ReportAttackPath], prefix: [ReportAttackPathHop], notListed: [ReportAttackPathSummary]) {
        let listed = Array(ordered.prefix(narratedPaths))
        let notListed = ordered.dropFirst(narratedPaths).map {
            ReportAttackPathSummary(
                startName: $0.startName,
                endName: $0.endName,
                worstScore: $0.worstScore
            )
        }
        guard listed.count > 1 else { return (listed, [], Array(notListed)) }

        let prefix = sharedPrefix(of: listed)
        guard prefix.isEmpty == false else { return (listed, [], Array(notListed)) }

        let trimmed = listed.map { path in
            ReportAttackPath(
                startName: path.startName,
                endName: path.endName,
                hops: Array(path.hops.dropFirst(prefix.count)),
                worstScore: path.worstScore,
                likelihoodLabel: path.likelihoodLabel
            )
        }
        return (trimmed, prefix, Array(notListed))
    }

    /// The hops every path starts with, by component name.
    ///
    /// It stops one hop short of the shortest path: a path trimmed to nothing
    /// is no longer a story.
    private static func sharedPrefix(of paths: [ReportAttackPath]) -> [ReportAttackPathHop] {
        guard let shortest = paths.map(\.hops.count).min(), shortest > 1 else { return [] }

        var length = 0
        while length < shortest - 1 {
            let name = paths[0].hops[length].componentName
            guard paths.allSatisfy({ $0.hops[length].componentName == name }) else { break }
            length += 1
        }
        return Array(paths[0].hops.prefix(length))
    }
```

- [ ] **Step 5: Give each path its likelihood and return the curation**

In `build`, the `found.append(…)` call sets the worst score. Give it the
likelihood of the hop that set the score. Replace the `found.append` block with:

```swift
            if ends.contains(component) && path.count > 1 {
                let worstScore = path.map(\.riskScore).max() ?? 0
                let worstHop = path.first { $0.riskScore == worstScore }
                let likelihood = threats
                    .first { $0.name == worstHop?.worstThreatName }?
                    .likelihoodLabel ?? ""
                found.append(
                    ReportAttackPath(
                        startName: path[0].componentName,
                        endName: hop.componentName,
                        hops: path,
                        worstScore: worstScore,
                        likelihoodLabel: likelihood
                    )
                )
            }
```

Change the return type of `build` and its last statement:

```swift
    public static func build(
        components: [Component],
        connections: [Connection],
        zones: [Zone],
        threats: [ReportThreat],
        nameOf: (ComponentId) -> String
    ) -> (paths: [ReportAttackPath], prefix: [ReportAttackPathHop], notListed: [ReportAttackPathSummary]) {
```

Both early returns become `return ([], [], [])`. The final statement becomes:

```swift
        return curate(Array(ordered.prefix(maximumPaths)))
```

- [ ] **Step 6: Carry the new shape on `Report`**

In `Report.swift`, change the type of `attackPathsNotListed` and add the prefix:

```swift
    /// The attack paths the trace found and the narrative did not carry.
    public let attackPathsNotListed: [ReportAttackPathSummary]
    /// The hops every listed path starts with, stated once above them. Empty
    /// when the listed paths share no first hop.
    public let attackPathPrefix: [ReportAttackPathHop]
```

In the initialiser:

```swift
        attackPathsNotListed: [ReportAttackPathSummary] = [],
        attackPathPrefix: [ReportAttackPathHop] = [],
```

```swift
        self.attackPathsNotListed = attackPathsNotListed
        self.attackPathPrefix = attackPathPrefix
```

In `BuildThreatModelReport.execute`, the `Report(…)` call:

```swift
                attackPaths: attack.paths,
                attackPathsNotListed: attack.notListed,
                attackPathPrefix: attack.prefix,
```

- [ ] **Step 7: Update the existing attack path tests**

In `ThreatModelKit/Tests/UnitTests/AttackPathTests.swift`, the private `build`
helper returns a two-element tuple. Change it:

```swift
    private func build(
        components: [Component],
        connections: [Connection],
        threats: [ReportThreat] = []
    ) -> (paths: [ReportAttackPath], prefix: [ReportAttackPathHop], notListed: [ReportAttackPathSummary]) {
        AttackPaths.build(
            components: components,
            connections: connections,
            zones: [],
            threats: threats,
            nameOf: { $0.value }
        )
    }
```

Every assertion on `notListed` as a number becomes an assertion on
`notListed.count`. Every assertion on a path's hops must allow for the shared
prefix being trimmed: where a test asserted a full hop list and the fixture has
more than one path sharing a first hop, assert against `prefix + hops`.

Run the suite and fix each failure one at a time.

- [ ] **Step 8: Run the tests and see them pass**

Run: `cd ThreatModelKit && swift test --filter AttackPath`
Expected: PASS, both suites.

Run: `cd ThreatModelKit && swift test`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit ThreatModelKit/Tests/UnitTests
git commit -m "feat: the attack paths carry five stories, not twenty repeats"
```

---

### Task 9: The attack paths section and Appendix C

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownAttackPaths.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/ExportModelAsMarkdown.swift`
- Test: `ThreatModelKit/Tests/UnitTests/MarkdownAttackPathsTests.swift` (create)

**Interfaces:**
- Consumes: the curation from Task 8.
- Produces: `MarkdownAttackPaths.lines(_ paths: [ReportAttackPath], prefix: [ReportAttackPathHop]) -> [String]` and `MarkdownAttackPaths.appendixLines(_ notListed: [ReportAttackPathSummary]) -> [String]`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/MarkdownAttackPathsTests.swift`:

```swift
import Testing
import ThreatModelKit

struct MarkdownAttackPathsTests {
    private func hop(
        _ name: String,
        flow: String? = nil,
        threat: String? = nil,
        score: Int = 0,
        reducedBy: [String] = []
    ) -> ReportAttackPathHop {
        ReportAttackPathHop(
            componentName: name,
            flowKindLabel: flow,
            worstThreatName: threat,
            riskScore: score,
            reducedBy: reducedBy
        )
    }

    @Test func writesThePrefixOnceAndATablePerPath() {
        let text = MarkdownAttackPaths.lines(
            [
                ReportAttackPath(
                    startName: "Internet",
                    endName: "Secrets store",
                    hops: [
                        hop("Build pipeline", flow: "Network", threat: "Package substitution", score: 13),
                        hop("Secrets store", flow: "Local IPC", threat: "Credential theft", score: 9, reducedBy: ["Touch ID gate"])
                    ],
                    worstScore: 13,
                    likelihoodLabel: "Commodity"
                )
            ],
            prefix: [hop("Internet"), hop("ClearanceKit GUI")]
        ).joined(separator: "\n")

        #expect(text.hasPrefix("## Attack paths"))
        #expect(text.contains("Every path below starts at Internet \u{2192} ClearanceKit GUI."))
        #expect(text.contains("### 1. Internet \u{2192} Secrets store \u{2014} worst 13, Commodity"))
        #expect(text.contains("| Hop | Flow | Worst threat | Score | Reduced by |"))
        #expect(text.contains("| Build pipeline | Network | Package substitution | 13 | nothing reduces this hop |"))
        #expect(text.contains("| Secrets store | Local IPC | Credential theft | 9 | Touch ID gate |"))
    }

    @Test func writesNoPrefixLineWhenThePathsShareNoStart() {
        let text = MarkdownAttackPaths.lines(
            [ReportAttackPath(startName: "A", endName: "B", hops: [hop("A"), hop("B")], worstScore: 3)],
            prefix: []
        ).joined(separator: "\n")

        #expect(text.contains("Every path below starts") == false)
        #expect(text.contains("### 1. A \u{2192} B \u{2014} worst 3"))
    }

    @Test func writesNoneWhenTheTraceFoundNothing() {
        let text = MarkdownAttackPaths.lines([], prefix: []).joined(separator: "\n")

        #expect(text.contains("## Attack paths"))
        #expect(text.contains("None."))
    }

    @Test func writesTheDroppedPathsAsAnAppendix() {
        let text = MarkdownAttackPaths.appendixLines([
            ReportAttackPathSummary(startName: "Internet", endName: "Queue", worstScore: 8)
        ]).joined(separator: "\n")

        #expect(text.hasPrefix("## Appendix C \u{2014} Attack paths not listed"))
        #expect(text.contains("- Internet \u{2192} Queue, worst 8"))
    }

    @Test func writesNoAppendixWhenNothingWasDropped() {
        #expect(MarkdownAttackPaths.appendixLines([]).isEmpty)
    }
}
```

- [ ] **Step 2: Run the test and see it fail**

Run: `cd ThreatModelKit && swift test --filter MarkdownAttackPathsTests`
Expected: FAIL, the `lines` signature does not match.

- [ ] **Step 3: Rewrite the writer**

Replace the whole body of `MarkdownAttackPaths.swift`:

```swift
/// The report's Attack paths section.
///
/// WARNING: the walk is bounded and the narrative is curated. When it drops a
/// path the report says so and names the appendix that lists it, because a
/// silent truncation reads as full coverage.
public enum MarkdownAttackPaths {
    public static func lines(
        _ paths: [ReportAttackPath],
        prefix: [ReportAttackPathHop]
    ) -> [String] {
        var lines = ["## Attack paths", ""]

        guard paths.isEmpty == false else {
            return lines + ["None.", ""]
        }

        if prefix.isEmpty == false {
            lines.append(
                "Every path below starts at "
                    + prefix.map(\.componentName).joined(separator: " \u{2192} ")
                    + "."
            )
            lines.append("")
        }

        for (index, path) in paths.enumerated() {
            var heading = "### \(index + 1). \(path.startName) \u{2192} \(path.endName)"
                + " \u{2014} worst \(path.worstScore)"
            if path.likelihoodLabel.isEmpty == false {
                heading += ", \(path.likelihoodLabel)"
            }
            lines.append(heading)
            lines.append("")
            lines.append("| Hop | Flow | Worst threat | Score | Reduced by |")
            lines.append("| --- | --- | --- | --- | --- |")
            for hop in path.hops {
                lines.append(
                    "| \(Markdown.cell(hop.componentName))"
                        + " | \(Markdown.cell(hop.flowKindLabel ?? "\u{2014}"))"
                        + " | \(Markdown.cell(hop.worstThreatName ?? "none"))"
                        + " | \(hop.riskScore)"
                        + " | \(hop.reducedBy.isEmpty ? "nothing reduces this hop" : Markdown.cell(hop.reducedBy.joined(separator: ", ")))"
                        + " |"
                )
            }
            lines.append("")
        }
        return lines
    }

    /// Appendix C: one line per path the narrative did not carry.
    public static func appendixLines(_ notListed: [ReportAttackPathSummary]) -> [String] {
        guard notListed.isEmpty == false else { return [] }

        var lines = ["## Appendix C \u{2014} Attack paths not listed", ""]
        lines.append(
            "The trace found \(notListed.count) further paths. Each one scores"
                + " at or below the paths above."
        )
        lines.append("")
        for path in notListed {
            lines.append("- \(path.startName) \u{2192} \(path.endName), worst \(path.worstScore)")
        }
        lines.append("")
        return lines
    }
}
```

- [ ] **Step 4: Change the call in the exporter**

In `ExportModelAsMarkdown.execute`, replace the `MarkdownAttackPaths.lines(…)` call:

```swift
        lines += MarkdownAttackPaths.lines(report.attackPaths, prefix: report.attackPathPrefix)
```

The appendix is written in Task 11, with the other appendices.

- [ ] **Step 5: Run the tests and see them pass**

Run: `cd ThreatModelKit && swift test --filter MarkdownAttackPathsTests`
Expected: PASS, 5 tests.

Run: `cd ThreatModelKit && swift test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/reporting ThreatModelKit/Tests/UnitTests/MarkdownAttackPathsTests.swift
git commit -m "feat: an attack path reads as a story with the controls that fire on it"
```

---

### Task 10: Recommendations, worst first

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownRecommendations.swift`
- Test: `ThreatModelKit/Tests/UnitTests/MarkdownRecommendationsTests.swift` (create)

**Interfaces:**
- Consumes: `ReportRecommendation.riskScore`.
- Produces: no new symbol; the section's order changes.

- [ ] **Step 1: Read the writer**

Read `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownRecommendations.swift`
and note how it groups today. The change keeps every field it prints and
changes only the order of the entries.

- [ ] **Step 2: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/MarkdownRecommendationsTests.swift`:

```swift
import Testing
import ThreatModelKit

struct MarkdownRecommendationsTests {
    private func recommendation(_ text: String, _ score: Int, on element: String) -> ReportRecommendation {
        ReportRecommendation(
            text: text,
            note: nil,
            threatName: "t",
            sourceName: element,
            riskScore: score
        )
    }

    @Test func ordersByTheRiskItAnswersNotByTheElement() throws {
        let text = MarkdownRecommendations.lines([
            recommendation("small", 3, on: "Alpha"),
            recommendation("large", 13, on: "Beta"),
            recommendation("middle", 8, on: "Alpha")
        ]).joined(separator: "\n")

        let large = try #require(text.range(of: "large"))
        let middle = try #require(text.range(of: "middle"))
        let small = try #require(text.range(of: "small"))

        #expect(large.lowerBound < middle.lowerBound)
        #expect(middle.lowerBound < small.lowerBound)
    }
}
```

- [ ] **Step 3: Run the test and see it fail**

Run: `cd ThreatModelKit && swift test --filter MarkdownRecommendationsTests`
Expected: FAIL, the entries come out grouped by element.

- [ ] **Step 4: Sort the entries**

At the top of `MarkdownRecommendations.lines`, sort before anything else
reads the list:

```swift
        // A reader works down this list, so the worst risk is first. Grouping
        // by element hid the order a team should work in.
        let recommendations = recommendations.sorted { $0.riskScore > $1.riskScore }
```

Remove any grouping by `sourceName` that reorders after this, keeping every
field each entry prints.

- [ ] **Step 5: Run the tests and see them pass**

Run: `cd ThreatModelKit && swift test --filter MarkdownRecommendationsTests`
Expected: PASS.

Run: `cd ThreatModelKit && swift test`
Expected: PASS. Fix any acceptance test that asserted the old order.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/reporting ThreatModelKit/Tests/UnitTests/MarkdownRecommendationsTests.swift
git commit -m "feat: the recommendations read in the order a team should work"
```

---

### Task 11: The section order and the appendices

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/ExportModelAsMarkdown.swift`
- Modify: `ThreatModelKit/Tests/AcceptanceTests/ReportingAThreatModelTests.swift`
- Modify: `ThreatModelKit/Tests/AcceptanceTests/ExportingAReportAsOnePageTests.swift`
- Test: `ThreatModelKit/Tests/AcceptanceTests/ReportingAThreatModelTests.swift`

**Interfaces:**
- Consumes: every writer from Tasks 3 to 10.
- Produces: the final section order.

- [ ] **Step 1: Write the failing test**

Add to `ReportingAThreatModelTests`:

```swift
    @Test func writesTheSectionsInTheOrderAReaderNeedsThem() throws {
        _ = aModelWorthReporting()

        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        let order = [
            "## Executive summary",
            "## Methodology",
            "### Diagram legend",
            "## Findings",
            "## Attack paths",
            "## Recommendations",
            "## Glossary",
            "## Appendix A \u{2014} Full threat register",
            "## Appendix B \u{2014} Model inventory"
        ]
        var last = markdown.startIndex
        for heading in order {
            let found = try #require(
                markdown.range(of: heading, range: last..<markdown.endIndex),
                "the report has no \(heading) after the section before it"
            )
            last = found.upperBound
        }
    }

    @Test func writesNoSummaryBulletsAndKeepsTheControlCounts() {
        _ = aModelWorthReporting()

        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        #expect(markdown.contains("## Summary") == false)
        #expect(markdown.contains("- Controls recorded: "))
        #expect(markdown.contains("### Components"))
        #expect(markdown.contains("### Connections"))
        #expect(markdown.contains("### Zones"))
    }
```

- [ ] **Step 2: Run the test and see it fail**

Run: `cd ThreatModelKit && swift test --filter ReportingAThreatModelTests`
Expected: FAIL, the report still writes `## Summary` and `## Components`.

- [ ] **Step 3: Rewrite the exporter's body**

Replace the section assembly in `ExportModelAsMarkdown.execute` with:

```swift
        lines += MarkdownExecutiveSummary.lines(
            report.executiveSummary,
            components: report.components
        )
        lines += MarkdownRollups.lines(
            report.rollups,
            showsAssumed: report.assumedMitigations.isEmpty == false
        )
        lines += MarkdownThreatPictures.lines(
            report.rollups.topResidual,
            pictures: request.threatPictures
        )
        lines += MarkdownMethodology.lines(report.methodology)
        lines += MarkdownFindings.lines(report.findings, toleranceLabel: report.toleranceLabel)
        lines += MarkdownAttackPaths.lines(report.attackPaths, prefix: report.attackPathPrefix)
        lines += MarkdownProtectionDependencies.lines(
            report.protectionDependencies,
            pictures: request.controlPictures
        )
        lines += MarkdownRecommendations.lines(report.recommendations)
        lines += MarkdownAssumptions.lines(
            assumptions: report.assumptions,
            assumedMitigations: report.assumedMitigations
        )
        lines += MarkdownGlossary.lines()
        lines += threatRegister(report.threats, summary: report.summary)
        lines += modelInventory(report)
        lines += MarkdownAttackPaths.appendixLines(report.attackPathsNotListed)
```

Delete the `summary(_:)` method. Rename `threats(_:)` to
`threatRegister(_:summary:)` and give it the heading and the counts the removed
summary wrote:

```swift
    /// Appendix A: every threat the model raises, in full.
    ///
    /// The control counts the summary bullets used to write open this
    /// appendix, so no number the report published is lost.
    private func threatRegister(_ threats: [ReportThreat], summary: ReportSummary) -> [String] {
        var lines = ["## Appendix A \u{2014} Full threat register", ""]
        lines.append("- Threats: \(summary.totalThreats)")
        lines.append("- Controls recorded: \(summary.controlsRecorded) of \(summary.controlsOffered)")
        for status in summary.byControlStatus {
            lines.append("- Controls \(status.label.lowercased()): \(status.count)")
        }
        for level in summary.byLevel {
            lines.append("- \(level.label): \(level.count)")
        }
        lines.append("")

        guard threats.isEmpty == false else {
            return lines + ["None.", ""]
        }
        for threat in threats {
            lines += MarkdownThreatStanza.lines(threat)
        }
        return lines
    }

    /// Appendix B: what the model holds.
    private func modelInventory(_ report: Report) -> [String] {
        ["## Appendix B \u{2014} Model inventory", ""]
            + components(report.components)
            + connections(report.connections)
            + zones(report.zones)
    }
```

Change the three inventory methods to write `### ` headings rather than `## `:

- `components(_:)` starts `["### Components", ""]`
- `connections(_:)` starts `["### Connections", ""]`
- `zones(_:)` starts `["### Zones", ""]` and each zone becomes `#### \(zone.name)`

- [ ] **Step 4: Run the tests and see them pass**

Run: `cd ThreatModelKit && swift test --filter ReportingAThreatModelTests`
Expected: PASS.

Run: `cd ThreatModelKit && swift test`
Expected: FAIL in the suites that assert `## Components`, `## Threats` or
`## Summary`. Change each assertion to the new heading. The suites to check:
`ReportingAThreatModelTests`, `ExportingAReportAsOnePageTests`,
`ReadingAndAnsweringThreatsTests`, `ModellingFromSourceTests`,
`CommandLineApplicationTests`.

Run: `cd ThreatModelKit && swift test`
Expected: PASS.

- [ ] **Step 5: Run the application tests**

Run: `xcodebuild clean -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
Expected: PASS. Fix any application test asserting an old heading.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit threatmodellerTests
git commit -m "feat: the report leads with the findings and files the bulk as appendices"
```

---

### Task 12: One report path, and the PDF printed from it

**Files:**
- Delete: `threatmodeller/reporting/PDFReportRenderer.swift`
- Delete: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/ExportModelAsPdf.swift`
- Delete: `ThreatModelKit/Sources/ThreatModelKit/reporting/gateway/ReportRenderer.swift`
- Delete: `threatmodellerTests/ReportRendererTests.swift`
- Create: `threatmodeller/reporting/HtmlPdfPrinter.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`
- Modify: `threatmodeller/Dependencies.swift`
- Modify: `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`
- Modify: `threatmodeller/ThreatModelSession.swift`
- Test: `threatmodellerTests/HtmlPdfPrinterTests.swift` (create)

**Interfaces:**
- Consumes: `ThreatModelSession.htmlExport() -> (data: Data, fileName: String)`.
- Produces: `HtmlPdfPrinter.pdf(fromHtml html: String) async throws -> Data`.

- [ ] **Step 1: Write the failing test**

Create `threatmodellerTests/HtmlPdfPrinterTests.swift`:

```swift
import Testing
import Foundation
@testable import threatmodeller

/// The page a person exports and the page the PDF prints are one page.
@MainActor
struct HtmlPdfPrinterTests {
    @Test func printsAPageToPdfBytes() async throws {
        let data = try await HtmlPdfPrinter().pdf(
            fromHtml: "<html><body><h1>Payments</h1></body></html>"
        )

        #expect(data.isEmpty == false)
        #expect(data.starts(with: Array("%PDF".utf8)))
    }
}
```

- [ ] **Step 2: Run the test and see it fail**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/HtmlPdfPrinterTests`
Expected: FAIL, `cannot find 'HtmlPdfPrinter' in scope`.

- [ ] **Step 3: Write the printer**

Create `threatmodeller/reporting/HtmlPdfPrinter.swift`:

```swift
import Foundation
import WebKit

/// Prints the report page to PDF.
///
/// The report has one path: `ExportModelAsMarkdown` writes it,
/// `ExportModelAsHtml` converts it, and this prints that page. A second
/// renderer would drift from the first, and the one this replaced did.
@MainActor
struct HtmlPdfPrinter {
    /// A4 at 72 points to the inch, which is what the page's stylesheet
    /// targets.
    static let pageSize = CGSize(width: 595, height: 842)

    enum Fault: Error {
        case couldNotLoad(String)
    }

    func pdf(fromHtml html: String) async throws -> Data {
        let view = WKWebView(
            frame: CGRect(origin: .zero, size: Self.pageSize),
            configuration: WKWebViewConfiguration()
        )
        let delegate = LoadWatcher()
        view.navigationDelegate = delegate

        view.loadHTMLString(html, baseURL: nil)
        try await delegate.waitForLoad()

        let configuration = WKPDFConfiguration()
        configuration.rect = CGRect(origin: .zero, size: view.bounds.size)
        return try await view.pdf(configuration: configuration)
    }
}

/// Waits for one page to finish loading. `WKWebView` reports the load through
/// its delegate, and the print must not start before it.
@MainActor
private final class LoadWatcher: NSObject, WKNavigationDelegate {
    private var waiting: CheckedContinuation<Void, Error>?
    private var finished = false
    private var fault: Error?

    func waitForLoad() async throws {
        if finished { return }
        if let fault { throw fault }
        try await withCheckedThrowingContinuation { continuation in
            waiting = continuation
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        finished = true
        waiting?.resume()
        waiting = nil
    }

    func webView(
        _ webView: WKWebView,
        didFail navigation: WKNavigation!,
        withError error: Error
    ) {
        fault = error
        waiting?.resume(throwing: error)
        waiting = nil
    }
}
```

- [ ] **Step 4: Run the test and see it pass**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/HtmlPdfPrinterTests`
Expected: PASS.

- [ ] **Step 5: Change the session to print the page**

In `threatmodeller/ThreatModelSession.swift`, replace `pdfExport()`:

```swift
    /// The report page, printed. Returns nil when the page could not print,
    /// and says so in `errorMessage`.
    func pdfExport() async -> (data: Data, fileName: String)? {
        let page = htmlExport()
        do {
            let data = try await HtmlPdfPrinter().pdf(
                fromHtml: String(decoding: page.data, as: UTF8.self)
            )
            errorMessage = nil
            return (data, page.fileName.replacingOccurrences(of: ".html", with: ".pdf"))
        } catch {
            errorMessage = "The report could not be printed: \(String(describing: error))"
            return nil
        }
    }
```

In `threatmodeller/reporting/ReportExporter.swift`, `data(for:)` and `export(_:)`
become `async`, because the PDF case now awaits:

```swift
    func export(_ kind: Kind) async {
        guard let export = await data(for: kind) else { return }
        guard let url = chooseFile(export.fileName, kind.contentType) else { return }

        do {
            try export.data.write(to: url)
        } catch {
            session.reportExportFailed(String(describing: error))
        }
    }

    func data(for kind: Kind) async -> (data: Data, fileName: String)? {
        switch kind {
        case .markdown:
            session.markdownExport()
        case .html:
            session.htmlExport()
        case .threatcl:
            session.threatclExport()
        case .pdf:
            await session.pdfExport()
        case .image:
            image()
        }
    }
```

Every caller of `export(_:)` is a menu action. Wrap each in a `Task { await … }`.
Find them with `grep -rn "\.export(" threatmodeller`.

- [ ] **Step 6: Delete the old path**

```bash
git rm threatmodeller/reporting/PDFReportRenderer.swift \
       ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/ExportModelAsPdf.swift \
       ThreatModelKit/Sources/ThreatModelKit/reporting/gateway/ReportRenderer.swift \
       threatmodellerTests/ReportRendererTests.swift
```

Remove `func exportModelAsPdf() -> ExportModelAsPdfUseCase` from
`ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`, its
implementation in `threatmodeller/Dependencies.swift`, and its implementation
and the `FakeReportRenderer` in
`ThreatModelKit/Sources/TestSupport/TestDependencies.swift`.

Remove the `writesTheSameModelAsAPdf` style assertions from
`ReportingAThreatModelTests` — the PDF is no longer a package concern.

- [ ] **Step 7: Run every test**

Run: `cd ThreatModelKit && swift test`
Expected: PASS.

Run: `xcodebuild clean -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
Expected: PASS.

- [ ] **Step 8: Check the menu by hand**

Open the application, open a sample from the Welcome window, and choose
**File ▸ Export as PDF…**. Save the file and open it. Confirm the PDF holds the
executive summary, the methodology, the findings and the appendices, and that
the pictures are in it.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "feat: the PDF prints the report page, so one path feeds every output"
```

---

### Task 13: The documentation follows the report

**Files:**
- Modify: `docs/LANGUAGE.md:275-330` (the `system` section's report paragraph)
- Modify: `README.md`

**Interfaces:**
- Consumes: the finished report.
- Produces: no code.

- [ ] **Step 1: Find every place the documents name a report section**

Run: `grep -rn "## Threats\|## Summary\|## Components\|## Attack paths\|Attack paths" README.md docs/LANGUAGE.md`

- [ ] **Step 2: Correct each one**

Change each named section to the name it now has: `## Threats` becomes
`## Appendix A — Full threat register`, `## Components` becomes
`### Components` inside `## Appendix B — Model inventory`, and the assumptions
paragraph in section 4.2 keeps its wording because `## Assumptions` has not
moved.

Add one paragraph to `README.md` under the reporting description:

```markdown
The report opens with an executive summary, states the scale it scored
against, and lists every threat above the project's risk tolerance before it
lists anything else. The full threat register and the model inventory are
appendices.
```

- [ ] **Step 3: Check the documents are true**

Export a report from a sample and read it beside the documents. Every heading
the documents name must be in the file.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/LANGUAGE.md
git commit -m "docs: the documents name the report's sections as they are"
```

---

## Self-review

**Spec coverage.**

| Spec section | Task |
| --- | --- |
| 3 — the new shape | 11 |
| 4 — prose register | 3 (consultancy), every other writer (plain) |
| 5.1 `ReportExecutiveSummary` | 2 |
| 5.2 `ReportMethodology` | 4 |
| 5.3 `ReportFindingsCut` | 1 |
| 5.4 attack path narrative types | 8 |
| 6.1 executive summary section | 3 |
| 6.2 methodology section | 5 |
| 6.3 diagram legend | 5 |
| 6.4 findings section | 6 |
| 6.5 attack paths section | 9 |
| 6.6 recommendations order | 10 |
| 6.7 glossary | 7 |
| 6.8 the appendices | 11 |
| 7 — the PDF path | 12 |
| 8 — empty and edge cases | 3, 5, 6, 8, 9 |
| 9 — testing | every task |
| 10 — where the code goes | every task |

**Type consistency.** `ReportFindingsCut.build(from:tolerance:)` is defined in
Task 1 and used in Tasks 2 and 6. `ReportExecutiveSummary.build(threats:recommendations:tolerance:)`
is defined in Task 2 and used in Task 2 only. `ReportMethodology.build(zones:tolerance:)`
is defined in Task 4 and used in Task 4 only. `MarkdownThreatStanza.lines(_:)`
is defined in Task 6 and used in Tasks 6 and 11.
`AttackPaths.build` returns `(paths:prefix:notListed:)` from Task 8 and every
caller in Tasks 8, 9 and 11 uses those three names.
`MarkdownAttackPaths.lines(_:prefix:)` and `appendixLines(_:)` are defined in
Task 9 and used in Tasks 9 and 11. `HtmlPdfPrinter.pdf(fromHtml:)` is defined
in Task 12 and used in Task 12 only.

**Ordering.** Task 6 lifts the threat stanza, and Task 11 uses it for the
register. Task 8 changes the shape `AttackPaths.build` returns, and Task 9
prints it. No task uses a symbol a later task defines.
