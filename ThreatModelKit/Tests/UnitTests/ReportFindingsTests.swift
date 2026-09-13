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

    @Test func sortsWorstFirstWhenThreatsArriveOutOfOrder() {
        // Create 27 threats with varying scores, worst-to-best spread across the list
        let shuffled = [
            threat("mid-score-a", 50, "critical"),
            threat("worst-a", 95, "critical"),
            threat("low-score-a", 20, "critical"),
            threat("mid-score-b", 55, "critical"),
            threat("worst-b", 90, "critical"),
            threat("low-score-b", 15, "critical"),
            threat("mid-score-c", 60, "critical"),
            threat("worst-c", 100, "critical"),
            threat("low-score-c", 25, "critical"),
            threat("mid-score-d", 65, "critical"),
            threat("mid-score-e", 70, "critical"),
            threat("mid-score-f", 75, "critical"),
            threat("mid-score-g", 80, "critical"),
            threat("tie-a", 85, "critical"),
            threat("tie-b", 85, "critical"),
            threat("mid-score-h", 40, "critical"),
            threat("mid-score-i", 45, "critical"),
            threat("mid-score-j", 30, "critical"),
            threat("mid-score-k", 35, "critical"),
            threat("worst-d", 92, "critical"),
            threat("low-score-d", 10, "critical"),
            threat("mid-score-l", 5, "critical"),
            threat("mid-score-m", 88, "critical"),
            threat("worst-e", 99, "critical"),
            threat("mid-score-n", 12, "critical"),
            threat("low-score-e", 8, "critical"),
            threat("mid-score-o", 78, "critical")
        ]

        let cut = ReportFindingsCut.build(from: shuffled, tolerance: .low)

        // Verify cap: 25 shown, 2 not shown
        #expect(cut.above.count == 25)
        #expect(cut.notShown == 2)

        // Verify sort order: descending by riskScore, tie-broken by name ascending
        let scores = cut.above.map(\.riskScore)
        #expect(scores == scores.sorted(by: >))

        // Verify worst threats are in the cut, not in the overflow
        let scoreSet = Set(cut.above.map(\.riskScore))
        #expect(scoreSet.contains(100))
        #expect(scoreSet.contains(99))
        #expect(scoreSet.contains(95))

        // Verify the tie-break by name: within same score, earlier alphabet comes first
        let score85Threats = cut.above.filter { $0.riskScore == 85 }
        #expect(score85Threats.count == 2)
        #expect(score85Threats.map(\.name) == ["tie-a", "tie-b"])
    }
}
