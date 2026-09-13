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
