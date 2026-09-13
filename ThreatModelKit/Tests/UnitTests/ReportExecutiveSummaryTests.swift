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

    private func summary(
        threats: [ReportThreat],
        recommendations: [ReportRecommendation] = [],
        tolerance: RiskLevel
    ) -> ReportExecutiveSummary {
        ReportExecutiveSummary.build(
            threats: threats,
            recommendations: recommendations,
            tolerance: tolerance,
            findings: ReportFindingsCut.build(from: threats, tolerance: tolerance)
        )
    }

    @Test func statesNoExposureWhenNothingRanksAboveTheTolerance() {
        let summary = summary(
            threats: [threat("a", 5, "medium")],
            recommendations: [],
            tolerance: .medium
        )

        #expect(summary.verdict == "No residual exposure exceeds the project's medium risk tolerance.")
    }

    @Test func namesOneExposureInTheSingular() {
        let summary = summary(
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
        let summary = summary(
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
        let summary = summary(
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

    @Test func sortsThreatsBeforeTakingTheTop() {
        let summary = summary(
            threats: [
                threat("c", 8, "high"),
                threat("a", 13, "critical"),
                threat("d", 7, "medium"),
                threat("b", 9, "high")
            ],
            recommendations: [],
            tolerance: .low
        )

        #expect(summary.topRisks.map(\.name) == ["a", "b", "c"])
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

        let summary = summary(
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
