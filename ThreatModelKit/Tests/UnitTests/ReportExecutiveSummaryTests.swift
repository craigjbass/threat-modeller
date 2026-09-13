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

    @Test func breaksATieBetweenTwoActionsByTextSoTwoRunsAgree() {
        let summary = ReportExecutiveSummary.build(
            threats: [],
            recommendations: [
                recommendation("zebra", 9),
                recommendation("alpha", 9),
                recommendation("middle", 9),
                recommendation("omitted", 9)
            ],
            tolerance: .low,
            findings: ReportFindingsCut()
        )

        #expect(summary.topActions.map { $0.text } == ["alpha", "middle", "omitted"])
    }

    @Test func namesATopRiskThatNoRecommendationAnswers() {
        let worst = threat("unanswered", 13, "critical")
        let lesser = threat("answered", 9, "high")

        let summary = ReportExecutiveSummary.build(
            threats: [worst, lesser],
            recommendations: [
                ReportRecommendation(
                    text: "do the lesser thing",
                    note: nil,
                    threatName: lesser.name,
                    sourceName: lesser.sourceName,
                    riskScore: 9,
                    threatId: lesser.threatId,
                    sourceId: lesser.sourceId
                )
            ],
            tolerance: .low,
            findings: ReportFindingsCut()
        )

        // The worst risk carries no recommendation, so no action names it and
        // the reader is told rather than left to notice.
        #expect(
            summary.topRisksWithNoAction
                == [ReportRecommendation.key(threatId: worst.threatId, sourceId: worst.sourceId)]
        )
    }

    @Test func namesNoGapWhenEveryTopRiskHasARecommendation() {
        let only = threat("answered", 13, "critical")

        let summary = ReportExecutiveSummary.build(
            threats: [only],
            recommendations: [
                ReportRecommendation(
                    text: "do it",
                    note: nil,
                    threatName: only.name,
                    sourceName: only.sourceName,
                    riskScore: 13,
                    threatId: only.threatId,
                    sourceId: only.sourceId
                )
            ],
            tolerance: .low,
            findings: ReportFindingsCut()
        )

        #expect(summary.topRisksWithNoAction.isEmpty)
    }
}
