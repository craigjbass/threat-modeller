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

    @Test func saysWhenATopRiskHasNoRecommendation() {
        let worst = threat("Credential theft", 13, "critical", on: "Build pipeline")
        let summary = ReportExecutiveSummary(
            verdict: "v",
            topRisks: [worst],
            totalThreats: 1,
            topRisksWithNoAction: [
                ReportRecommendation.key(threatId: worst.threatId, sourceId: worst.sourceId)
            ]
        )

        let text = MarkdownExecutiveSummary.lines(summary, components: []).joined(separator: "\n")

        #expect(text.contains("No recommendation names this threat, so none is listed below."))
    }

    @Test func staysQuietWhenATopRiskHasOne() {
        let worst = threat("Credential theft", 13, "critical", on: "Build pipeline")
        let summary = ReportExecutiveSummary(verdict: "v", topRisks: [worst], totalThreats: 1)

        let text = MarkdownExecutiveSummary.lines(summary, components: []).joined(separator: "\n")

        #expect(text.contains("No recommendation names this threat") == false)
    }

    @Test func writesTheActionsWhenTheModelDeclaresThem() {
        let summary = ReportExecutiveSummary(
            verdict: "v",
            totalThreats: 1,
            topLeverageActions: [
                ReportAction(
                    label: "reenable",
                    text: "Re-enable the dev-tool read rules",
                    blockedBy: "devtool-rules-disabled",
                    removes: 19,
                    totalResidual: 412,
                    threatsMoved: 8,
                    worstBefore: 13,
                    worstAfter: 5
                )
            ]
        )

        let text = MarkdownExecutiveSummary.lines(summary, components: []).joined(separator: "\n")

        #expect(text.contains("**Do first**"))
        #expect(
            text.contains(
                "1. Re-enable the dev-tool read rules \u{2014} removes 19 of 412 residual points"
            )
        )
        #expect(text.contains("   across 8 threats; worst falls 13 \u{2192} 5. Blocked by devtool-rules-disabled."))
    }

    @Test func writesTheSingularForAnActionThatMovesOneThreat() {
        let summary = ReportExecutiveSummary(
            verdict: "v",
            totalThreats: 1,
            topLeverageActions: [
                ReportAction(
                    label: "reenable",
                    text: "Re-enable the dev-tool read rules",
                    removes: 19,
                    totalResidual: 412,
                    threatsMoved: 1,
                    worstBefore: 13,
                    worstAfter: 5
                )
            ]
        )

        let text = MarkdownExecutiveSummary.lines(summary, components: []).joined(separator: "\n")

        #expect(text.contains("   across 1 threat; worst falls 13 \u{2192} 5."))
    }

    @Test func writesTheRecommendationsWhenTheModelDeclaresNoAction() {
        let summary = ReportExecutiveSummary(
            verdict: "v",
            topActions: [
                ReportRecommendation(
                    text: "Pin every package to a hash",
                    note: nil,
                    threatName: "Package substitution",
                    sourceName: "Build pipeline",
                    riskScore: 13
                )
            ],
            totalThreats: 1
        )

        let text = MarkdownExecutiveSummary.lines(summary, components: []).joined(separator: "\n")

        #expect(text.contains("1. Pin every package to a hash \u{2014} answers Package substitution"))
    }
}
