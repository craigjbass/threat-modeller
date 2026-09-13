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
