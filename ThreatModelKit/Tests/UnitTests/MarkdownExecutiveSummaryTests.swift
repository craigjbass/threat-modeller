import Testing
import ThreatModelKit

struct MarkdownExecutiveSummaryTests {
    private func threat(
        _ name: String,
        _ score: Int,
        _ level: String,
        on element: String,
        sourceId: String = "",
        kind: String = "Component",
        overriddenBy: String? = nil,
        overrideChanges: [String] = [],
        likelihoodReason: String = LikelihoodSource.catalogue(.commodity).reason,
        likelihoodLabel: String = Likelihood.commodity.label,
        likelihoodFindingLabel: String? = nil
    ) -> ReportThreat {
        ReportThreat(
            threatId: name,
            name: name,
            description: "",
            severityLabel: "Critical",
            riskScore: score,
            riskLevel: level,
            strideLabels: [],
            mitreTechniqueIds: [],
            likelihoodReason: likelihoodReason,
            overriddenBy: overriddenBy,
            overrideChanges: overrideChanges,
            sourceName: element,
            sourceKind: kind,
            sourceId: sourceId,
            controls: [],
            pathwayMitigationLabels: [],
            likelihoodLabel: likelihoodLabel,
            likelihoodFindingLabel: likelihoodFindingLabel
        )
    }

    private let link = ReportConnection(
        id: "link-1",
        sourceName: "EC2",
        targetName: "RDS",
        kindLabel: "Network"
    )

    private let appZone = ReportZone(
        zoneId: "z1",
        name: "App VPC",
        networkZoneLabel: "Private Zone",
        networkTypeLabel: "Generic Network",
        componentNames: ["EC2", "RDS"],
        riskReductionPercent: nil,
        boundaryLabel: "Network Boundary"
    )

    @Test func statesTheReasonForATopRiskOnAConnection() {
        let summary = ReportExecutiveSummary(
            verdict: "v",
            topRisks: [
                threat(
                    "Data read in transit",
                    11,
                    "critical",
                    on: "EC2 \u{2192} RDS",
                    sourceId: "connection:link-1",
                    kind: "Connection"
                )
            ],
            totalThreats: 1
        )

        let text = MarkdownExecutiveSummary.lines(
            summary,
            components: [pipeline],
            connections: [link]
        ).joined(separator: "\n")

        #expect(text.contains("   The flow is a Network link from EC2 to RDS."))
    }

    @Test func statesTheReasonForATopRiskOnAZone() {
        let summary = ReportExecutiveSummary(
            verdict: "v",
            topRisks: [
                threat("Lateral movement", 9, "high", on: "App VPC", sourceId: "zone:z1", kind: "Zone")
            ],
            totalThreats: 1
        )

        let text = MarkdownExecutiveSummary.lines(
            summary,
            components: [pipeline],
            zones: [appZone]
        ).joined(separator: "\n")

        #expect(text.contains("   The zone is a Network Boundary and holds 2 components."))
    }

    @Test func namesTheLibraryBehindATopRisk() {
        let summary = ReportExecutiveSummary(
            verdict: "v",
            topRisks: [
                threat(
                    "Package substitution",
                    13,
                    "critical",
                    on: "Build pipeline",
                    overriddenBy: "acme-platform",
                    overrideChanges: ["severity", "likelihood"]
                )
            ],
            totalThreats: 1
        )

        let text = MarkdownExecutiveSummary.lines(summary, components: [pipeline])
            .joined(separator: "\n")

        #expect(
            text.contains("   The library acme-platform changes this threat's severity, likelihood.")
        )
    }

    @Test func namesTheKnownExploitedCveBehindATopRisk() {
        let summary = ReportExecutiveSummary(
            verdict: "v",
            topRisks: [
                threat(
                    "Package substitution",
                    13,
                    "critical",
                    on: "Build pipeline",
                    likelihoodReason: LikelihoodSource
                        .vulnerability(.commodity, cveId: "CVE-2023-44487").reason
                )
            ],
            totalThreats: 1
        )

        let text = MarkdownExecutiveSummary.lines(summary, components: [pipeline])
            .joined(separator: "\n")

        #expect(
            text.contains(
                "   The known exploited CVE CVE-2023-44487 raises this threat to Commodity."
            )
        )
    }

    @Test func namesTheLikelihoodFindingBehindATopRisk() {
        let summary = ReportExecutiveSummary(
            verdict: "v",
            topRisks: [
                threat(
                    "Package substitution",
                    13,
                    "critical",
                    on: "Build pipeline",
                    likelihoodLabel: "Targeted",
                    likelihoodFindingLabel: "Exploit code is published"
                )
            ],
            totalThreats: 1
        )

        let text = MarkdownExecutiveSummary.lines(summary, components: [pipeline])
            .joined(separator: "\n")

        #expect(
            text.contains(
                "   The finding Exploit code is published sets the likelihood to Targeted."
            )
        )
    }

    @Test func statesHowManyKnownExploitedCvesTheModelHolds() {
        let one = MarkdownExecutiveSummary.lines(
            ReportExecutiveSummary(knownExploitedCount: 1),
            components: []
        )
        let three = MarkdownExecutiveSummary.lines(
            ReportExecutiveSummary(knownExploitedCount: 3),
            components: []
        )
        let none = MarkdownExecutiveSummary.lines(ReportExecutiveSummary(), components: [])

        #expect(
            one.contains("This model holds 1 known exploited CVE, listed under Known vulnerabilities.")
        )
        #expect(
            three.contains(
                "This model holds 3 known exploited CVEs, listed under Known vulnerabilities."
            )
        )
        #expect(none.contains { $0.contains("known exploited") } == false)
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

    @Test func statesHowManyAdversariesTheModelDeclares() {
        let one = MarkdownExecutiveSummary.lines(
            ReportExecutiveSummary(adversaryCount: 1),
            components: []
        )
        let two = MarkdownExecutiveSummary.lines(
            ReportExecutiveSummary(adversaryCount: 2),
            components: []
        )
        let none = MarkdownExecutiveSummary.lines(
            ReportExecutiveSummary(),
            components: []
        )

        #expect(one.contains("This model declares 1 adversary, listed under Scope."))
        #expect(two.contains("This model declares 2 adversaries, listed under Scope."))
        #expect(none.contains { $0.contains("adversar") } == false)
    }
}
