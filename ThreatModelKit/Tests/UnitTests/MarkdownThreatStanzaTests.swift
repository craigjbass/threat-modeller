import Testing
import ThreatModelKit

@Suite("One threat, written the same way wherever the report writes it")
struct MarkdownThreatStanzaTests {
    private func threat(
        mitigatedByComponentLabels: [String] = [],
        mitigatedByComponentReductions: [Int] = [],
        likelihoodLabel: String = Likelihood.commodity.label,
        likelihoodRationale: String? = nil,
        likelihoodFindingLabel: String? = nil,
        compensating: [ReportCompensatingControl] = []
    ) -> ReportThreat {
        ReportThreat(
            threatId: "credential-theft",
            name: "Credential Theft",
            description: "Attacker steals credentials to impersonate a principal.",
            severityLabel: "Critical",
            riskScore: 12,
            riskLevel: "critical",
            strideLabels: ["Spoofing"],
            mitreTechniqueIds: [],
            sourceName: "Application Server",
            sourceKind: "Component",
            controls: [],
            pathwayMitigationLabels: [],
            compensating: compensating,
            mitigatedByComponentLabels: mitigatedByComponentLabels,
            mitigatedByComponentReductions: mitigatedByComponentReductions,
            likelihoodLabel: likelihoodLabel,
            likelihoodRationale: likelihoodRationale,
            likelihoodFindingLabel: likelihoodFindingLabel
        )
    }

    // MARK: a `mitigates` edge

    /// GAP audit #260: a `mitigates` edge printed as a bare name, so a
    /// reader could not see how much the edge took off.
    @Test func statesThePercentageAMitigatesEdgeTakesOff() {
        let lines = MarkdownThreatStanza.lines(
            threat(mitigatedByComponentLabels: ["WAF"], mitigatedByComponentReductions: [75])
        )

        #expect(lines.contains("- Reduced by: WAF (75%)"))
    }

    @Test func statesEachEdgesOwnPercentageWhenTwoAnswerTheThreat() {
        let lines = MarkdownThreatStanza.lines(
            threat(
                mitigatedByComponentLabels: ["WAF", "Gateway"],
                mitigatedByComponentReductions: [75, 40]
            )
        )

        #expect(lines.contains("- Reduced by: WAF (75%), Gateway (40%)"))
    }

    // MARK: every compensating control, not only the first

    /// GAP audit #260 / issue #264: the stanza must state the evidence and
    /// the date of every compensating control, not only the first.
    @Test func statesTheEvidenceAndDateOfEveryCompensatingControl() {
        let lines = MarkdownThreatStanza.lines(
            threat(compensating: [
                ReportCompensatingControl(
                    label: "Rate limiter",
                    reducesRiskBy: 10,
                    rationale: "a rate limiter throttles the flood",
                    evidence: "tested, test-a, verified 2026-01-05"
                ),
                ReportCompensatingControl(
                    label: "Autoscaling",
                    reducesRiskBy: 20,
                    rationale: "autoscaling absorbs the flood",
                    evidence: "audited, test-b, verified 2026-02-10"
                )
            ])
        )
        let text = lines.joined(separator: "\n")

        #expect(text.contains("Rate limiter"))
        #expect(text.contains("tested, test-a, verified 2026-01-05"))
        #expect(text.contains("Autoscaling"))
        #expect(text.contains("audited, test-b, verified 2026-02-10"))
    }

    // MARK: the label a person writes on a likelihood block

    /// GAP audit #260: `LikelihoodFinding.label` never reached the report.
    @Test func statesTheLikelihoodFindingsLabelBesideItsRationale() throws {
        let lines = MarkdownThreatStanza.lines(
            threat(
                likelihoodLabel: "Research",
                likelihoodRationale: "every bypass was researcher-found",
                likelihoodFindingLabel: "no in-the-wild use"
            )
        )
        let text = lines.joined(separator: "\n")

        let findingIndex = try #require(text.range(of: "no in-the-wild use"))
        let rationaleIndex = try #require(text.range(of: "every bypass was researcher-found"))
        #expect(findingIndex.lowerBound < rationaleIndex.lowerBound)
    }

    @Test func writesNoFindingLabelWhenTheLibrarysPriorStands() {
        let lines = MarkdownThreatStanza.lines(threat())

        #expect(lines.contains { $0.contains("Finding:") } == false)
    }
}
