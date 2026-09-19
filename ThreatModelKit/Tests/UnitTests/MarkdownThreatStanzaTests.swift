import Testing
import ThreatModelKit

/// The threat stanza: the one shape a threat prints in, wherever the report
/// prints it.
@Suite("The report's threat stanza")
struct MarkdownThreatStanzaTests {
    private func threat(
        controls: [ReportControl] = [],
        matchReason: String? = nil,
        overriddenBy: String? = nil,
        overrideChanges: [String] = [],
        pathwayMitigationLabels: [String] = [],
        pathwayMitigationModes: [String: String] = [:],
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
            description: "An attacker steals credentials.",
            severityLabel: "High",
            riskScore: 8,
            riskLevel: "high",
            strideLabels: [],
            mitreTechniqueIds: [],
            overriddenBy: overriddenBy,
            overrideChanges: overrideChanges,
            matchReason: matchReason,
            pathwayMitigationModes: pathwayMitigationModes,
            sourceName: "api",
            sourceKind: "Component",
            controls: controls,
            pathwayMitigationLabels: pathwayMitigationLabels,
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

    // MARK: attributes group E: the attributes nothing reads today

    /// GAP: `control.note` reached the window and no report section read it.
    @Test func statesAControlSNote() {
        let lines = MarkdownThreatStanza.lines(
            threat(
                controls: [
                    ReportControl(
                        description: "Rotate credentials regularly",
                        isImplemented: true,
                        note: "Rotated by the platform team every quarter."
                    )
                ]
            )
        )

        #expect(lines.contains { $0.contains("Rotated by the platform team every quarter.") })
    }

    /// GAP: the match reason `applies_to`, `runs_as`, `boundary`, `pathway`
    /// and `zone_context` compute to reached only the window's threat card.
    @Test func statesWhyAThreatWasNarrowedToThisElement() {
        let lines = MarkdownThreatStanza.lines(
            threat(matchReason: "Applies only where the component runs as Administrator.")
        )

        #expect(
            lines.contains {
                $0.contains("Applies only where the component runs as Administrator.")
            }
        )
    }

    @Test func statesNothingWhenNoMatcherNarrowsTheThreat() {
        let lines = MarkdownThreatStanza.lines(threat(matchReason: nil))

        #expect(lines.contains { $0.contains("Narrowed to this element") } == false)
    }

    /// GAP: a pathway mitigation's `mode` states only the label, never
    /// whether it removes the threat or reduces it.
    @Test func statesWhatAPathwayMitigationDoesToTheThreat() {
        let lines = MarkdownThreatStanza.lines(
            threat(
                pathwayMitigationLabels: ["WAF Protection"],
                pathwayMitigationModes: ["WAF Protection": "Lower the score"]
            )
        )

        #expect(lines.contains { $0.contains("WAF Protection (Lower the score)") })
    }

    /// GAP: a library override names only the library, never what it
    /// changed.
    @Test func statesWhatALibraryOverrideChanged() {
        let lines = MarkdownThreatStanza.lines(
            threat(overriddenBy: "acme", overrideChanges: ["severity", "controls"])
        )

        #expect(lines.contains { $0.contains("Changed by the library: acme (severity, controls)") })
    }

    @Test func statesTheLibraryAloneWhenItChangedNothingNamed() {
        let lines = MarkdownThreatStanza.lines(threat(overriddenBy: "acme", overrideChanges: []))

        #expect(lines.contains { $0.contains("Changed by the library: acme") })
        #expect(lines.contains { $0.contains("acme (") } == false)
    }
}
