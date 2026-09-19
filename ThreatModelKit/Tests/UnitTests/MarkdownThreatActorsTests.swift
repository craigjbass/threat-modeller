import Testing
import ThreatModelKit

@Suite("The report's Threat actors section")
struct MarkdownThreatActorsTests {
    @Test func writesOneRowPerActor() {
        let lines = MarkdownThreatActors.lines([
            ReportThreatActor(
                name: "Commodity crimeware",
                capabilityLabel: "Commodity",
                intent: "opportunistic",
                threatsPerformed: 31
            ),
            ReportThreatActor(
                name: "FIN7 (G0046)",
                capabilityLabel: "Targeted",
                intent: "financial",
                threatsPerformed: 22
            )
        ])
        let text = lines.joined(separator: "\n")

        #expect(lines.first == "## Threat actors")
        #expect(text.contains("A threat no actor here performs keeps the catalogue's own likelihood."))
        #expect(text.contains("| Actor | Capability | Intent | Threats performed |"))
        #expect(text.contains("| Commodity crimeware | Commodity | Opportunistic | 31 |"))
        #expect(text.contains("| FIN7 (G0046) | Targeted | Financial | 22 |"))
    }

    @Test func callsAFacedActorAThreatActorAndNotAnAdversary() {
        let lines = MarkdownThreatActors.lines([
            ReportThreatActor(
                name: "Commodity crimeware",
                capabilityLabel: "Commodity",
                intent: "opportunistic",
                threatsPerformed: 31
            )
        ])
        let text = lines.joined(separator: "\n")

        #expect(text.contains("This assessment is written against these threat actors."))
        #expect(text.lowercased().contains("adversar") == false)
    }

    @Test func writesNoSectionForAModelThatFacesNobody() {
        #expect(MarkdownThreatActors.lines([]).isEmpty)
    }
}

@Suite("The likelihood line of a threat stanza")
struct MarkdownThreatStanzaLikelihoodTests {
    private func threat(
        likelihoodLabel: String,
        likelihoodReason: String,
        rationale: String? = nil,
        performedBy: [String] = []
    ) -> ReportThreat {
        ReportThreat(
            threatId: "credential-theft",
            name: "Credential theft",
            description: "It can happen.",
            severityLabel: "Critical",
            riskScore: 7,
            riskLevel: "high",
            strideLabels: [],
            mitreTechniqueIds: ["T1552", "T1078"],
            performedByLabels: performedBy,
            likelihoodReason: likelihoodReason,
            sourceName: "Web tier",
            sourceKind: "Component",
            controls: [],
            pathwayMitigationLabels: [],
            likelihoodLabel: likelihoodLabel,
            likelihoodRationale: rationale,
            scoreBeforeLikelihood: 12
        )
    }

    @Test func namesTheCatalogueWhenTheCataloguesTierStands() {
        let text = MarkdownThreatStanza.lines(
            threat(likelihoodLabel: "Targeted", likelihoodReason: "from the catalogue")
        ).joined(separator: "\n")

        #expect(text.contains("- Likelihood: Targeted, from the catalogue (12 \u{2192} 7)"))
    }

    @Test func namesTheActorThatSetIt() {
        let text = MarkdownThreatStanza.lines(
            threat(
                likelihoodLabel: "Targeted",
                likelihoodReason: "set by FIN7",
                performedBy: ["Commodity crimeware", "FIN7"]
            )
        ).joined(separator: "\n")

        #expect(text.contains("- Likelihood: Targeted, set by FIN7 (12 \u{2192} 7)"))
        #expect(text.contains("- Performed by: Commodity crimeware, FIN7"))
    }

    @Test func keepsTheWordingAFindingAlreadyHad() {
        let text = MarkdownThreatStanza.lines(
            threat(
                likelihoodLabel: "Research",
                likelihoodReason: "no in-the-wild use",
                rationale: "every bypass was researcher-found"
            )
        ).joined(separator: "\n")

        #expect(text.contains("- Likelihood: Research (12 \u{2192} 7)"))
        #expect(text.contains("  - Rationale: every bypass was researcher-found"))
    }

    @Test func writesNoPerformedByLineForAThreatNobodyPerforms() {
        let text = MarkdownThreatStanza.lines(
            threat(likelihoodLabel: "Commodity", likelihoodReason: "from the catalogue")
        ).joined(separator: "\n")

        #expect(text.contains("- Performed by:") == false)
    }
}
