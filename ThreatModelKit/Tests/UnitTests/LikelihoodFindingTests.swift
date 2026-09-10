import Testing
import ThreatModelKit
import TestSupport

/// Builds a threat with a stated likelihood through the library path, since
/// the fixture catalogue exposes no `add` or `severity(id:)` helper. Follows
/// the pattern `LikelihoodScoringTests` already uses.
private func endpointLibrary(threatId: String, likelihood: String) -> Library {
    let source = LibrarySource(
        label: "endpoint",
        technologies: [
            SourceTechnology(
                id: "laptop",
                name: "Laptop",
                category: "compute",
                threatIds: [threatId]
            )
        ],
        threats: [
            SourceLibraryThreat(
                id: threatId,
                name: "SIP Bypass",
                severityLabel: "critical",
                likelihood: likelihood
            )
        ]
    )
    let (library, faults) = Library.build(from: source, taxonomy: CatalogueFixture.taxonomy())
    precondition(faults.isEmpty, "library build faults: \(faults)")
    return library!
}

@Suite("A likelihood finding against a library prior")
struct LikelihoodFindingTests {
    private let app = TestDependencies()

    private func threats() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    private func aComponentRaisingAThreat(likelihood: String) -> String {
        app.useLibraries([endpointLibrary(threatId: "sip-bypass", likelihood: likelihood)])
        guard case .added(let componentId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "endpoint-laptop", x: 0, y: 0, sensitivity: "restricted")
        ) else { return "" }
        return componentId
    }

    @Test func theFindingWinsOverThePrior() throws {
        let componentId = aComponentRaisingAThreat(likelihood: "commodity")
        let key = ThreatKey(threatId: "endpoint-sip-bypass", sourceId: "component:\(componentId)")

        app.modelStore.mutate { model in
            model.likelihoodFindings[key] = LikelihoodFinding(
                label: "no in-the-wild use",
                likelihood: .research,
                rationale: "every bypass was researcher-found",
                sources: ["CVE-2021-30892"]
            )
        }

        let threat = try #require(threats().first)
        #expect(threat.scoreBeforeLikelihood == 16)
        #expect(threat.riskScore == 4)
        #expect(threat.likelihoodId == "research")
        #expect(threat.likelihoodRationale == "every bypass was researcher-found")
        #expect(threat.likelihoodSources == ["CVE-2021-30892"])
    }

    @Test func thePriorStandsWhenNoFindingNamesTheThreat() throws {
        _ = aComponentRaisingAThreat(likelihood: "targeted")
        let threat = try #require(threats().first)
        #expect(threat.riskScore == 10)
        #expect(threat.likelihoodRationale == nil)
    }

    /// A finding wins in both directions. A `commodity` finding against a
    /// `research` prior raises the score back to the unfactored one, and
    /// still reports the rationale the finding carries.
    @Test func aCommodityFindingRaisesTheScoreBackWhenThePriorIsResearch() throws {
        let componentId = aComponentRaisingAThreat(likelihood: "research")
        let key = ThreatKey(threatId: "endpoint-sip-bypass", sourceId: "component:\(componentId)")

        app.modelStore.mutate { model in
            model.likelihoodFindings[key] = LikelihoodFinding(
                label: "seen in the wild",
                likelihood: .commodity,
                rationale: "exploit kits carry it now",
                sources: ["CVE-2022-11111"]
            )
        }

        let threat = try #require(threats().first)
        #expect(threat.scoreBeforeLikelihood == 16)
        #expect(threat.riskScore == 16)
        #expect(threat.likelihoodId == "commodity")
        #expect(threat.likelihoodRationale == "exploit kits carry it now")
        #expect(threat.likelihoodSources == ["CVE-2022-11111"])
    }

    /// A `commodity` finding on a threat whose prior is already `commodity`
    /// still attaches: the score is unchanged, but the rationale reaches the
    /// report.
    @Test func aCommodityFindingOnAPlainThreatKeepsTheScoreAndReportsTheRationale() throws {
        let componentId = aComponentRaisingAThreat(likelihood: "commodity")
        let key = ThreatKey(threatId: "endpoint-sip-bypass", sourceId: "component:\(componentId)")

        app.modelStore.mutate { model in
            model.likelihoodFindings[key] = LikelihoodFinding(
                label: "confirmed common",
                likelihood: .commodity,
                rationale: "widely automated already",
                sources: ["CVE-2019-22222"]
            )
        }

        let threat = try #require(threats().first)
        #expect(threat.scoreBeforeLikelihood == 16)
        #expect(threat.riskScore == 16)
        #expect(threat.likelihoodId == "commodity")
        #expect(threat.likelihoodRationale == "widely automated already")
        #expect(threat.likelihoodSources == ["CVE-2019-22222"])
    }
}
