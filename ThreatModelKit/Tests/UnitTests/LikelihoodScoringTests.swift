import Testing
import ThreatModelKit
import TestSupport

/// Builds a threat with a stated likelihood through the library path, since
/// the fixture catalogue exposes no `add` or `severity(id:)` helper.
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
                name: "Test threat",
                severityLabel: "critical",
                likelihood: likelihood
            )
        ]
    )
    let (library, faults) = Library.build(from: source, taxonomy: CatalogueFixture.taxonomy())
    precondition(faults.isEmpty, "library build faults: \(faults)")
    return library!
}

@Suite("Where the likelihood stage sits in the score")
struct LikelihoodScoringTests {
    private let app = TestDependencies()

    private func threats() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    @Test func aCommodityThreatKeepsItsScore() throws {
        app.useLibraries([endpointLibrary(threatId: "theft", likelihood: "commodity")])
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "endpoint-laptop", x: 0, y: 0, sensitivity: "restricted")
        )

        let threat = try #require(threats().first)
        #expect(threat.riskScore == threat.scoreBeforeLikelihood)
        #expect(threat.likelihoodId == "commodity")
    }

    @Test func aResearchThreatScoresAQuarter() throws {
        app.useLibraries([endpointLibrary(threatId: "sip-bypass", likelihood: "research")])
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "endpoint-laptop", x: 0, y: 0, sensitivity: "restricted")
        )

        let threat = try #require(threats().first)
        #expect(threat.scoreBeforeLikelihood == 16)
        #expect(threat.riskScore == 4)
        #expect(threat.likelihoodLabel == "Research")
    }

    @Test func anInsiderThreatScoresLikeATargetedOne() throws {
        app.useLibraries([endpointLibrary(threatId: "key-copying", likelihood: "insider")])
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "endpoint-laptop", x: 0, y: 0, sensitivity: "restricted")
        )

        let threat = try #require(threats().first)
        #expect(threat.scoreBeforeLikelihood == 16)
        #expect(threat.riskScore == 10)
        #expect(threat.likelihoodId == "insider")
        #expect(threat.likelihoodLabel == "Insider")
    }

    /// The compensating stage rebuilds a `ResolvedThreat`. This proves it
    /// carries the likelihood fields through rather than dropping them.
    @Test func aCompensatingControlKeepsTheLikelihoodFields() throws {
        app.useLibraries([endpointLibrary(threatId: "sip-bypass", likelihood: "research")])
        let response = app.addComponent().execute(
            AddComponentRequest(technologyId: "endpoint-laptop", x: 0, y: 0, sensitivity: "restricted")
        )
        guard case .added(let componentId) = response else {
            Issue.record("the component was not added")
            return
        }
        let before = try #require(threats().first)
        app.modelStore.mutate { model in
            model.compensatingControls[
                ThreatKey(threatId: before.threatId, sourceId: "component:\(componentId)")
            ] = [CompensatingControl(label: "Watched by the SIEM", reducesRiskBy: 40, rationale: "It alerts on use.")]
        }

        let after = try #require(threats().first)
        #expect(after.likelihoodId == "research")
        #expect(after.likelihoodLabel == "Research")
        #expect(after.scoreBeforeLikelihood == 16)
        #expect(after.compensatingLabels == ["Watched by the SIEM"])
    }

    /// A caller that wants to write a finding needs the key the assessment
    /// looks findings up by. Without it every caller builds the string itself
    /// and one of them gets the form wrong.
    @Test func carriesTheKeyAFindingIsStoredUnder() throws {
        app.useLibraries([endpointLibrary(threatId: "sip-bypass", likelihood: "commodity")])
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "endpoint-laptop", x: 0, y: 0, sensitivity: "restricted")
        )
        let before = try #require(threats().first)

        #expect(
            app.setLikelihoodFinding().execute(
                SetLikelihoodFindingRequest(
                    threatKey: before.threatKey,
                    label: "no campaign has used this",
                    tier: "research",
                    prior: nil,
                    rationale: "No public reporting names it.",
                    sources: []
                )
            ) == .recorded
        )

        let after = try #require(threats().first)
        #expect(after.likelihoodId == "research")
        #expect(after.riskScore < before.riskScore)
    }
}
