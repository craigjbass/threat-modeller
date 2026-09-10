import Testing
import ThreatModelKit
import TestSupport

/// Builds a target technology with one threat and a protector technology with
/// none, through the library path, since the fixture catalogue exposes no
/// `add` helper. Follows the pattern `LikelihoodScoringTests` already uses.
private func twoComponentLibrary() -> Library {
    let source = LibrarySource(
        label: "endpoint",
        technologies: [
            SourceTechnology(id: "laptop", name: "Laptop", category: "compute", threatIds: ["persistence"]),
            SourceTechnology(id: "es-client", name: "ES Client", category: "compute", threatIds: [])
        ],
        threats: [
            SourceLibraryThreat(id: "persistence", name: "Persistence", severityLabel: "critical")
        ]
    )
    let (library, faults) = Library.build(from: source, taxonomy: CatalogueFixture.taxonomy())
    precondition(faults.isEmpty, "library build faults: \(faults)")
    return library!
}

@Suite("What an assumed mitigation does to the two postures")
struct AssumedMitigationTests {
    private let app = TestDependencies()

    private func threats() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    @Test func anAdoptedEdgeLowersBothNumbers() throws {
        let (protector, target, threatId) = twoComponents(status: .adopted)
        _ = protector
        _ = threatId

        let threat = try #require(threats().first { $0.source.id == "component:\(target)" })
        #expect(threat.riskScore == threat.scoreIfAssumptionsHold)
        #expect(threat.mitigatedByComponentLabels.isEmpty == false)
        #expect(threat.assumedByComponentLabels.isEmpty)
    }

    @Test func anAssumedEdgeLowersTheTargetPostureOnly() throws {
        let (_, target, _) = twoComponents(status: .assumed)

        let threat = try #require(threats().first { $0.source.id == "component:\(target)" })
        #expect(threat.riskScore == 16)
        #expect(threat.scoreIfAssumptionsHold == 6)
        #expect(threat.mitigatedByComponentLabels.isEmpty)
        #expect(threat.assumedByComponentLabels.isEmpty == false)
    }

    /// Spec section 3: the pipeline runs the `mitigates` edges before the
    /// likelihood stage, on both postures. Applying likelihood first would
    /// give a different number: 16 x 0.25 = 4, rounded, then 4 x 0.6 = 2.4,
    /// rounded to 2. Applying the edge first, as the design orders it, gives
    /// 16 x 0.6 = 9.6, rounded to 10, then 10 x 0.25 = 2.5, rounded to 3.
    @Test func theAssumedEdgeAppliesBeforeLikelihoodOnTheTargetPosture() throws {
        app.useLibraries([twoComponentLibrary()])
        guard case .added(let target) = app.addComponent().execute(
            AddComponentRequest(technologyId: "endpoint-laptop", x: 0, y: 0, sensitivity: "restricted")
        ),
        case .added(let protector) = app.addComponent().execute(
            AddComponentRequest(technologyId: "endpoint-es-client", x: 200, y: 0, sensitivity: "internal")
        ) else {
            Issue.record("the components were not added")
            return
        }

        app.modelStore.mutate { model in
            model.mitigatesEdges = [
                MitigatesEdge(
                    source: ComponentId(protector),
                    target: ComponentId(target),
                    threatIds: [ThreatId("endpoint-persistence")],
                    reducesRiskBy: 40,
                    status: .assumed
                )
            ]
            model.likelihoodFindings[
                ThreatKey(threatId: "endpoint-persistence", sourceId: "component:\(target)")
            ] = LikelihoodFinding(
                label: "researcher-only",
                likelihood: .research,
                rationale: "no in-the-wild use"
            )
        }

        let threat = try #require(threats().first { $0.source.id == "component:\(target)" })
        // No adopted edge answers this threat, so the residual pass sees
        // only the likelihood stage: 16 x 0.25 = 4.
        #expect(threat.riskScore == 4)
        // The target posture sees the assumed edge, then the likelihood
        // stage, in that order: 3, not the 2 the wrong order would give.
        #expect(threat.scoreIfAssumptionsHold == 3)
    }

    /// Two edges from one protector to one target can name the same threat
    /// with different statuses; nothing in the parser, the import or the
    /// domain rejects that pair. The residual counts only the adopted edge.
    /// The target posture counts both and keeps the stronger. The assumed
    /// label names only the edge whose own status is assumed, not every edge
    /// the stronger reduction happens to share a protector with.
    @Test func twoEdgesFromOneProtectorWithDifferentStatusesNameOnlyTheAssumedOne() throws {
        app.useLibraries([twoComponentLibrary()])

        guard case .added(let target) = app.addComponent().execute(
            AddComponentRequest(technologyId: "endpoint-laptop", x: 0, y: 0, sensitivity: "restricted")
        ),
        case .added(let protector) = app.addComponent().execute(
            AddComponentRequest(technologyId: "endpoint-es-client", x: 200, y: 0, sensitivity: "internal")
        ) else {
            Issue.record("the components were not added")
            return
        }

        app.modelStore.mutate { model in
            model.mitigatesEdges = [
                MitigatesEdge(
                    source: ComponentId(protector),
                    target: ComponentId(target),
                    threatIds: [ThreatId("endpoint-persistence")],
                    reducesRiskBy: 40,
                    status: .adopted
                ),
                MitigatesEdge(
                    source: ComponentId(protector),
                    target: ComponentId(target),
                    threatIds: [ThreatId("endpoint-persistence")],
                    reducesRiskBy: 60,
                    status: .assumed
                )
            ]
        }

        let threat = try #require(threats().first { $0.source.id == "component:\(target)" })
        #expect(threat.riskScore == 10)
        #expect(threat.scoreIfAssumptionsHold == 6)
        #expect(threat.mitigatedByComponentLabels == ["ES Client"])
        #expect(threat.assumedByComponentLabels == ["ES Client"])
    }

    /// Draws a protector, a protected component and one edge between them.
    private func twoComponents(status: MitigationStatus) -> (String, String, String) {
        app.useLibraries([twoComponentLibrary()])

        guard case .added(let target) = app.addComponent().execute(
            AddComponentRequest(technologyId: "endpoint-laptop", x: 0, y: 0, sensitivity: "restricted")
        ),
        case .added(let protector) = app.addComponent().execute(
            AddComponentRequest(technologyId: "endpoint-es-client", x: 200, y: 0, sensitivity: "internal")
        ) else { return ("", "", "") }

        app.modelStore.mutate { model in
            model.mitigatesEdges = [
                MitigatesEdge(
                    source: ComponentId(protector),
                    target: ComponentId(target),
                    threatIds: [ThreatId("endpoint-persistence")],
                    reducesRiskBy: 60,
                    status: status
                )
            ]
        }
        return (protector, target, "endpoint-persistence")
    }
}
