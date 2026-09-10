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
