import Testing
import ThreatModelKit
import TestSupport

@Suite("Saying that one component lowers a threat on another")
struct ComponentMitigationTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func component(_ id: String, _ technology: String = "aws-ec2") -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId(technology),
            position: Point(x: 0, y: 0),
            sensitivity: .confidential
        )
    }

    /// The first control of credential theft on the store, which is what a
    /// person maps an edge to.
    private var firstControl: ControlKey {
        ControlIdentity.componentControl(
            componentId: ComponentId("store"),
            threatId: ThreatId("credential-theft"),
            description: "Enforce IMDSv2 to block SSRF-based credential theft",
            isTechnologySpecific: true
        )
    }

    private var secondControl: ControlKey {
        ControlIdentity.componentControl(
            componentId: ComponentId("store"),
            threatId: ThreatId("credential-theft"),
            description: "Use IAM roles with minimal permissions",
            isTechnologySpecific: true
        )
    }

    /// A model of a guard and a store, with the edges it states and the
    /// mappings a person wrote against the store's controls.
    private func model(
        _ edges: [MitigatesEdge],
        mapping: [ControlKey: [ControlMitigation]] = [:],
        implemented: Set<ControlKey> = []
    ) -> ThreatModel {
        var model = ThreatModel(
            name: "S",
            components: [component("guard", "aws-waf"), component("store")],
            mitigatesEdges: edges
        )
        model.controlMitigatedBy = mapping
        for key in implemented { model.controlStatuses[key] = .implemented }
        return model
    }

    private func liveEdge(_ threats: [String] = ["credential-theft"]) -> MitigatesEdge {
        MitigatesEdge(
            source: ComponentId("guard"),
            target: ComponentId("store"),
            threatIds: threats.map(ThreatId.init)
        )
    }

    private func credentialTheft(_ model: ThreatModel) -> ResolvedThreat {
        ThreatResolver(model: model, catalogue: catalogue).resolve()
            .first { $0.threat.id == ThreatId("credential-theft") && $0.source.id == "component:store" }!
    }

    @Test func noEdgeLeavesTheScoreAlone() {
        #expect(credentialTheft(model([])).score.value == 12)
    }

    @Test func anEdgeNobodyNamesLeavesTheScoreAlone() {
        #expect(credentialTheft(model([liveEdge()])).score.value == 12)
    }

    @Test func aMappedControlLowersTheThreatByWhatItStates() {
        let threat = credentialTheft(model(
            [liveEdge()],
            mapping: [firstControl: [ControlMitigation(edgeId: "guard->store", reducesRiskBy: 75)]],
            implemented: [firstControl]
        ))

        #expect(threat.score.value == 3)
        #expect(threat.mitigatedByComponents.first?.protectorName == "WAF")
        #expect(threat.mitigatedByComponents.first?.reducesRiskBy == 75)
        #expect(threat.mitigatedByComponents.first?.status == .live)
    }

    @Test func aMappingNobodyImplementedLowersNothing() {
        let threat = credentialTheft(model(
            [liveEdge()],
            mapping: [firstControl: [ControlMitigation(edgeId: "guard->store", reducesRiskBy: 75)]]
        ))

        #expect(threat.score.value == 12)
        #expect(threat.mitigatedByComponents.isEmpty)
    }

    @Test func anEdgeNamingAnotherThreatChangesNothing() {
        let threat = credentialTheft(model(
            [liveEdge(["dos-attack"])],
            mapping: [firstControl: [ControlMitigation(edgeId: "guard->store", reducesRiskBy: 75)]],
            implemented: [firstControl]
        ))

        #expect(threat.score.value == 12)
    }

    @Test func twoMappingsGiveTheStrongerAndNotTheSum() {
        let threat = credentialTheft(model(
            [
                liveEdge(),
                MitigatesEdge(
                    source: ComponentId("store"),
                    target: ComponentId("store"),
                    threatIds: [ThreatId("credential-theft")]
                )
            ],
            mapping: [
                firstControl: [ControlMitigation(edgeId: "guard->store", reducesRiskBy: 50)],
                secondControl: [ControlMitigation(edgeId: "store->store", reducesRiskBy: 50)]
            ],
            implemented: [firstControl, secondControl]
        ))

        #expect(threat.score.value == 6)
    }

    @Test func oneControlMayNameTwoEdges() {
        let threat = credentialTheft(model(
            [
                liveEdge(),
                MitigatesEdge(
                    source: ComponentId("store"),
                    target: ComponentId("store"),
                    threatIds: [ThreatId("credential-theft")]
                )
            ],
            mapping: [
                firstControl: [
                    ControlMitigation(edgeId: "guard->store", reducesRiskBy: 20),
                    ControlMitigation(edgeId: "store->store", reducesRiskBy: 75)
                ]
            ],
            implemented: [firstControl]
        ))

        #expect(threat.score.value == 3)
        #expect(threat.mitigatedByComponents.map(\.reducesRiskBy) == [20, 75])
    }

    @Test func theScoreNeverFallsBelowOne() {
        let threat = credentialTheft(model(
            [liveEdge()],
            mapping: [firstControl: [ControlMitigation(edgeId: "guard->store", reducesRiskBy: 100)]],
            implemented: [firstControl]
        ))

        #expect(threat.score.value == 1)
    }

    @Test func aProposedEdgeLowersTheScoreItWouldReachAndNotTheScoreToday() {
        let proposed = MitigatesEdge(
            source: ComponentId("guard"),
            target: ComponentId("store"),
            threatIds: [ThreatId("credential-theft")],
            status: .proposed
        )
        let threat = credentialTheft(model(
            [proposed],
            mapping: [firstControl: [ControlMitigation(edgeId: "guard->store", reducesRiskBy: 75)]]
        ))

        #expect(threat.score.value == 12)
        #expect(threat.scoreIfAssumptionsHold == 3)
        #expect(threat.assumedMitigations.first?.reducesRiskBy == 75)
    }

    @Test func theAssessedThreatNamesTheComponentThatMitigatedIt() throws {
        let held = model(
            [liveEdge()],
            mapping: [firstControl: [ControlMitigation(edgeId: "guard->store", reducesRiskBy: 75)]],
            implemented: [firstControl]
        )
        let response = AssessThreatModel(
            models: InMemoryThreatModelGateway(held),
            catalogue: catalogue
        ).execute(AssessThreatModelRequest())

        let threat = try #require(
            response.threats.first {
                $0.threatId == "credential-theft" && $0.source.id == "component:store"
            }
        )
        #expect(threat.mitigatedByComponentLabels == ["WAF"])
        #expect(threat.mitigatedByComponentReductions == [75])
    }
}
