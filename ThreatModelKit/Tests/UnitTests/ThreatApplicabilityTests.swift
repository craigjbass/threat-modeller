import Testing
import ThreatModelKit
import TestSupport

struct ThreatApplicabilityTests {
    private func threat(
        appliesTo: [FlowKind] = [],
        boundary: ZoneBoundary? = nil,
        runsAs: [PrivilegeLevel] = []
    ) -> Threat {
        Threat(
            id: ThreatId("t"),
            name: "T",
            description: "",
            severity: CatalogueFixture.high,
            isConnectionThreat: true,
            appliesToFlowKinds: appliesTo,
            boundary: boundary,
            appliesToPrivilegeLevels: runsAs
        )
    }

    @Test func aThreatThatNamesNoKindIsANetworkThreat() {
        let untagged = threat()
        #expect(ThreatApplicability.appliesToConnection(threat: untagged, kind: .network, crossesPrivilege: false))
        #expect(ThreatApplicability.appliesToConnection(threat: untagged, kind: .ipc, crossesPrivilege: false) == false)
        #expect(ThreatApplicability.appliesToConnection(threat: untagged, kind: .file, crossesPrivilege: false) == false)
    }

    @Test func aThreatIsRaisedOnTheKindsItNames() {
        let tagged = threat(appliesTo: [.file, .ipc])
        #expect(ThreatApplicability.appliesToConnection(threat: tagged, kind: .ipc, crossesPrivilege: false))
        #expect(ThreatApplicability.appliesToConnection(threat: tagged, kind: .network, crossesPrivilege: false) == false)
    }

    @Test func aPrivilegeThreatIsRaisedOnlyWhereTheFlowCrossesALevel() {
        let crossing = threat(boundary: .privilege)
        #expect(ThreatApplicability.appliesToConnection(threat: crossing, kind: .syscall, crossesPrivilege: true))
        #expect(ThreatApplicability.appliesToConnection(threat: crossing, kind: .syscall, crossesPrivilege: false) == false)
    }

    @Test func aZoneRaisesOnlyTheThreatsOfItsOwnBoundary() {
        #expect(ThreatApplicability.appliesToZone(threat: threat(), boundary: .network))
        #expect(ThreatApplicability.appliesToZone(threat: threat(), boundary: .privilege) == false)
        #expect(ThreatApplicability.appliesToZone(threat: threat(boundary: .privilege), boundary: .privilege))
        #expect(ThreatApplicability.appliesToZone(threat: threat(boundary: .privilege), boundary: .network) == false)
    }

    @Test func aComponentThreatThatNamesNoLevelIsRaisedAtEveryLevel() {
        #expect(ThreatApplicability.appliesToComponent(threat: threat(), runsAs: .user))
        #expect(ThreatApplicability.appliesToComponent(threat: threat(), runsAs: .kernel))
    }

    @Test func aComponentThreatIsRaisedOnlyAtTheLevelsItNames() {
        let rootOnly = threat(runsAs: [.root, .kernel])
        #expect(ThreatApplicability.appliesToComponent(threat: rootOnly, runsAs: .root))
        #expect(ThreatApplicability.appliesToComponent(threat: rootOnly, runsAs: .user) == false)
    }
}

struct ThreatApplicabilityInTheResolverTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func component(_ id: String) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: .confidential
        )
    }

    @Test func aLocalFlowRaisesNoNetworkThreat() {
        let model = ThreatModel(
            components: [component("a"), component("b")],
            connections: [
                Connection(
                    id: ConnectionId("a->b"),
                    source: ComponentId("a"),
                    target: ComponentId("b"),
                    kind: .ipc
                )
            ]
        )
        let resolved = ThreatResolver(model: model, catalogue: catalogue).resolve()
        #expect(resolved.contains { $0.threat.id == ThreatId("connection-mitm") } == false)
        #expect(resolved.contains { $0.threat.id == ThreatId("connection-dos") } == false)
    }

    @Test func aNetworkFlowStillRaisesTheNetworkThreats() {
        let model = ThreatModel(
            components: [component("a"), component("b")],
            connections: [
                Connection(id: ConnectionId("a->b"), source: ComponentId("a"), target: ComponentId("b"))
            ]
        )
        let resolved = ThreatResolver(model: model, catalogue: catalogue).resolve()
        #expect(resolved.contains { $0.threat.id == ThreatId("connection-mitm") })
    }
}
