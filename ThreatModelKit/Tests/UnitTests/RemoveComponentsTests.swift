import Testing
import ThreatModelKit
import TestSupport

struct RemoveComponentsTests {
    private let models = InMemoryThreatModelGateway(
        ThreatModel(
            components: [
                RemoveComponentsTests.component("c1"),
                RemoveComponentsTests.component("c2"),
                RemoveComponentsTests.component("c3")
            ],
            connections: [
                Connection(id: ConnectionId("k1"), source: ComponentId("c1"), target: ComponentId("c2")),
                Connection(id: ConnectionId("k2"), source: ComponentId("c2"), target: ComponentId("c3")),
                Connection(id: ConnectionId("k3"), source: ComponentId("c3"), target: ComponentId("c1"))
            ]
        )
    )

    private static func component(_ id: String) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData
        )
    }

    private func remove(_ ids: [String]) -> RemoveComponentsResponse {
        RemoveComponents(models: models).execute(RemoveComponentsRequest(componentIds: ids))
    }

    @Test func removesTheComponentAndEveryConnectionThatTouchesIt() {
        let response = remove(["c1"])

        #expect(response == .removed(componentIds: ["c1"], connectionIds: ["k1", "k3"]))
        #expect(models.current().components.map(\.id.value) == ["c2", "c3"])
        #expect(models.current().connections.map(\.id.value) == ["k2"])
    }

    @Test func removesSeveralComponentsAtOnce() {
        let response = remove(["c3", "c1"])

        #expect(response == .removed(componentIds: ["c1", "c3"], connectionIds: ["k1", "k2", "k3"]))
        #expect(models.current().components.map(\.id.value) == ["c2"])
        #expect(models.current().connections.isEmpty)
    }

    @Test func reportsEachRemovalInModelOrderNotRequestOrder() {
        let response = remove(["c2", "c1"])

        #expect(response == .removed(componentIds: ["c1", "c2"], connectionIds: ["k1", "k2", "k3"]))
    }

    @Test func removesNothingWhenOneComponentIsUnknown() {
        let response = remove(["c1", "c9"])

        #expect(response == .unknownComponent(componentId: "c9"))
        #expect(models.current().components.count == 3)
        #expect(models.current().connections.count == 3)
    }

    @Test func acceptsAnEmptyRequest() {
        #expect(remove([]) == .removed(componentIds: [], connectionIds: []))
        #expect(models.current().components.count == 3)
    }

    @Test func prunesTheRemovedComponentsControlKeys() {
        let mine = ControlIdentity.componentControl(
            componentId: ComponentId("c1"),
            threatId: ThreatId("credential-theft"),
            description: "Rotate credentials",
            isTechnologySpecific: false
        )
        let theirs = ControlIdentity.componentControl(
            componentId: ComponentId("c2"),
            threatId: ThreatId("credential-theft"),
            description: "Rotate credentials",
            isTechnologySpecific: false
        )
        let shared = ControlIdentity.connectionControl(
            threatId: ThreatId("connection-mitm"),
            description: "Enforce TLS"
        )
        let models = InMemoryThreatModelGateway(
            ThreatModel(
                components: [Self.component("c1"), Self.component("c2")],
                implementedControls: [mine, theirs, shared]
            )
        )

        _ = RemoveComponents(models: models).execute(RemoveComponentsRequest(componentIds: ["c1"]))

        #expect(models.current().implementedControls == [theirs, shared])
    }

    @Test func leavesEverySeverityOverrideAlone() {
        // An override is keyed by technology, so removing one component of that
        // technology must not clear it.
        let key = SeverityOverrideKey.forComponent(
            technologyId: TechnologyId("aws-ec2"),
            threatId: ThreatId("credential-theft")
        )
        let models = InMemoryThreatModelGateway(
            ThreatModel(components: [Self.component("c1")], severityOverrides: [key: "low"])
        )

        _ = RemoveComponents(models: models).execute(RemoveComponentsRequest(componentIds: ["c1"]))

        #expect(models.current().severityOverrides == [key: "low"])
    }
}
