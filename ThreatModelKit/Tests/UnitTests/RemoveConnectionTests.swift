import Testing
import ThreatModelKit
import TestSupport

struct RemoveConnectionTests {
    private let models = InMemoryThreatModelGateway(
        ThreatModel(
            components: [
                RemoveConnectionTests.component("c1"),
                RemoveConnectionTests.component("c2")
            ],
            connections: [
                Connection(id: ConnectionId("k1"), source: ComponentId("c1"), target: ComponentId("c2")),
                Connection(id: ConnectionId("k2"), source: ComponentId("c2"), target: ComponentId("c1"))
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

    private func remove(_ id: String) -> RemoveConnectionResponse {
        RemoveConnection(models: models).execute(RemoveConnectionRequest(connectionId: id))
    }

    @Test func removesTheNamedConnectionAndLeavesTheOther() {
        #expect(remove("k1") == .removed)

        #expect(models.current().connections.map(\.id.value) == ["k2"])
        #expect(models.current().components.count == 2)
    }

    @Test func refusesAConnectionTheModelDoesNotHold() {
        #expect(remove("k9") == .unknownConnection)
        #expect(models.current().connections.count == 2)
    }
}
