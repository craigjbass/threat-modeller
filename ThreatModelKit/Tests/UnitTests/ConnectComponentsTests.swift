import Testing
import ThreatModelKit
import TestSupport

struct ConnectComponentsTests {
    private let models = InMemoryThreatModelGateway(
        ThreatModel(components: [
            ConnectComponentsTests.component("c1"),
            ConnectComponentsTests.component("c2"),
            ConnectComponentsTests.component("c3")
        ])
    )
    private let ids = SequentialIdentityGenerator()

    private static func component(_ id: String) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData
        )
    }

    private func connect(_ source: String, _ target: String) -> ConnectComponentsResponse {
        ConnectComponents(models: models, ids: ids)
            .execute(ConnectComponentsRequest(sourceComponentId: source, targetComponentId: target))
    }

    private func view() -> ViewThreatModelResponse {
        ViewThreatModel(models: models, catalogue: CatalogueFixture.catalogue())
            .execute(ViewThreatModelRequest())
    }

    @Test func linksTwoComponents() {
        #expect(connect("c1", "c2") == .connected(connectionId: "id-1"))

        let connections = view().connections
        #expect(connections.map(\.id) == ["id-1"])
        #expect(connections.first?.sourceComponentId == "c1")
        #expect(connections.first?.targetComponentId == "c2")
    }

    @Test func refusesAComponentLinkedToItself() {
        #expect(connect("c1", "c1") == .selfConnection)
        #expect(view().connections.isEmpty)
    }

    @Test func refusesASecondLinkBetweenTheSamePairInTheSameDirection() {
        _ = connect("c1", "c2")

        #expect(connect("c1", "c2") == .duplicateConnection(connectionId: "id-1"))
        #expect(view().connections.count == 1)
    }

    @Test func allowsALinkBackTheOtherWay() {
        _ = connect("c1", "c2")

        #expect(connect("c2", "c1") == .connected(connectionId: "id-2"))
        #expect(view().connections.count == 2)
    }

    @Test func refusesASourceTheModelDoesNotHold() {
        #expect(connect("c9", "c2") == .unknownComponent(componentId: "c9"))
        #expect(view().connections.isEmpty)
    }

    @Test func refusesATargetTheModelDoesNotHold() {
        #expect(connect("c1", "c9") == .unknownComponent(componentId: "c9"))
        #expect(view().connections.isEmpty)
    }

    @Test func spendsNoIdentifierOnALinkItRefuses() {
        _ = connect("c1", "c1")
        _ = connect("c9", "c2")

        #expect(connect("c1", "c2") == .connected(connectionId: "id-1"))
    }
}
