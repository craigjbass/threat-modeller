import Testing
import ThreatModelKit
import TestSupport

struct ViewThreatModelTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func view(_ model: ThreatModel) -> ViewThreatModelResponse {
        ViewThreatModel(models: InMemoryThreatModelGateway(model), catalogue: catalogue)
            .execute(ViewThreatModelRequest())
    }

    private func component(
        _ id: String,
        technologyId: String = "aws-ec2",
        x: Double = 0,
        y: Double = 0,
        customName: String? = nil,
        threatsDisabled: Bool = false
    ) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId(technologyId),
            position: Point(x: x, y: y),
            sensitivity: .confidential,
            customName: customName,
            threatsDisabled: threatsDisabled
        )
    }

    @Test func showsAnEmptyModel() {
        let response = view(ThreatModel())

        #expect(response.name == "Untitled")
        #expect(response.components.isEmpty)
        #expect(response.connections.isEmpty)
    }

    @Test func describesAComponentForDrawing() throws {
        let response = view(ThreatModel(components: [component("c1", x: 120, y: 40)]))

        let drawn = try #require(response.components.first)
        #expect(drawn.id == "c1")
        #expect(drawn.technologyId == "aws-ec2")
        #expect(drawn.name == "EC2")
        #expect(drawn.providerId == "aws")
        #expect(drawn.categoryId == "compute")
        #expect(drawn.x == 120)
        #expect(drawn.y == 40)
        #expect(drawn.sensitivityId == "confidential")
        #expect(drawn.threatsDisabled == false)
        #expect(drawn.isUnknownTechnology == false)
    }

    @Test func prefersTheUsersOwnNameForAComponent() throws {
        let response = view(ThreatModel(components: [component("c1", customName: "Web tier")]))

        #expect(try #require(response.components.first).name == "Web tier")
    }

    @Test func stillDrawsAComponentWhoseTechnologyLeftTheCatalogue() throws {
        let response = view(ThreatModel(components: [component("c1", technologyId: "aws-retired")]))

        let drawn = try #require(response.components.first)
        #expect(drawn.name == "aws-retired")
        #expect(drawn.providerId == "")
        #expect(drawn.categoryId == "")
        #expect(drawn.isUnknownTechnology)
    }

    @Test func listsConnectionsInModelOrder() {
        let response = view(
            ThreatModel(
                components: [component("c1"), component("c2"), component("c3")],
                connections: [
                    Connection(id: ConnectionId("k2"), source: ComponentId("c2"), target: ComponentId("c3")),
                    Connection(id: ConnectionId("k1"), source: ComponentId("c1"), target: ComponentId("c2"))
                ]
            )
        )

        #expect(response.connections.map(\.id) == ["k2", "k1"])
        #expect(response.connections.first?.sourceComponentId == "c2")
        #expect(response.connections.first?.targetComponentId == "c3")
    }
}
