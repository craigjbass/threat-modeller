import Testing
import ThreatModelKit

struct ConnectionTests {
    private let a = ComponentId("a")
    private let b = ComponentId("b")
    private let c = ComponentId("c")

    private func component(_ id: ComponentId) -> Component {
        Component(
            id: id,
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData
        )
    }

    @Test func touchesBothOfItsEnds() {
        let connection = Connection(id: ConnectionId("k1"), source: a, target: b)

        #expect(connection.touches(a))
        #expect(connection.touches(b))
        #expect(connection.touches(c) == false)
    }

    @Test func aReversedPairIsADifferentConnection() {
        let forward = Connection(id: ConnectionId("k1"), source: a, target: b)
        let backward = Connection(id: ConnectionId("k1"), source: b, target: a)

        #expect(forward != backward)
    }

    @Test func anEmptyModelCarriesNoConnections() {
        #expect(ThreatModel().connections.isEmpty)
    }

    @Test func findsAComponentById() {
        let model = ThreatModel(components: [component(a)])

        #expect(model.component(a)?.id == a)
        #expect(model.component(b) == nil)
    }

    @Test func holdsTheConnectionsItWasBuiltWith() {
        let model = ThreatModel(
            components: [component(a), component(b)],
            connections: [Connection(id: ConnectionId("k1"), source: a, target: b)]
        )

        #expect(model.connections.map(\.id.value) == ["k1"])
    }
}
