import Testing
import ThreatModelKit
import TestSupport

struct SetConnectionPropertiesTests {
    private func gateway() -> InMemoryThreatModelGateway {
        InMemoryThreatModelGateway(
            ThreatModel(
                components: [
                    Component(
                        id: ComponentId("a"),
                        technologyId: TechnologyId("aws-ec2"),
                        position: Point(x: 0, y: 0),
                        sensitivity: .internalData
                    ),
                    Component(
                        id: ComponentId("b"),
                        technologyId: TechnologyId("aws-ec2"),
                        position: Point(x: 100, y: 0),
                        sensitivity: .internalData
                    )
                ],
                connections: [
                    Connection(id: ConnectionId("a->b"), source: ComponentId("a"), target: ComponentId("b"))
                ]
            )
        )
    }

    @Test func itSetsTheKindAndTheDescription() {
        let models = gateway()
        let response = SetConnectionProperties(models: models).execute(
            SetConnectionPropertiesRequest(connectionId: "a->b", kind: "ipc", description: "XPC call")
        )
        #expect(response == .updated)
        #expect(models.current().connections.first?.kind == .ipc)
        #expect(models.current().connections.first?.description == "XPC call")
    }

    @Test func anEmptyDescriptionIsNoDescription() {
        let models = gateway()
        _ = SetConnectionProperties(models: models).execute(
            SetConnectionPropertiesRequest(connectionId: "a->b", kind: "ipc", description: "  ")
        )
        #expect(models.current().connections.first?.description == nil)
    }

    @Test func itRefusesAKindTheApplicationDoesNotHold() {
        let models = gateway()
        let response = SetConnectionProperties(models: models).execute(
            SetConnectionPropertiesRequest(connectionId: "a->b", kind: "carrier-pigeon", description: nil)
        )
        #expect(response == .unknownKind)
        #expect(models.current().connections.first?.kind == .network)
    }

    @Test func itRefusesAConnectionTheModelDoesNotHold() {
        let response = SetConnectionProperties(models: gateway()).execute(
            SetConnectionPropertiesRequest(connectionId: "x->y", kind: "ipc", description: nil)
        )
        #expect(response == .unknownConnection)
    }

    @Test func theViewStatesTheKindThePrivilegeAndTheBoundary() throws {
        let models = gateway()
        _ = SetConnectionProperties(models: models).execute(
            SetConnectionPropertiesRequest(connectionId: "a->b", kind: "file", description: nil)
        )
        let view = ViewThreatModel(models: models, catalogue: CatalogueFixture.catalogue())
            .execute(ViewThreatModelRequest())
        #expect(view.connections.first?.kindId == "file")
        #expect(view.components.first?.runsAsId == "user")
    }
}
