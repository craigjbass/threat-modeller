import Testing
import ThreatModelKit
import TestSupport

struct MoveComponentsTests {
    private let models = InMemoryThreatModelGateway(
        ThreatModel(components: [
            MoveComponentsTests.component("c1"),
            MoveComponentsTests.component("c2")
        ])
    )

    private static func component(_ id: String) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData
        )
    }

    private func move(_ moves: [ComponentMove]) -> MoveComponentsResponse {
        MoveComponents(models: models).execute(MoveComponentsRequest(moves: moves))
    }

    private func positions() -> [String: Point] {
        var found: [String: Point] = [:]
        for component in models.current().components {
            found[component.id.value] = component.position
        }
        return found
    }

    @Test func movesOneComponent() {
        #expect(move([ComponentMove(componentId: "c1", x: 120, y: 40)]) == .moved(count: 1))

        #expect(positions()["c1"] == Point(x: 120, y: 40))
        #expect(positions()["c2"] == Point(x: 0, y: 0))
    }

    @Test func movesEveryComponentInTheRequest() {
        let response = move([
            ComponentMove(componentId: "c1", x: 10, y: 20),
            ComponentMove(componentId: "c2", x: 30, y: 40)
        ])

        #expect(response == .moved(count: 2))
        #expect(positions()["c1"] == Point(x: 10, y: 20))
        #expect(positions()["c2"] == Point(x: 30, y: 40))
    }

    @Test func movesNothingWhenOneComponentIsUnknown() {
        let response = move([
            ComponentMove(componentId: "c1", x: 10, y: 20),
            ComponentMove(componentId: "c9", x: 30, y: 40)
        ])

        #expect(response == .unknownComponent(componentId: "c9"))
        #expect(positions()["c1"] == Point(x: 0, y: 0))
    }

    @Test func acceptsAnEmptyRequest() {
        #expect(move([]) == .moved(count: 0))
    }

    @Test func takesTheLastPositionWhenAComponentIsNamedTwice() {
        let response = move([
            ComponentMove(componentId: "c1", x: 10, y: 20),
            ComponentMove(componentId: "c1", x: 30, y: 40)
        ])

        #expect(response == .moved(count: 1))
        #expect(positions()["c1"] == Point(x: 30, y: 40))
    }

    @Test func givesTheSameResultWhenCalledTwice() {
        let request = [ComponentMove(componentId: "c1", x: 55, y: 65)]

        _ = move(request)
        _ = move(request)

        #expect(positions()["c1"] == Point(x: 55, y: 65))
    }
}
