import Testing
import ThreatModelKit
import TestSupport

/// Laying the drawn diagram out again.
@Suite("Laying the diagram out again")
struct ArrangeDiagramTests {
    private let app = TestDependencies()

    private func drawn() -> [String] {
        _ = app.importArchitecture().execute(
            ImportArchitectureRequest(
                text: """
                system "Payments" {
                  zone "app" {
                    kind = "private"

                    component "api" { technology = "aws-ec2" }
                    component "db" { technology = "aws-rds" }
                  }

                  flow api -> db
                }
                """
            )
        )
        return app.modelStore.current().components.map(\.id.value)
    }

    private func positions() -> [String: Point] {
        Dictionary(
            uniqueKeysWithValues: app.modelStore.current().components.map {
                ($0.id.value, $0.position)
            }
        )
    }

    @Test func saysThereIsNothingToLayOutForAnEmptyModel() {
        #expect(app.arrangeDiagram().execute(ArrangeDiagramRequest()) == .nothingToArrange)
    }

    @Test func movesEveryComponentAndEveryZone() {
        let ids = drawn()
        for (index, id) in ids.enumerated() {
            _ = app.moveComponents().execute(
                MoveComponentsRequest(
                    moves: [ComponentMove(componentId: id, x: Double(index) * 37, y: 1200)]
                )
            )
        }
        let scattered = positions()

        guard case .arranged(let componentIds, let zoneIds) = app.arrangeDiagram()
            .execute(ArrangeDiagramRequest()) else {
            Issue.record("expected the diagram to be laid out")
            return
        }

        #expect(Set(componentIds) == Set(ids))
        #expect(zoneIds.count == 1)
        #expect(positions() != scattered)
    }

    @Test func oneUndoPutsEveryElementBack() {
        let ids = drawn()
        _ = app.moveComponents().execute(
            MoveComponentsRequest(moves: [ComponentMove(componentId: ids[0], x: 900, y: 900)])
        )
        let before = positions()
        let zoneBefore = app.modelStore.current().zones.first?.rect

        _ = app.arrangeDiagram().execute(ArrangeDiagramRequest())
        _ = app.undoLastChange().execute(UndoLastChangeRequest())

        #expect(positions() == before)
        #expect(app.modelStore.current().zones.first?.rect == zoneBefore)
    }

    @Test func laysOutOnlyWhatIsNamed() {
        let ids = drawn()
        for id in ids {
            _ = app.moveComponents().execute(
                MoveComponentsRequest(moves: [ComponentMove(componentId: id, x: 900, y: 900)])
            )
        }
        let before = positions()

        guard case .arranged(let moved, let zones) = app.arrangeDiagram().execute(
            ArrangeDiagramRequest(componentIds: [ids[0]])
        ) else {
            Issue.record("expected the selection to be laid out")
            return
        }

        #expect(moved == [ids[0]])
        #expect(zones.isEmpty)
        #expect(positions()[ids[1]] == before[ids[1]])
        #expect(positions()[ids[0]] != before[ids[0]])
    }

    @Test func costsOneUndoForTheWholeLayout() {
        let ids = drawn()
        _ = app.moveComponents().execute(
            MoveComponentsRequest(moves: [ComponentMove(componentId: ids[0], x: 900, y: 900)])
        )

        _ = app.arrangeDiagram().execute(ArrangeDiagramRequest())
        _ = app.undoLastChange().execute(UndoLastChangeRequest())

        #expect(positions()[ids[0]] == Point(x: 900, y: 900))
    }
}
