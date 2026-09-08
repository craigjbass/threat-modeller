import Testing
import ThreatModelKit
import TestSupport

struct HistoryTests {
    private let models = InMemoryThreatModelGateway()
    private let catalogue = CatalogueFixture.catalogue()
    private let ids = SequentialIdentityGenerator()

    private func addComponent(x: Double = 0) {
        _ = AddComponent(models: models, catalogue: catalogue, ids: ids)
            .execute(AddComponentRequest(technologyId: "aws-ec2", x: x, y: 0, sensitivity: "internal"))
    }

    private func undo() -> UndoLastChangeResponse {
        UndoLastChange(models: models).execute(UndoLastChangeRequest())
    }

    private func redo() -> RedoChangeResponse {
        RedoChange(models: models).execute(RedoChangeRequest())
    }

    @Test func saysThereIsNothingToTakeBackOnAFreshModel() {
        #expect(undo() == .nothingToUndo)
        #expect(redo() == .nothingToRedo)
    }

    @Test func takesBackOneChange() {
        addComponent()
        addComponent(x: 300)
        #expect(models.current().components.count == 2)

        #expect(undo() == .undone(canUndoMore: true))
        #expect(models.current().components.count == 1)

        #expect(undo() == .undone(canUndoMore: false))
        #expect(models.current().components.isEmpty)

        #expect(undo() == .nothingToUndo)
    }

    @Test func putsBackWhatWasTakenBack() {
        addComponent()
        _ = undo()

        #expect(redo() == .redone(canRedoMore: false))
        #expect(models.current().components.count == 1)
        #expect(redo() == .nothingToRedo)
    }

    @Test func takesBackEveryKindOfChange() {
        addComponent()
        let id = models.current().components[0].id.value

        _ = MoveComponents(models: models)
            .execute(MoveComponentsRequest(moves: [ComponentMove(componentId: id, x: 500, y: 500)]))
        #expect(models.current().components[0].position == Point(x: 500, y: 500))

        _ = undo()
        #expect(models.current().components[0].position == Point(x: 0, y: 0))

        _ = AddZone(models: models, ids: ids).execute(AddZoneRequest(x: 0, y: 0, width: 400, height: 300))
        #expect(models.current().zones.count == 1)
        _ = undo()
        #expect(models.current().zones.isEmpty)

        _ = RecordControlImplemented(models: models)
            .execute(RecordControlImplementedRequest(controlKey: "node:x:y::deadbeef"))
        _ = undo()
        #expect(models.current().implementedControls.isEmpty)
    }

    @Test func neverCountsARefusedChangeAsAStep() {
        addComponent()

        // Every one of these is refused and changes nothing.
        _ = AddComponent(models: models, catalogue: catalogue, ids: ids)
            .execute(AddComponentRequest(technologyId: "aws-imaginary", x: 0, y: 0, sensitivity: "internal"))
        _ = MoveComponents(models: models)
            .execute(MoveComponentsRequest(moves: [ComponentMove(componentId: "nope", x: 1, y: 1)]))
        _ = RemoveZone(models: models).execute(RemoveZoneRequest(zoneId: "nope"))

        // One undo takes the model back to empty, because only one thing
        // actually happened.
        #expect(undo() == .undone(canUndoMore: false))
        #expect(models.current().components.isEmpty)
    }
}
