import Testing
import ThreatModelKit
import TestSupport

/// Given a change I did not mean to make
/// When I take it back
/// Then the model is as it was, and I can put the change back again
struct TakingItBackTests {
    private let app = TestDependencies()

    private func add(_ technologyId: String, x: Double) -> String {
        guard case .added(let componentId) = app.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: x, y: 100, sensitivity: "confidential")
        ) else {
            Issue.record("Expected the component to be added")
            return ""
        }
        return componentId
    }

    private func canvas() -> ViewThreatModelResponse {
        app.viewThreatModel().execute(ViewThreatModelRequest())
    }

    private func threats() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    @Test func takesBackTheLastThingIDid() {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        #expect(canvas().canUndo == false)

        let web = add("aws-ec2", x: 100)
        #expect(threats().isEmpty == false)
        #expect(canvas().canUndo)

        #expect(app.undoLastChange().execute(UndoLastChangeRequest())
                == .undone(canUndoMore: false))

        #expect(canvas().components.isEmpty)
        #expect(threats().isEmpty)
        #expect(canvas().canRedo)

        #expect(app.redoChange().execute(RedoChangeRequest()) == .redone(canRedoMore: false))
        #expect(canvas().components.map(\.id) == [web])
        #expect(threats().isEmpty == false)
    }

    @Test func takesBackEachStepInTurn() {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        _ = add("aws-ec2", x: 100)
        _ = add("aws-rds", x: 500)
        _ = app.addZone().execute(AddZoneRequest(x: 0, y: 0, width: 700, height: 600))

        #expect(canvas().zones.count == 1)
        _ = app.undoLastChange().execute(UndoLastChangeRequest())
        #expect(canvas().zones.isEmpty)
        #expect(canvas().components.count == 2)

        _ = app.undoLastChange().execute(UndoLastChangeRequest())
        #expect(canvas().components.count == 1)

        _ = app.undoLastChange().execute(UndoLastChangeRequest())
        #expect(canvas().components.isEmpty)
        #expect(canvas().canUndo == false)
    }

    @Test func forgetsTheAbandonedBranchOnceIDoSomethingElse() {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        _ = add("aws-ec2", x: 100)
        _ = app.undoLastChange().execute(UndoLastChangeRequest())
        #expect(canvas().canRedo)

        _ = add("aws-rds", x: 500)

        #expect(canvas().canRedo == false)
        #expect(canvas().components.count == 1)
    }

    @Test func copiesAndPastesAcrossTheSameModel() throws {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        let web = add("aws-ec2", x: 100)
        let database = add("aws-rds", x: 500)
        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: web, targetComponentId: database)
        )
        let before = threats().count

        guard case .copied(let payload, let componentCount, _) = app.copySelection().execute(
            CopySelectionRequest(componentIds: [web, database], zoneIds: [])
        ) else {
            Issue.record("Expected the selection to be copied")
            return
        }
        #expect(componentCount == 2)

        guard case .pasted(let componentIds, _) = app.pasteSelection().execute(
            PasteSelectionRequest(
                payload: payload,
                offsetX: PasteSelection.defaultOffset,
                offsetY: PasteSelection.defaultOffset
            )
        ) else {
            Issue.record("Expected the selection to be pasted")
            return
        }

        #expect(componentIds.count == 2)
        #expect(canvas().components.count == 4)
        #expect(canvas().connections.count == 2)
        // Twice the diagram is twice the threats.
        #expect(threats().count == before * 2)

        // And the whole paste comes back out in one step.
        _ = app.undoLastChange().execute(UndoLastChangeRequest())
        #expect(canvas().components.count == 2)
        #expect(threats().count == before)
    }

    @Test func pastesIntoADifferentModel() throws {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        let web = add("aws-ec2", x: 100)

        guard case .copied(let payload, _, _) = app.copySelection().execute(
            CopySelectionRequest(componentIds: [web], zoneIds: [])
        ) else {
            Issue.record("Expected the selection to be copied")
            return
        }

        // A different document entirely.
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Reporting"))
        #expect(canvas().components.isEmpty)

        guard case .pasted(let componentIds, _) = app.pasteSelection().execute(
            PasteSelectionRequest(payload: payload, offsetX: 0, offsetY: 0)
        ) else {
            Issue.record("Expected the selection to be pasted")
            return
        }

        #expect(canvas().components.count == 1)
        #expect(componentIds.first != web)
        #expect(canvas().components.first?.name == "EC2")
    }

    @Test func duplicatesInPlaceWithoutTouchingWhatIsOnTheClipboard() throws {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        let web = add("aws-ec2", x: 100)
        let database = add("aws-rds", x: 500)

        guard case .copied(let payload, _, _) = app.copySelection().execute(
            CopySelectionRequest(componentIds: [web], zoneIds: [])
        ) else {
            Issue.record("Expected the selection to be copied")
            return
        }

        _ = app.duplicateSelection().execute(
            DuplicateSelectionRequest(
                componentIds: [database],
                zoneIds: [],
                offsetX: PasteSelection.defaultOffset,
                offsetY: PasteSelection.defaultOffset
            )
        )
        #expect(canvas().components.count == 3)

        // What was copied is still what is on the clipboard.
        guard case .pasted = app.pasteSelection().execute(
            PasteSelectionRequest(payload: payload, offsetX: 0, offsetY: 0)
        ) else {
            Issue.record("Expected the earlier copy to still paste")
            return
        }
        #expect(canvas().components.count == 4)
    }

    @Test func neverOffersToTakeBackOpeningADocument() throws {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        _ = add("aws-ec2", x: 100)
        guard case .saved(let file) = app.saveThreatModel().execute(SaveThreatModelRequest()) else {
            Issue.record("Expected the model to be saved")
            return
        }

        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Blank"))
        _ = add("aws-rds", x: 0)
        #expect(canvas().canUndo)

        _ = app.openThreatModel().execute(OpenThreatModelRequest(data: file))

        // Undoing back into a document the user closed would be a surprise.
        #expect(canvas().canUndo == false)
        #expect(canvas().canRedo == false)
    }
}
