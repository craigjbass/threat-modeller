import Testing
import ThreatModelKit
import TestSupport
import FileGateways

struct ClipboardUseCaseTests {
    private let models = InMemoryThreatModelGateway()
    private let catalogue = CatalogueFixture.catalogue()
    private let ids = SequentialIdentityGenerator()
    private let codec = ThreatModelCodec()

    private func seed() -> (web: String, database: String, zone: String) {
        _ = CreateThreatModel(models: models, catalogue: catalogue, clock: FixedClock())
            .execute(CreateThreatModelRequest(name: "Payments"))

        let add = AddComponent(models: models, catalogue: catalogue, ids: ids)
        guard case .added(let web) = add.execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 100, y: 100, sensitivity: "confidential")
        ), case .added(let database) = add.execute(
            AddComponentRequest(technologyId: "aws-rds", x: 500, y: 100, sensitivity: "restricted")
        ) else {
            Issue.record("Expected two components")
            return ("", "", "")
        }
        _ = ConnectComponents(models: models, ids: ids)
            .execute(ConnectComponentsRequest(sourceComponentId: web, targetComponentId: database))
        guard case .added(let zone) = AddZone(models: models, ids: ids)
            .execute(AddZoneRequest(x: 0, y: 0, width: 700, height: 600)) else {
            Issue.record("Expected a zone")
            return ("", "", "")
        }
        return (web, database, zone)
    }

    private func copy(components: [String], zones: [String] = []) -> CopySelectionResponse {
        CopySelection(models: models, files: codec)
            .execute(CopySelectionRequest(componentIds: components, zoneIds: zones))
    }

    private func paste(_ payload: String) -> PasteSelectionResponse {
        PasteSelection(models: models, ids: ids, files: codec).execute(
            PasteSelectionRequest(
                payload: payload,
                offsetX: PasteSelection.defaultOffset,
                offsetY: PasteSelection.defaultOffset
            )
        )
    }

    private func payload(_ response: CopySelectionResponse) -> String {
        guard case .copied(let payload, _, _) = response else {
            Issue.record("Expected the selection to be copied")
            return ""
        }
        return payload
    }

    @Test func copiesNothingWhenNothingIsSelected() {
        _ = seed()

        #expect(copy(components: []) == .nothingSelected)
    }

    @Test func copiesWhatWasSelected() {
        let seeded = seed()

        guard case .copied(_, let componentCount, let zoneCount) = copy(
            components: [seeded.web, seeded.database],
            zones: [seeded.zone]
        ) else {
            Issue.record("Expected the selection to be copied")
            return
        }
        #expect(componentCount == 2)
        #expect(zoneCount == 1)
    }

    @Test func keepsOnlyTheLinksWithBothEndsInTheSelection() throws {
        let seeded = seed()

        let both = try codec.decodeSelection(payload(copy(components: [seeded.web, seeded.database])))
        #expect(both.connections.count == 1)

        let one = try codec.decodeSelection(payload(copy(components: [seeded.web])))
        #expect(one.components.count == 1)
        #expect(one.connections.isEmpty)
    }

    @Test func pastesFreshComponentsBesideTheOriginals() throws {
        let seeded = seed()
        let text = payload(copy(components: [seeded.web]))

        guard case .pasted(let componentIds, _) = paste(text) else {
            Issue.record("Expected the selection to be pasted")
            return
        }

        #expect(componentIds.count == 1)
        #expect(componentIds.first != seeded.web)
        #expect(models.current().components.count == 3)

        let pastedId = try #require(componentIds.first)
        let pasted = try #require(models.current().component(ComponentId(pastedId)))
        let original = try #require(models.current().component(ComponentId(seeded.web)))
        #expect(pasted.position == Point(
            x: original.position.x + PasteSelection.defaultOffset,
            y: original.position.y + PasteSelection.defaultOffset
        ))
        #expect(pasted.technologyId == original.technologyId)
        #expect(pasted.sensitivity == original.sensitivity)
    }

    @Test func rewiresACopiedLinkOntoTheNewComponents() throws {
        let seeded = seed()
        let text = payload(copy(components: [seeded.web, seeded.database]))

        guard case .pasted(let componentIds, _) = paste(text) else {
            Issue.record("Expected the selection to be pasted")
            return
        }

        #expect(models.current().connections.count == 2)
        let pasted = try #require(models.current().connections.last)
        #expect(componentIds.contains(pasted.source.value))
        #expect(componentIds.contains(pasted.target.value))
        // The copy is a copy, not a second reference to the original.
        #expect(pasted.source.value != seeded.web)
    }

    @Test func pastesAZoneToo() throws {
        let seeded = seed()
        let text = payload(copy(components: [], zones: [seeded.zone]))

        guard case .pasted(_, let zoneIds) = paste(text) else {
            Issue.record("Expected the selection to be pasted")
            return
        }

        #expect(zoneIds.count == 1)
        #expect(zoneIds.first != seeded.zone)
        #expect(models.current().zones.count == 2)
    }

    @Test func refusesClipboardTextItCannotRead() {
        _ = seed()
        let before = models.current()

        guard case .unreadable = paste("someone copied a sentence") else {
            Issue.record("Expected the text to be refused")
            return
        }
        #expect(models.current() == before)
    }

    @Test func saysThereIsNothingToPasteForAnEmptySnippet() throws {
        _ = seed()
        let empty = try codec.encodeSelection(
            SelectionSnippet(components: [], connections: [], zones: [])
        )

        #expect(paste(empty) == .nothingToPaste)
    }

    @Test func pastesAsOneStepToTakeBack() {
        let seeded = seed()
        let text = payload(copy(components: [seeded.web, seeded.database]))
        let before = models.current()

        _ = paste(text)
        #expect(models.current().components.count == 4)

        #expect(UndoLastChange(models: models).execute(UndoLastChangeRequest())
                == .undone(canUndoMore: true))
        #expect(models.current() == before)
    }

    @Test func duplicatesWithoutTouchingTheClipboard() throws {
        let seeded = seed()

        guard case .duplicated(let componentIds, _) = DuplicateSelection(
            models: models,
            ids: ids
        ).execute(
            DuplicateSelectionRequest(
                componentIds: [seeded.web],
                zoneIds: [],
                offsetX: PasteSelection.defaultOffset,
                offsetY: PasteSelection.defaultOffset
            )
        ) else {
            Issue.record("Expected the selection to be duplicated")
            return
        }

        #expect(componentIds.count == 1)
        #expect(componentIds.first != seeded.web)
        #expect(models.current().components.count == 3)
    }

    @Test func duplicatesNothingWhenNothingIsSelected() {
        _ = seed()

        #expect(DuplicateSelection(models: models, ids: ids).execute(
            DuplicateSelectionRequest(componentIds: [], zoneIds: [], offsetX: 0, offsetY: 0)
        ) == .nothingSelected)
    }
}
