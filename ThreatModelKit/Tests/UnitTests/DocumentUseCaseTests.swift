import Foundation
import Testing
import ThreatModelKit
import TestSupport
import FileGateways

struct DocumentUseCaseTests {
    private let models = InMemoryThreatModelGateway()
    private let catalogue = CatalogueFixture.catalogue()
    private let clock = FixedClock()
    private let codec = ThreatModelCodec()

    private func create(_ name: String) -> CreateThreatModelResponse {
        CreateThreatModel(models: models, catalogue: catalogue, clock: clock)
            .execute(CreateThreatModelRequest(name: name))
    }

    private func rename(_ name: String) -> RenameThreatModelResponse {
        RenameThreatModel(models: models, clock: clock)
            .execute(RenameThreatModelRequest(name: name))
    }

    private func save() -> SaveThreatModelResponse {
        SaveThreatModel(models: models, catalogue: catalogue, clock: clock, files: codec)
            .execute(SaveThreatModelRequest())
    }

    private func open(_ data: Data) -> OpenThreatModelResponse {
        OpenThreatModel(models: models, catalogue: catalogue, files: codec)
            .execute(OpenThreatModelRequest(data: data))
    }

    private func savedData() -> Data {
        guard case .saved(let data) = save() else {
            Issue.record("Expected the model to be saved")
            return Data()
        }
        return data
    }

    @Test func startsAModelNamedAndStamped() {
        #expect(create("Payments") == .created)

        let model = models.current()
        #expect(model.name == "Payments")
        #expect(model.createdAt == clock.now())
        #expect(model.updatedAt == clock.now())
        #expect(model.catalogueVersion == catalogue.version())
        #expect(model.components.isEmpty)
    }

    @Test func emptiesWhateverWasThereBefore() {
        models.save(
            ThreatModel(components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .internalData
                )
            ])
        )

        _ = create("Fresh")

        #expect(models.current().components.isEmpty)
    }

    @Test func refusesAnEmptyName() {
        #expect(create("   ") == .emptyName)
        #expect(models.current().name == "Untitled")
    }

    @Test func renamesAndTouchesTheModel() {
        _ = create("Payments")
        clock.advance(by: 60)

        #expect(rename("  Payments v2  ") == .renamed)

        #expect(models.current().name == "Payments v2")
        #expect(models.current().updatedAt == clock.now())
        // Creating is not renaming: the created time does not move.
        #expect(models.current().createdAt != models.current().updatedAt)
    }

    @Test func refusesToRenameToNothing() {
        _ = create("Payments")

        #expect(rename("") == .emptyName)
        #expect(models.current().name == "Payments")
    }

    @Test func stampsTheSaveWithTheTimeAndTheCatalogue() {
        _ = create("Payments")
        clock.advance(by: 3600)

        let data = savedData()

        #expect(models.current().updatedAt == clock.now())
        #expect(models.current().catalogueVersion == catalogue.version())
        #expect(data.isEmpty == false)
    }

    @Test func savesEverythingTheModelHolds() {
        _ = create("Payments")
        _ = AddComponent(models: models, catalogue: catalogue, ids: SequentialIdentityGenerator())
            .execute(AddComponentRequest(technologyId: "aws-ec2", x: 10, y: 20, sensitivity: "restricted"))

        let data = savedData()
        let reopened = InMemoryThreatModelGateway()
        _ = OpenThreatModel(models: reopened, catalogue: catalogue, files: codec)
            .execute(OpenThreatModelRequest(data: data))

        #expect(reopened.current().components.map(\.technologyId.value) == ["aws-ec2"])
        #expect(reopened.current().components.first?.sensitivity == .restricted)
    }

    @Test func opensWhatItSaved() {
        _ = create("Payments")
        let data = savedData()
        models.save(ThreatModel())

        #expect(open(data) == .opened(
            name: "Payments",
            drift: ThreatModelDrift(
                savedCatalogueTag: catalogue.version().tag,
                currentCatalogueTag: catalogue.version().tag,
                unknownTechnologyIds: []
            )
        ))
        #expect(models.current().name == "Payments")
    }

    @Test func leavesTheModelAloneWhenTheBytesAreNotAThreatModel() {
        _ = create("Payments")

        guard case .unreadable(let reason) = open(Data("nonsense".utf8)) else {
            Issue.record("Expected the bytes to be refused")
            return
        }
        #expect(reason.isEmpty == false)
        #expect(models.current().name == "Payments")
    }

    @Test func reportsATechnologyTheCatalogueNoLongerHolds() {
        _ = create("Payments")
        models.mutate { model in
            model.components.append(
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-retired"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .internalData
                )
            )
        }
        let data = savedData()

        guard case .opened(_, let drift) = open(data) else {
            Issue.record("Expected the model to open")
            return
        }
        #expect(drift.unknownTechnologyIds == ["aws-retired"])
        #expect(drift.hasDrift)
    }

    @Test func reportsACatalogueThatHasMovedOn() {
        _ = create("Payments")
        let data = savedData()

        let newer = InMemoryTechnologyCatalogue(
            technologies: [CatalogueFixture.ec2()],
            threats: CatalogueFixture.ec2Threats(),
            taxonomy: CatalogueFixture.taxonomy(),
            providers: CatalogueFixture.providers(),
            version: CatalogueVersion(repository: "fixture", tag: "v9.9.9")
        )

        guard case .opened(_, let drift) = OpenThreatModel(
            models: models,
            catalogue: newer,
            files: codec
        ).execute(OpenThreatModelRequest(data: data)) else {
            Issue.record("Expected the model to open")
            return
        }
        #expect(drift.savedCatalogueTag == "v0.0.0")
        #expect(drift.currentCatalogueTag == "v9.9.9")
        #expect(drift.hasDrift)
    }

    @Test func reportsNoDriftForAModelThatMatches() {
        _ = create("Payments")
        let data = savedData()

        guard case .opened(_, let drift) = open(data) else {
            Issue.record("Expected the model to open")
            return
        }
        #expect(drift.hasDrift == false)
    }

    @Test func neverTouchesTheModelJustByOpeningIt() {
        _ = create("Payments")
        let saved = savedData()
        let savedAt = models.current().updatedAt
        clock.advance(by: 9999)

        _ = open(saved)

        // Opening is reading. The updated time is what the file says.
        #expect(models.current().updatedAt == savedAt)
    }
}
