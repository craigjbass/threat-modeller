import ArchitectureDSL
import FileGateways
import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// A catalogue that counts how many times something reads it.
final class CountingReadCatalogue: TechnologyCatalogue, @unchecked Sendable {
    private let real: TechnologyCatalogue
    private let lock = NSLock()
    private var perTechnology = 0
    private var whole = 0

    /// How many times something asked for one technology's threats.
    var perTechnologyReads: Int {
        lock.lock(); defer { lock.unlock() }
        return perTechnology
    }

    /// How many times something asked for the whole index.
    var wholeIndexReads: Int {
        lock.lock(); defer { lock.unlock() }
        return whole
    }

    init(_ real: TechnologyCatalogue) { self.real = real }

    func threatsFor(technologyId: TechnologyId) -> [Threat] {
        lock.lock(); perTechnology += 1; lock.unlock()
        return real.threatsFor(technologyId: technologyId)
    }

    func everyThreat() -> [Threat] {
        lock.lock(); whole += 1; lock.unlock()
        return real.everyThreat()
    }

    func findById(_ id: TechnologyId) -> Technology? { real.findById(id) }
    func all() -> [Technology] { real.all() }
    func providers() -> [Provider] { real.providers() }
    func connectionThreats() -> [Threat] { real.connectionThreats() }
    func zoneThreats() -> [Threat] { real.zoneThreats() }
    func taxonomy() -> Taxonomy { real.taxonomy() }
    func version() -> CatalogueVersion { real.version() }
    func pathwayMitigations() -> [PathwayMitigationDefinition] { real.pathwayMitigations() }
    func threatActors() -> [ThreatActor] { real.threatActors() }
    func findActor(_ id: ThreatActorId) -> ThreatActor? { real.findActor(id) }
    func faults() -> [CatalogueFault] { real.faults() }
}

/// The four gaps the custom technology editor had.
@Suite("A technology this model defines")
struct CustomTechnologyGapTests {
    private let app = TestDependencies()

    private func made(
        name: String = "Cribl Stream",
        controls: [String] = ["Sign the pipeline"],
        threats: [String] = ["credential-theft"]
    ) -> CreateCustomTechnologyResponse {
        app.createCustomTechnology().execute(
            CreateCustomTechnologyRequest(
                name: name,
                categoryId: "compute",
                description: "An observability pipeline",
                threatIds: threats,
                enforcesEncryption: false,
                controls: controls
            )
        )
    }

    // MARK: its own controls

    @Test func carriesItsOwnControls() throws {
        guard case .created(let technologyId) = made() else {
            Issue.record("expected the technology to be created")
            return
        }

        let held = try #require(
            app.modelStore.current().customTechnologies.first { $0.id.value == technologyId }
        )
        #expect(held.controls == ["Sign the pipeline"])
    }

    @Test func itsControlsReachTheThreatCard() throws {
        guard case .created(let technologyId) = made() else { return }
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: 0, y: 0, sensitivity: "confidential")
        )

        let threat = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats
                .first { $0.threatId == "credential-theft" }
        )

        #expect(threat.controls.contains { $0.description == "Sign the pipeline" })
    }

    @Test func itsControlsAreWrittenToTheFileAndReadBack() throws {
        guard case .created(let technologyId) = made() else { return }
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: 0, y: 0, sensitivity: "internal")
        )

        let text = app.exportArchitecture().execute(ExportArchitectureRequest()).text
        #expect(text.contains("control \"Sign the pipeline\""))

        let fresh = TestDependencies()
        _ = fresh.importArchitecture().execute(ImportArchitectureRequest(text: text))
        #expect(fresh.modelStore.current().customTechnologies.first?.controls
            == ["Sign the pipeline"])
    }

    @Test func aDocumentRoundTripKeepsItsControls() throws {
        _ = made()

        let data = try ThreatModelCodec().encode(app.modelStore.current())
        let read = try ThreatModelCodec().decode(data)

        #expect(read.customTechnologies.first?.controls == ["Sign the pipeline"])
    }

    /// A model written before this build states no controls, and opens.
    @Test func aModelWithNoControlsOpensUnchanged() throws {
        let model = ThreatModel(
            customTechnologies: [
                CustomTechnology(
                    id: TechnologyId("custom-1"),
                    name: "Cribl",
                    category: CategoryId("compute"),
                    description: "",
                    threatIds: [ThreatId("credential-theft")]
                )
            ]
        )

        let read = try ThreatModelCodec().decode(try ThreatModelCodec().encode(model))

        #expect(read.customTechnologies.first?.controls.isEmpty == true)
    }

    // MARK: two of one name

    @Test func twoTechnologiesCannotShareAName() throws {
        guard case .created(let first) = made() else { return }

        let second = made()

        #expect(second == .nameAlreadyUsed(byTechnologyId: first))
        #expect(app.modelStore.current().customTechnologies.count == 1)
    }

    @Test func theNameClashIgnoresTheCase() throws {
        _ = made(name: "Cribl Stream")

        #expect(made(name: "cribl stream") != .created(technologyId: ""))
    }

    @Test func aRenameOntoAnotherNameIsRefused() throws {
        guard case .created(let first) = made(name: "One") else { return }
        guard case .created(let second) = made(name: "Two") else { return }

        let response = app.editCustomTechnology().execute(
            EditCustomTechnologyRequest(
                technologyId: second,
                name: "One",
                categoryId: "compute",
                description: "",
                threatIds: [],
                enforcesEncryption: false
            )
        )

        #expect(response == .nameAlreadyUsed(byTechnologyId: first))
    }

    @Test func aTechnologyKeepsItsOwnName() throws {
        guard case .created(let technologyId) = made(name: "One") else { return }

        let response = app.editCustomTechnology().execute(
            EditCustomTechnologyRequest(
                technologyId: technologyId,
                name: "One",
                categoryId: "compute",
                description: "changed",
                threatIds: [],
                enforcesEncryption: false
            )
        )

        #expect(response == .updated)
    }

    // MARK: the categories the editor offers

    @Test func theEditorOffersEveryCategoryTheTaxonomyHolds() {
        let listed = app.listCategories().execute(ListCategoriesRequest()).categories

        #expect(listed.map(\.id).sorted() == ["compute", "database", "person"])
        #expect(listed == listed.sorted { $0.label < $1.label })
    }

    /// The palette lists a category only when something is in it. The taxonomy
    /// lists them all, which is what the editor needs.
    @Test func aCategoryWithNothingInItIsStillOffered() {
        let inThePalette = Set(
            app.listTechnologies().execute(ListTechnologiesRequest()).providers
                .flatMap { $0.categories.map(\.id) }
        )
        let offered = Set(app.listCategories().execute(ListCategoriesRequest()).categories.map(\.id))

        #expect(offered.isSuperset(of: inThePalette))
        #expect(offered.contains("person"))
    }

    // MARK: one indexed read

    @Test func theThreatChoicesAreOneIndexedRead() {
        let catalogue = CountingReadCatalogue(CatalogueFixture.catalogue())

        _ = ListThreatChoices(catalogue: catalogue).execute(ListThreatChoicesRequest())

        #expect(catalogue.wholeIndexReads == 1)
        #expect(catalogue.perTechnologyReads == 0)
    }

    @Test func theLookupReadsTheSameIndex() {
        let catalogue = CountingReadCatalogue(CatalogueFixture.catalogue())
        let lookup = TechnologyLookup(
            model: ThreatModel(
                customTechnologies: [
                    CustomTechnology(
                        id: TechnologyId("custom-1"),
                        name: "Cribl",
                        category: CategoryId("compute"),
                        description: "",
                        threatIds: [ThreatId("credential-theft")]
                    )
                ]
            ),
            catalogue: catalogue
        )

        _ = lookup.threatsFor(technologyId: TechnologyId("custom-1"))

        #expect(catalogue.wholeIndexReads == 1)
        #expect(catalogue.perTechnologyReads == 0)
    }
}
