import ArchitectureDSL
import ThreatModelKit
import FileGateways

/// The composition root for tests. Mirrors the application's own `Dependencies`
/// but wires use cases to fakes. Gateways are deliberately private: an
/// acceptance test may only speak to the use case boundary.
public final class TestDependencies: UseCaseFactory {
    private let catalogue: InMemoryTechnologyCatalogue
    private let models: ThreatModelGateway
    /// The store, so a test can state domain facts a use case does not yet
    /// write. Every other test goes through the use cases.
    public var modelStore: ThreatModelGateway { models }
    private let ids: IdentityGenerator
    private let files: ThreatModelFileGateway = ThreatModelCodec()
    /// The project this composition root wires, so a test can put a file in
    /// it and then open it through the use cases.
    public let project = InMemoryProject()
    private var projects: ProjectSourceGateway { project }
    private let architectureSources: ArchitectureSourceGateway = HclArchitectureSource()
    private let samples: SampleModelGateway = FakeSampleModels()
    private let clock = FixedClock()
    /// The clock this root runs on, so an acceptance test can move time.
    public var time: FixedClock { clock }

    public init() {
        self.catalogue = CatalogueFixture.catalogue()
        self.models = InMemoryThreatModelGateway()
        self.ids = SequentialIdentityGenerator()
    }

    public func createThreatModel() -> CreateThreatModelUseCase {
        CreateThreatModel(models: models, catalogue: catalogue, clock: clock)
    }

    public func openThreatModel() -> OpenThreatModelUseCase {
        OpenThreatModel(models: models, catalogue: catalogue, files: files)
    }

    public func saveThreatModel() -> SaveThreatModelUseCase {
        SaveThreatModel(models: models, catalogue: catalogue, clock: clock, files: files)
    }

    public func renameThreatModel() -> RenameThreatModelUseCase {
        RenameThreatModel(models: models, clock: clock)
    }

    public func copySelection() -> CopySelectionUseCase {
        CopySelection(models: models, files: files)
    }

    public func pasteSelection() -> PasteSelectionUseCase {
        PasteSelection(models: models, ids: ids, files: files)
    }

    public func duplicateSelection() -> DuplicateSelectionUseCase {
        DuplicateSelection(models: models, ids: ids)
    }

    public func undoLastChange() -> UndoLastChangeUseCase {
        UndoLastChange(models: models)
    }

    public func redoChange() -> RedoChangeUseCase {
        RedoChange(models: models)
    }

    public func createCustomTechnology() -> CreateCustomTechnologyUseCase {
        CreateCustomTechnology(models: models, catalogue: catalogue, ids: ids)
    }

    public func editCustomTechnology() -> EditCustomTechnologyUseCase {
        EditCustomTechnology(models: models, catalogue: catalogue)
    }

    public func deleteCustomTechnology() -> DeleteCustomTechnologyUseCase {
        DeleteCustomTechnology(models: models)
    }

    public func viewCustomTechnology() -> ViewCustomTechnologyUseCase {
        ViewCustomTechnology(models: models)
    }

    public func buildThreatModelReport() -> BuildThreatModelReportUseCase {
        BuildThreatModelReport(models: models, catalogue: catalogue)
    }

    public func exportModelAsMarkdown() -> ExportModelAsMarkdownUseCase {
        ExportModelAsMarkdown(reports: buildThreatModelReport())
    }

    public func setComponentProperties() -> SetComponentPropertiesUseCase {
        SetComponentProperties(models: models)
    }

    public func layOutModel() -> LayOutModelUseCase {
        LayOutModel()
    }

    public func importArchitecture() -> ImportArchitectureUseCase {
        ImportArchitecture(
            models: models,
            catalogue: catalogue,
            sources: architectureSources,
            layout: layOutModel()
        )
    }

    public func exportArchitecture() -> ExportArchitectureUseCase {
        ExportArchitecture(models: models, sources: architectureSources)
    }

    public func openProject() -> OpenProjectUseCase {
        OpenProject(projects: projects)
    }

    public func openSystem() -> OpenSystemUseCase {
        OpenSystem(projects: projects, imports: importArchitecture())
    }

    public func saveSystem() -> SaveSystemUseCase {
        SaveSystem(projects: projects, exports: exportArchitecture())
    }

    public func viewCatalogueVersion() -> ViewCatalogueVersionUseCase {
        ViewCatalogueVersion(catalogue: catalogue)
    }

    public func listSampleModels() -> ListSampleModelsUseCase {
        ListSampleModels(samples: samples)
    }

    public func loadSampleModel() -> LoadSampleModelUseCase {
        LoadSampleModel(models: models, samples: samples, files: files)
    }

    public func exportModelAsPdf() -> ExportModelAsPdfUseCase {
        ExportModelAsPdf(reports: buildThreatModelReport(), renderer: FakeReportRenderer())
    }

    public func exportModelAsImage() -> ExportModelAsImageUseCase {
        ExportModelAsImage(models: models)
    }

    public func exportModelAsThreatcl() -> ExportModelAsThreatclUseCase {
        ExportModelAsThreatcl(reports: buildThreatModelReport())
    }

    public func listThreatChoices() -> ListThreatChoicesUseCase {
        ListThreatChoices(catalogue: catalogue)
    }

    public func listTechnologies() -> ListTechnologiesUseCase {
        ListTechnologies(models: models, catalogue: catalogue)
    }

    public func viewThreatModel() -> ViewThreatModelUseCase {
        ViewThreatModel(models: models, catalogue: catalogue)
    }

    public func addComponent() -> AddComponentUseCase {
        AddComponent(models: models, catalogue: catalogue, ids: ids)
    }

    public func moveComponents() -> MoveComponentsUseCase {
        MoveComponents(models: models)
    }

    public func removeComponents() -> RemoveComponentsUseCase {
        RemoveComponents(models: models)
    }

    public func connectComponents() -> ConnectComponentsUseCase {
        ConnectComponents(models: models, ids: ids)
    }

    public func removeConnection() -> RemoveConnectionUseCase {
        RemoveConnection(models: models)
    }

    public func addZone() -> AddZoneUseCase {
        AddZone(models: models, ids: ids)
    }

    public func resizeZone() -> ResizeZoneUseCase {
        ResizeZone(models: models)
    }

    public func setZoneProperties() -> SetZonePropertiesUseCase {
        SetZoneProperties(models: models)
    }

    public func removeZone() -> RemoveZoneUseCase {
        RemoveZone(models: models)
    }

    public func overrideThreatSeverity() -> OverrideThreatSeverityUseCase {
        OverrideThreatSeverity(models: models, catalogue: catalogue)
    }

    public func clearSeverityOverride() -> ClearSeverityOverrideUseCase {
        ClearSeverityOverride(models: models)
    }

    public func recordControlImplemented() -> RecordControlImplementedUseCase {
        RecordControlImplemented(models: models)
    }

    public func recordControlNotImplemented() -> RecordControlNotImplementedUseCase {
        RecordControlNotImplemented(models: models)
    }

    public func summariseRisk() -> SummariseRiskUseCase {
        SummariseRisk(models: models, catalogue: catalogue)
    }

    public func listPathwayMitigations() -> ListPathwayMitigationsUseCase {
        ListPathwayMitigations(models: models, catalogue: catalogue)
    }

    public func configurePathwayMitigations() -> ConfigurePathwayMitigationsUseCase {
        ConfigurePathwayMitigations(models: models, catalogue: catalogue)
    }

    public func assessThreatModel() -> AssessThreatModelUseCase {
        AssessThreatModel(models: models, catalogue: catalogue)
    }
}
