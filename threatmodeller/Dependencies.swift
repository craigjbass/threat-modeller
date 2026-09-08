import CatalogueGateways
import FileGateways
import ThreatModelKit

/// The composition root. One graph per open model; from Milestone 6 that means
/// one per document window. `UseCaseFactory` lives in the core so this root and
/// `TestDependencies` cannot drift apart.
nonisolated final class Dependencies: UseCaseFactory {
    private let catalogue: TechnologyCatalogue
    private let models: ThreatModelGateway
    private let ids: IdentityGenerator
    private let files: ThreatModelFileGateway = ThreatModelCodec()
    private let samples: SampleModelGateway = BundledSampleModels()
    private let clock: Clock = SystemClock()

    init() throws {
        catalogue = try BundledTechnologyCatalogue()
        models = InMemoryThreatModelGateway()
        ids = UUIDIdentityGenerator()
    }

    func createThreatModel() -> CreateThreatModelUseCase {
        CreateThreatModel(models: models, catalogue: catalogue, clock: clock)
    }

    func openThreatModel() -> OpenThreatModelUseCase {
        OpenThreatModel(models: models, catalogue: catalogue, files: files)
    }

    func saveThreatModel() -> SaveThreatModelUseCase {
        SaveThreatModel(models: models, catalogue: catalogue, clock: clock, files: files)
    }

    func renameThreatModel() -> RenameThreatModelUseCase {
        RenameThreatModel(models: models, clock: clock)
    }

    func copySelection() -> CopySelectionUseCase {
        CopySelection(models: models, files: files)
    }

    func pasteSelection() -> PasteSelectionUseCase {
        PasteSelection(models: models, ids: ids, files: files)
    }

    func duplicateSelection() -> DuplicateSelectionUseCase {
        DuplicateSelection(models: models, ids: ids)
    }

    func undoLastChange() -> UndoLastChangeUseCase {
        UndoLastChange(models: models)
    }

    func redoChange() -> RedoChangeUseCase {
        RedoChange(models: models)
    }

    func createCustomTechnology() -> CreateCustomTechnologyUseCase {
        CreateCustomTechnology(models: models, catalogue: catalogue, ids: ids)
    }

    func editCustomTechnology() -> EditCustomTechnologyUseCase {
        EditCustomTechnology(models: models, catalogue: catalogue)
    }

    func deleteCustomTechnology() -> DeleteCustomTechnologyUseCase {
        DeleteCustomTechnology(models: models)
    }

    func viewCustomTechnology() -> ViewCustomTechnologyUseCase {
        ViewCustomTechnology(models: models)
    }

    func buildThreatModelReport() -> BuildThreatModelReportUseCase {
        BuildThreatModelReport(models: models, catalogue: catalogue)
    }

    func exportModelAsMarkdown() -> ExportModelAsMarkdownUseCase {
        ExportModelAsMarkdown(reports: buildThreatModelReport())
    }

    func setComponentProperties() -> SetComponentPropertiesUseCase {
        SetComponentProperties(models: models)
    }

    func listSampleModels() -> ListSampleModelsUseCase {
        ListSampleModels(samples: samples)
    }

    func loadSampleModel() -> LoadSampleModelUseCase {
        LoadSampleModel(models: models, samples: samples, files: files)
    }

    func exportModelAsPdf() -> ExportModelAsPdfUseCase {
        ExportModelAsPdf(reports: buildThreatModelReport(), renderer: PDFReportRenderer())
    }

    func exportModelAsImage() -> ExportModelAsImageUseCase {
        ExportModelAsImage(models: models)
    }

    func exportModelAsThreatcl() -> ExportModelAsThreatclUseCase {
        ExportModelAsThreatcl(reports: buildThreatModelReport())
    }

    func listThreatChoices() -> ListThreatChoicesUseCase {
        ListThreatChoices(catalogue: catalogue)
    }

    func listTechnologies() -> ListTechnologiesUseCase {
        ListTechnologies(models: models, catalogue: catalogue)
    }

    func viewThreatModel() -> ViewThreatModelUseCase {
        ViewThreatModel(models: models, catalogue: catalogue)
    }

    func addComponent() -> AddComponentUseCase {
        AddComponent(models: models, catalogue: catalogue, ids: ids)
    }

    func moveComponents() -> MoveComponentsUseCase {
        MoveComponents(models: models)
    }

    func removeComponents() -> RemoveComponentsUseCase {
        RemoveComponents(models: models)
    }

    func connectComponents() -> ConnectComponentsUseCase {
        ConnectComponents(models: models, ids: ids)
    }

    func removeConnection() -> RemoveConnectionUseCase {
        RemoveConnection(models: models)
    }

    func addZone() -> AddZoneUseCase {
        AddZone(models: models, ids: ids)
    }

    func resizeZone() -> ResizeZoneUseCase {
        ResizeZone(models: models)
    }

    func setZoneProperties() -> SetZonePropertiesUseCase {
        SetZoneProperties(models: models)
    }

    func removeZone() -> RemoveZoneUseCase {
        RemoveZone(models: models)
    }

    func overrideThreatSeverity() -> OverrideThreatSeverityUseCase {
        OverrideThreatSeverity(models: models, catalogue: catalogue)
    }

    func clearSeverityOverride() -> ClearSeverityOverrideUseCase {
        ClearSeverityOverride(models: models)
    }

    func recordControlImplemented() -> RecordControlImplementedUseCase {
        RecordControlImplemented(models: models)
    }

    func recordControlNotImplemented() -> RecordControlNotImplementedUseCase {
        RecordControlNotImplemented(models: models)
    }

    func summariseRisk() -> SummariseRiskUseCase {
        SummariseRisk(models: models, catalogue: catalogue)
    }

    func listPathwayMitigations() -> ListPathwayMitigationsUseCase {
        ListPathwayMitigations(models: models, catalogue: catalogue)
    }

    func configurePathwayMitigations() -> ConfigurePathwayMitigationsUseCase {
        ConfigurePathwayMitigations(models: models, catalogue: catalogue)
    }

    func assessThreatModel() -> AssessThreatModelUseCase {
        AssessThreatModel(models: models, catalogue: catalogue)
    }
}
