import CatalogueGateways
import FileGateways
import ArchitectureDSL
import ThreatModelKit

/// The composition root. One graph per open model; from Milestone 6 that means
/// one per document window. `UseCaseFactory` lives in the core so this root and
/// `TestDependencies` cannot drift apart.
nonisolated final class Dependencies: UseCaseFactory {
    /// The vendored catalogue alone.
    private let base: TechnologyCatalogue
    /// The open project's libraries. `useLibraries` is what fills it.
    private let libraries = LibraryStore()
    /// The vendored catalogue and the open project's libraries, read as one.
    private var catalogue: TechnologyCatalogue { MergedCatalogue(base: base, store: libraries) }
    private let models: ThreatModelGateway
    private let ids: IdentityGenerator
    private let files: ThreatModelFileGateway = ThreatModelCodec()
    private let projects: ProjectSourceGateway = FileSystemProject()
    private let architectureSources: ArchitectureSourceGateway = HclArchitectureSource()
    private let controlsSources: ControlsSourceGateway = HclControlsSource()
    private let librarySources: LibrarySourceGateway = HclLibrarySource()
    /// The one place this application runs `git`.
    private let libraryFetcher: LibraryFetching = GitLibraryFetcher()
    private let samples: SampleModelGateway = BundledSampleModels()
    private let clock: Clock = SystemClock()

    init() throws {
        base = try BundledTechnologyCatalogue()
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

    func layOutModel() -> LayOutModelUseCase {
        LayOutModel()
    }

    func importArchitecture() -> ImportArchitectureUseCase {
        ImportArchitecture(
            models: models,
            catalogue: catalogue,
            sources: architectureSources,
            layout: layOutModel()
        )
    }

    func exportArchitecture() -> ExportArchitectureUseCase {
        ExportArchitecture(models: models, sources: architectureSources)
    }

    func setControlStatus() -> SetControlStatusUseCase {
        SetControlStatus(models: models)
    }

    func setCompensatingControl() -> SetCompensatingControlUseCase {
        SetCompensatingControl(models: models)
    }

    func compileControls() -> CompileControlsUseCase {
        CompileControls(
            catalogue: catalogue,
            architectureSources: architectureSources,
            controlsSources: controlsSources,
            layout: layOutModel()
        )
    }

    func applyControlAnswers() -> ApplyControlAnswersUseCase {
        ApplyControlAnswers(models: models, catalogue: catalogue, sources: controlsSources)
    }

    func checkControlAnswers() -> CheckControlAnswersUseCase {
        CheckControlAnswers(compiles: compileControls(), sources: controlsSources)
    }

    func initialiseProject() -> InitialiseProjectUseCase {
        InitialiseProject(
            projects: projects,
            samples: samples,
            files: files,
            sources: architectureSources
        )
    }

    func openProject() -> OpenProjectUseCase {
        OpenProject(projects: projects)
    }

    func readProjectFingerprint() -> ReadProjectFingerprintUseCase {
        ReadProjectFingerprint(projects: projects)
    }

    func openSystem() -> OpenSystemUseCase {
        OpenSystem(
            projects: projects,
            imports: importArchitecture(),
            applies: applyControlAnswers()
        )
    }

    func saveSystemAnswers() -> SaveSystemAnswersUseCase {
        SaveSystemAnswers(
            projects: projects,
            models: models,
            catalogue: catalogue,
            exports: exportArchitecture(),
            compiles: compileControls(),
            controlsSources: controlsSources
        )
    }

    func compileSystemReport() -> CompileSystemReportUseCase {
        CompileSystemReport(projects: projects, markdown: exportModelAsMarkdown())
    }

    func saveSystem() -> SaveSystemUseCase {
        SaveSystem(projects: projects, exports: exportArchitecture())
    }

    func loadLibraries() -> LoadLibrariesUseCase {
        LoadLibraries(projects: projects, sources: librarySources, catalogue: base)
    }

    func useLibraries(_ libraries: [Library]) {
        self.libraries.set(libraries)
    }

    func addLibrary() -> AddLibraryUseCase {
        AddLibrary(projects: projects, fetcher: libraryFetcher, sources: librarySources)
    }

    func updateLibraries() -> UpdateLibrariesUseCase {
        UpdateLibraries(projects: projects, adds: addLibrary())
    }

    func removeLibrary() -> RemoveLibraryUseCase {
        RemoveLibrary(projects: projects, architectureSources: architectureSources)
    }

    func listLibraries() -> ListLibrariesUseCase {
        ListLibraries(
            projects: projects,
            sources: librarySources,
            verifies: VerifyLibraries(projects: projects)
        )
    }

    func listOutdatedLibraries() -> ListOutdatedLibrariesUseCase {
        ListOutdatedLibraries(projects: projects, fetcher: libraryFetcher)
    }

    func viewCatalogueVersion() -> ViewCatalogueVersionUseCase {
        ViewCatalogueVersion(catalogue: catalogue)
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

    func setConnectionProperties() -> SetConnectionPropertiesUseCase {
        SetConnectionProperties(models: models)
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
