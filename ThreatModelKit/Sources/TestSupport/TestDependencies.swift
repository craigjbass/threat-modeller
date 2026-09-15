import ArchitectureDSL
import ThreatModelKit
import FileGateways

/// The composition root for tests. Mirrors the application's own `Dependencies`
/// but wires use cases to fakes. Gateways are deliberately private: an
/// acceptance test may only speak to the use case boundary.
public final class TestDependencies: UseCaseFactory {
    /// The fixture catalogue alone.
    private let base: InMemoryTechnologyCatalogue
    /// The open project's libraries. `useLibraries` is what fills it.
    private let libraries = LibraryStore()
    /// The last resolution, kept so one change runs the resolver once.
    private let resolutions = ThreatResolutionCache()
    /// The fixture catalogue and the open project's libraries, read as one.
    private var catalogue: TechnologyCatalogue { MergedCatalogue(base: base, store: libraries, mitre: mitreActors) }
    private let models: ThreatModelGateway
    /// The store, so a test can state domain facts a use case does not yet
    /// write. Every other test goes through the use cases.
    public var modelStore: ThreatModelGateway { models }
    /// The catalogue this root wires, so a test builds a use case of its own
    /// over the same data.
    public var catalogueInUse: TechnologyCatalogue { catalogue }
    private let ids: IdentityGenerator
    private let files: ThreatModelFileGateway = ThreatModelCodec()
    /// The project this composition root wires, so a test can put a file in
    /// it and then open it through the use cases.
    public let project = InMemoryProject()
    private var projects: ProjectSourceGateway { project }
    private let architectureSources: ArchitectureSourceGateway = HclArchitectureSource()
    private let controlsSources: ControlsSourceGateway = HclControlsSource()
    private let librarySources: LibrarySourceGateway = HclLibrarySource()
    private let governanceSources: GovernanceSourceGateway = HclGovernanceSource()
    private let policySources: PolicySourceGateway = HclPolicySource()
    public let history = FakeGitHistory(root: "/work")
    private let attackTreeSources: AttackTreeSourceGateway = HclAttackTreeSource()
    /// The fetcher this root wires, so a test states what a repository holds
    /// and no test runs `git`.
    public let libraryFetcher = FakeLibraryFetcher()
    /// The fetcher this root wires, as the factory states it.
    public var fetcher: LibraryFetching { libraryFetcher }
    private let samples: SampleModelGateway = FakeSampleModels()
    private let clock = FixedClock()
    /// The clock this root runs on, so an acceptance test can move time.
    public var time: FixedClock { clock }

    public init() {
        mitreActors = MitreActorSource(data: attackData)
        self.base = CatalogueFixture.catalogue()
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
        PasteSelection(models: models, ids: ids, files: files, catalogue: catalogue)
    }

    public func duplicateSelection() -> DuplicateSelectionUseCase {
        DuplicateSelection(models: models, ids: ids, catalogue: catalogue)
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
        BuildThreatModelReport(
            models: models,
            catalogue: catalogue,
            clock: clock,
            mitre: mitreActors
        )
    }

    public func exportModelAsMarkdown() -> ExportModelAsMarkdownUseCase {
        ExportModelAsMarkdown(reports: buildThreatModelReport())
    }

    public func exportModelAsHtml() -> ExportModelAsHtmlUseCase {
        ExportModelAsHtml(markdown: exportModelAsMarkdown())
    }

    public func setComponentProperties() -> SetComponentPropertiesUseCase {
        SetComponentProperties(models: models, catalogue: catalogue)
    }

    public func layOutModel() -> LayOutModelUseCase {
        LayOutModel()
    }

    public func importArchitecture() -> ImportArchitectureUseCase {
        ImportArchitecture(
            models: models,
            catalogue: catalogue,
            sources: architectureSources,
            attackTreeSources: attackTreeSources,
            layout: layOutModel()
        )
    }

    public func exportArchitecture() -> ExportArchitectureUseCase {
        ExportArchitecture(models: models, sources: architectureSources)
    }

    public func setControlStatus() -> SetControlStatusUseCase {
        SetControlStatus(models: models)
    }

    public func listStaleAnswers() -> ListStaleAnswersUseCase {
        ListStaleAnswers(projects: projects, controlsSources: controlsSources)
    }

    public func removeStaleAnswer() -> RemoveStaleAnswerUseCase {
        RemoveStaleAnswer(projects: projects, controlsSources: controlsSources)
    }

    public func setLikelihoodFinding() -> SetLikelihoodFindingUseCase {
        SetLikelihoodFinding(models: models)
    }

    public func removeLikelihoodFinding() -> RemoveLikelihoodFindingUseCase {
        RemoveLikelihoodFinding(models: models)
    }

    public func setMitigatesEdge() -> SetMitigatesEdgeUseCase {
        SetMitigatesEdge(models: models)
    }

    public func removeMitigatesEdge() -> RemoveMitigatesEdgeUseCase {
        RemoveMitigatesEdge(models: models)
    }

    public func setAssumption() -> SetAssumptionUseCase {
        SetAssumption(models: models)
    }

    public func removeAssumption() -> RemoveAssumptionUseCase {
        RemoveAssumption(models: models)
    }

    public func setCompensatingControl() -> SetCompensatingControlUseCase {
        SetCompensatingControl(models: models)
    }

    public func compileControls() -> CompileControlsUseCase {
        CompileControls(
            catalogue: catalogue,
            architectureSources: architectureSources,
            controlsSources: controlsSources,
            attackTreeSources: attackTreeSources
        )
    }

    public func applyControlAnswers() -> ApplyControlAnswersUseCase {
        ApplyControlAnswers(models: models, catalogue: catalogue, sources: controlsSources)
    }

    public func compileGovernance() -> CompileGovernanceUseCase {
        CompileGovernance(
            controlsSources: controlsSources,
            governanceSources: governanceSources
        )
    }

    public func applyGovernance() -> ApplyGovernanceUseCase {
        ApplyGovernance(models: models, sources: governanceSources)
    }

    public func checkGovernance() -> CheckGovernanceUseCase {
        CheckGovernance(
            controlsSources: controlsSources,
            governanceSources: governanceSources,
            clock: clock
        )
    }

    public func applyPolicy() -> ApplyPolicyUseCase {
        ApplyPolicy(models: models, sources: policySources)
    }

    public func readRiskHistory() -> ReadRiskHistoryUseCase {
        ReadRiskHistory(
            projects: projects,
            history: history,
            catalogue: catalogue,
            architectureSources: architectureSources,
            controlsSources: controlsSources,
            attackTreeSources: attackTreeSources,
            governanceSources: governanceSources,
            layout: layOutModel()
        )
    }

    public func checkPolicy() -> CheckPolicyUseCase {
        CheckPolicy(
            policies: policySources,
            controlsSources: controlsSources,
            governanceSources: governanceSources,
            architectureSources: architectureSources
        )
    }

    public func checkControlAnswers() -> CheckControlAnswersUseCase {
        CheckControlAnswers(
            compiles: compileControls(),
            sources: controlsSources,
            governance: checkGovernance(),
            policy: checkPolicy()
        )
    }

    public func initialiseProject() -> InitialiseProjectUseCase {
        InitialiseProject(
            projects: projects,
            samples: samples,
            files: files,
            sources: architectureSources
        )
    }

    public func loadLibraries() -> LoadLibrariesUseCase {
        LoadLibraries(projects: projects, sources: librarySources, catalogue: base)
    }

    public func useLibraries(_ libraries: [Library]) {
        self.libraries.set(libraries)
        // The catalogue decides what a model raises, so a library that
        // arrives makes the kept resolution stale.
        resolutions.forget()
    }

    public func addLibrary() -> AddLibraryUseCase {
        AddLibrary(projects: projects, fetcher: libraryFetcher, sources: librarySources)
    }

    public func updateLibraries() -> UpdateLibrariesUseCase {
        UpdateLibraries(projects: projects, adds: addLibrary())
    }

    public func removeLibrary() -> RemoveLibraryUseCase {
        RemoveLibrary(projects: projects, architectureSources: architectureSources)
    }

    public func listLibraries() -> ListLibrariesUseCase {
        ListLibraries(
            projects: projects,
            sources: librarySources,
            verifies: VerifyLibraries(projects: projects)
        )
    }

    public func listOutdatedLibraries() -> ListOutdatedLibrariesUseCase {
        ListOutdatedLibraries(projects: projects, fetcher: libraryFetcher)
    }

    public func openProject() -> OpenProjectUseCase {
        OpenProject(projects: projects)
    }

    public func readProjectFingerprint() -> ReadProjectFingerprintUseCase {
        ReadProjectFingerprint(projects: projects)
    }

    public func openSystem() -> OpenSystemUseCase {
        OpenSystem(
            projects: projects,
            imports: importArchitecture(),
            applies: applyControlAnswers(),
            governance: applyGovernance(),
            policy: applyPolicy()
        )
    }

    public func saveSystemAnswers() -> SaveSystemAnswersUseCase {
        SaveSystemAnswers(
            projects: projects,
            models: models,
            catalogue: catalogue,
            exports: exportArchitecture(),
            compiles: compileControls(),
            controlsSources: controlsSources
        )
    }

    public func compileSystemReport() -> CompileSystemReportUseCase {
        CompileSystemReport(projects: projects, markdown: exportModelAsMarkdown())
    }

    public func saveSystem() -> SaveSystemUseCase {
        SaveSystem(
            projects: projects,
            exports: exportArchitecture(),
            sources: architectureSources
        )
    }

    public func adoptCatalogueVersion() -> AdoptCatalogueVersionUseCase {
        AdoptCatalogueVersion(models: models, catalogue: catalogue)
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

    public func labelConnection() -> LabelConnectionUseCase {
        LabelConnection(models: models)
    }

    public func reverseConnection() -> ReverseConnectionUseCase {
        ReverseConnection(models: models)
    }

    public func setConnectionProperties() -> SetConnectionPropertiesUseCase {
        SetConnectionProperties(models: models)
    }

    public func addZone() -> AddZoneUseCase {
        AddZone(models: models, ids: ids)
    }

    public func resizeZone() -> ResizeZoneUseCase {
        ResizeZone(models: models)
    }

    /// The index this root wires, so a test states what an index holds and
    /// no test reaches a server.
    public let libraryIndex = FakeLibraryIndex()

    /// The ATT&CK data this root wires, so a test states what a machine
    /// holds and nothing reaches a network.
    public let attackData = InMemoryAttackData()
    public let attackDownloader = FakeAttackDownloader()
    /// The groups on the machine, read the first time something asks.
    public let mitreActors: MitreActorSource

    public func attackTag(root: String) -> String {
        guard let layout = try? project.discover(root: root),
              let text = try? project.read(
                  path: ProjectConvention.path(layout.directory, AttackLock.fileName)
              ),
              let lock = AttackLock.read(text) else {
            return AttackRelease.default
        }
        return lock.tag
    }

    public func forgetAttackData() {
        mitreActors.forget()
    }

    public func synchroniseAttack() -> SynchroniseAttackUseCase {
        SynchroniseAttack(projects: project, data: attackData, downloader: attackDownloader)
    }

    public func verifyAttack() -> VerifyAttackUseCase {
        VerifyAttack(projects: project, data: attackData)
    }

    public func listThreatActorsInUse() -> ListThreatActorsInUseUseCase {
        ListThreatActorsInUse(catalogue: catalogue, mitre: mitreActors)
    }

    public func readLibraryIndex() -> ReadLibraryIndexUseCase {
        ReadLibraryIndex(indexes: libraryIndex)
    }

    public func moveTechnologyToLibrary() -> MoveTechnologyToLibraryUseCase {
        MoveTechnologyToLibrary(models: models, projects: project, libraries: librarySources)
    }

    public func listClassifications() -> ListClassificationsUseCase {
        ListClassifications(catalogue: catalogue)
    }

    public func listCategories() -> ListCategoriesUseCase {
        ListCategories(catalogue: catalogue)
    }

    public func previewSampleModel() -> PreviewSampleModelUseCase {
        PreviewSampleModel(samples: samples, files: files, catalogue: catalogue)
    }

    public func arrangeDiagram() -> ArrangeDiagramUseCase {
        ArrangeDiagram(models: models, catalogue: catalogue, layout: layOutModel())
    }

    public func changeComponentTechnology() -> ChangeComponentTechnologyUseCase {
        ChangeComponentTechnology(models: models, catalogue: catalogue)
    }

    public func moveZones() -> MoveZonesUseCase {
        MoveZones(models: models)
    }

    public func reorderZones() -> ReorderZonesUseCase {
        ReorderZones(models: models)
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
        SummariseRisk(models: models, catalogue: catalogue, cache: resolutions)
    }

    public func listPathwayMitigations() -> ListPathwayMitigationsUseCase {
        ListPathwayMitigations(models: models, catalogue: catalogue)
    }

    public func configurePathwayMitigations() -> ConfigurePathwayMitigationsUseCase {
        ConfigurePathwayMitigations(models: models, catalogue: catalogue)
    }

    public func assessThreatModel() -> AssessThreatModelUseCase {
        AssessThreatModel(models: models, catalogue: catalogue, cache: resolutions)
    }

    public func assessLeverage() -> AssessLeverageUseCase {
        AssessLeverage(models: models, catalogue: catalogue)
    }
}
