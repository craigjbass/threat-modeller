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
    /// The last resolution, kept so one change runs the resolver once.
    private let resolutions = ThreatResolutionCache()
    /// The vendored catalogue and the open project's libraries, read as one.
    private var catalogue: TechnologyCatalogue { MergedCatalogue(base: base, store: libraries, mitre: mitreActors) }
    private let models: ThreatModelGateway
    private let ids: IdentityGenerator
    private let files: ThreatModelFileGateway = ThreatModelCodec()
    private let projects: ProjectSourceGateway = FileSystemProject()
    private let architectureSources: ArchitectureSourceGateway = HclArchitectureSource()
    private let controlsSources: ControlsSourceGateway = HclControlsSource()
    private let librarySources: LibrarySourceGateway = HclLibrarySource()
    private let governanceSources: GovernanceSourceGateway = HclGovernanceSource()
    private let policySources: PolicySourceGateway = HclPolicySource()
    private let history: GitHistoryGateway = GitHistory()
    private let attackTreeSources: AttackTreeSourceGateway = HclAttackTreeSource()
    /// The one place this application runs `git`.
    private let gitFetcher = GitLibraryFetcher()
    private var libraryFetcher: LibraryFetching { gitFetcher }
    /// The same `git`, reading an index rather than a library.
    private var libraryIndexFetcher: LibraryIndexFetching { gitFetcher }
    /// The fetcher this root wires, so the Libraries sheet can stop a fetch.
    var fetcher: LibraryFetching { libraryFetcher }
    private let samples: SampleModelGateway = BundledSampleModels()
    private let clock: Clock = SystemClock()

    init() throws {
        mitreActors = MitreActorSource(data: attackData)
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
        PasteSelection(models: models, ids: ids, files: files, catalogue: catalogue)
    }

    func duplicateSelection() -> DuplicateSelectionUseCase {
        DuplicateSelection(models: models, ids: ids, catalogue: catalogue)
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
        BuildThreatModelReport(
            models: models,
            catalogue: catalogue,
            clock: clock,
            mitre: mitreActors
        )
    }

    func exportModelAsMarkdown() -> ExportModelAsMarkdownUseCase {
        ExportModelAsMarkdown(reports: buildThreatModelReport())
    }

    func exportModelAsHtml() -> ExportModelAsHtmlUseCase {
        ExportModelAsHtml(markdown: exportModelAsMarkdown())
    }

    func exportModelAsJson() -> ExportModelAsJsonUseCase {
        ExportModelAsJson(reports: buildThreatModelReport())
    }

    func exportModelAsOtm() -> ExportModelAsOtmUseCase {
        ExportModelAsOtm(reports: buildThreatModelReport())
    }

    func setComponentProperties() -> SetComponentPropertiesUseCase {
        SetComponentProperties(models: models, catalogue: catalogue)
    }

    /// Where the layout search says how it is going. The project session
    /// listens while it opens a system, so the window can draw the diagram
    /// forming rather than nothing.
    /// Declared optional because the protocol requires an optional. A
    /// non-optional stored property does not satisfy an optional requirement,
    /// so this root silently used the default of nil and the window drew
    /// nothing while a model opened.
    let layoutProgress: LayoutProgress? = LayoutProgress()

    func layOutModel() -> LayOutModelUseCase {
        LayOutModel(progress: layoutProgress)
    }

    func importArchitecture() -> ImportArchitectureUseCase {
        ImportArchitecture(
            models: models,
            catalogue: catalogue,
            sources: architectureSources,
            attackTreeSources: attackTreeSources,
            layout: layOutModel()
        )
    }

    func exportArchitecture() -> ExportArchitectureUseCase {
        ExportArchitecture(models: models, sources: architectureSources)
    }

    func setControlStatus() -> SetControlStatusUseCase {
        SetControlStatus(models: models)
    }

    func listStaleAnswers() -> ListStaleAnswersUseCase {
        ListStaleAnswers(projects: projects, controlsSources: controlsSources)
    }

    func removeStaleAnswer() -> RemoveStaleAnswerUseCase {
        RemoveStaleAnswer(projects: projects, controlsSources: controlsSources)
    }

    func setLikelihoodFinding() -> SetLikelihoodFindingUseCase {
        SetLikelihoodFinding(models: models)
    }

    func removeLikelihoodFinding() -> RemoveLikelihoodFindingUseCase {
        RemoveLikelihoodFinding(models: models)
    }

    func setMitigatesEdge() -> SetMitigatesEdgeUseCase {
        SetMitigatesEdge(models: models)
    }

    func removeMitigatesEdge() -> RemoveMitigatesEdgeUseCase {
        RemoveMitigatesEdge(models: models)
    }

    func setAssumption() -> SetAssumptionUseCase {
        SetAssumption(models: models)
    }

    func removeAssumption() -> RemoveAssumptionUseCase {
        RemoveAssumption(models: models)
    }

    func setSystemUseCase() -> SetSystemUseCaseUseCase {
        SetSystemUseCase(models: models)
    }

    func removeSystemUseCase() -> RemoveSystemUseCaseUseCase {
        RemoveSystemUseCase(models: models)
    }

    func setExclusion() -> SetExclusionUseCase {
        SetExclusion(models: models)
    }

    func removeExclusion() -> RemoveExclusionUseCase {
        RemoveExclusion(models: models)
    }

    func setSystemAsset() -> SetSystemAssetUseCase {
        SetSystemAsset(models: models, catalogue: catalogue)
    }

    func removeSystemAsset() -> RemoveSystemAssetUseCase {
        RemoveSystemAsset(models: models)
    }

    func setConnectionAssets() -> SetConnectionAssetsUseCase {
        SetConnectionAssets(models: models)
    }

    func setCompensatingControl() -> SetCompensatingControlUseCase {
        SetCompensatingControl(models: models)
    }

    func compileControls() -> CompileControlsUseCase {
        CompileControls(
            catalogue: catalogue,
            architectureSources: architectureSources,
            controlsSources: controlsSources,
            attackTreeSources: attackTreeSources
        )
    }

    func applyControlAnswers() -> ApplyControlAnswersUseCase {
        ApplyControlAnswers(models: models, catalogue: catalogue, sources: controlsSources)
    }

    func compileGovernance() -> CompileGovernanceUseCase {
        CompileGovernance(
            controlsSources: controlsSources,
            governanceSources: governanceSources
        )
    }

    func applyGovernance() -> ApplyGovernanceUseCase {
        ApplyGovernance(models: models, sources: governanceSources)
    }

    func checkGovernance() -> CheckGovernanceUseCase {
        CheckGovernance(
            controlsSources: controlsSources,
            governanceSources: governanceSources,
            clock: clock
        )
    }

    func applyPolicy() -> ApplyPolicyUseCase {
        ApplyPolicy(models: models, sources: policySources)
    }

    func readRiskHistory() -> ReadRiskHistoryUseCase {
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

    func checkPolicy() -> CheckPolicyUseCase {
        CheckPolicy(
            policies: policySources,
            controlsSources: controlsSources,
            governanceSources: governanceSources,
            architectureSources: architectureSources
        )
    }

    func checkControlAnswers() -> CheckControlAnswersUseCase {
        CheckControlAnswers(
            compiles: compileControls(),
            sources: controlsSources,
            governance: checkGovernance(),
            policy: checkPolicy()
        )
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
            applies: applyControlAnswers(),
            governance: applyGovernance(),
            policy: applyPolicy()
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
        SaveSystem(
            projects: projects,
            exports: exportArchitecture(),
            sources: architectureSources
        )
    }

    func loadLibraries() -> LoadLibrariesUseCase {
        LoadLibraries(projects: projects, sources: librarySources, catalogue: base)
    }

    func useLibraries(_ libraries: [Library]) {
        self.libraries.set(libraries)
        // The catalogue decides what a model raises, so a library that
        // arrives makes the kept resolution stale.
        resolutions.forget()
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

    func adoptCatalogueVersion() -> AdoptCatalogueVersionUseCase {
        AdoptCatalogueVersion(models: models, catalogue: catalogue)
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

    func labelConnection() -> LabelConnectionUseCase {
        LabelConnection(models: models)
    }

    func reverseConnection() -> ReverseConnectionUseCase {
        ReverseConnection(models: models)
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

    /// Where the ATT&CK data sits on this machine, and what fetches it.
    private let attackData: AttackDataGateway = FileSystemAttackData()
    private let attackDownloader: AttackDownloading = CurlDownloader()
    /// The groups on this machine, read the first time something asks.
    let mitreActors: MitreActorSource

    func attackTag(root: String) -> String {
        guard let layout = try? projects.discover(root: root),
              let text = try? projects.read(
                  path: ProjectConvention.path(layout.directory, AttackLock.fileName)
              ),
              let lock = AttackLock.read(text) else {
            return AttackRelease.default
        }
        return lock.tag
    }

    func forgetAttackData() {
        mitreActors.forget()
    }

    func synchroniseAttack() -> SynchroniseAttackUseCase {
        SynchroniseAttack(projects: projects, data: attackData, downloader: attackDownloader)
    }

    func verifyAttack() -> VerifyAttackUseCase {
        VerifyAttack(projects: projects, data: attackData)
    }

    func listThreatActorsInUse() -> ListThreatActorsInUseUseCase {
        ListThreatActorsInUse(catalogue: catalogue, mitre: mitreActors)
    }

    func readLibraryIndex() -> ReadLibraryIndexUseCase {
        ReadLibraryIndex(indexes: libraryIndexFetcher)
    }

    func listAttackTreeSources() -> ListAttackTreeSourcesUseCase {
        ListAttackTreeSources(projects: projects, sources: attackTreeSources)
    }

    func writeAttackTree() -> WriteAttackTreeUseCase {
        WriteAttackTree(projects: projects, sources: attackTreeSources)
    }

    func removeAttackTree() -> RemoveAttackTreeUseCase {
        RemoveAttackTree(projects: projects, sources: attackTreeSources)
    }

    func moveTechnologyToLibrary() -> MoveTechnologyToLibraryUseCase {
        MoveTechnologyToLibrary(models: models, projects: projects, libraries: librarySources)
    }

    func listClassifications() -> ListClassificationsUseCase {
        ListClassifications(catalogue: catalogue)
    }

    func listCategories() -> ListCategoriesUseCase {
        ListCategories(catalogue: catalogue)
    }

    func previewSampleModel() -> PreviewSampleModelUseCase {
        PreviewSampleModel(samples: samples, files: files, catalogue: catalogue)
    }

    func arrangeDiagram() -> ArrangeDiagramUseCase {
        ArrangeDiagram(models: models, catalogue: catalogue, layout: layOutModel())
    }

    func changeComponentTechnology() -> ChangeComponentTechnologyUseCase {
        ChangeComponentTechnology(models: models, catalogue: catalogue)
    }

    func moveZones() -> MoveZonesUseCase {
        MoveZones(models: models)
    }

    func reorderZones() -> ReorderZonesUseCase {
        ReorderZones(models: models)
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
        SummariseRisk(models: models, catalogue: catalogue, cache: resolutions)
    }

    func listPathwayMitigations() -> ListPathwayMitigationsUseCase {
        ListPathwayMitigations(models: models, catalogue: catalogue)
    }

    func configurePathwayMitigations() -> ConfigurePathwayMitigationsUseCase {
        ConfigurePathwayMitigations(models: models, catalogue: catalogue)
    }

    func assessThreatModel() -> AssessThreatModelUseCase {
        AssessThreatModel(models: models, catalogue: catalogue, cache: resolutions)
    }

    func assessLeverage() -> AssessLeverageUseCase {
        AssessLeverage(models: models, catalogue: catalogue)
    }
}
