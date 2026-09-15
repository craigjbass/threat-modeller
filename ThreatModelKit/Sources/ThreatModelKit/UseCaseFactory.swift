/// The set of use cases a delivery mechanism may call.
///
/// Two composition roots conform: `Dependencies` in the application, wired to
/// real gateways, and `TestDependencies` in `TestSupport`, wired to fakes.
/// The protocol keeps the two in step. A use case added here does not compile
/// until both roots vend it.
public protocol UseCaseFactory: Sendable {
    func createThreatModel() -> CreateThreatModelUseCase
    func openThreatModel() -> OpenThreatModelUseCase
    func saveThreatModel() -> SaveThreatModelUseCase
    func renameThreatModel() -> RenameThreatModelUseCase
    func copySelection() -> CopySelectionUseCase
    func pasteSelection() -> PasteSelectionUseCase
    func duplicateSelection() -> DuplicateSelectionUseCase
    func undoLastChange() -> UndoLastChangeUseCase
    func redoChange() -> RedoChangeUseCase
    func createCustomTechnology() -> CreateCustomTechnologyUseCase
    func editCustomTechnology() -> EditCustomTechnologyUseCase
    func deleteCustomTechnology() -> DeleteCustomTechnologyUseCase
    func listThreatChoices() -> ListThreatChoicesUseCase
    func buildThreatModelReport() -> BuildThreatModelReportUseCase
    func exportModelAsMarkdown() -> ExportModelAsMarkdownUseCase
    func exportModelAsHtml() -> ExportModelAsHtmlUseCase
    func exportModelAsThreatcl() -> ExportModelAsThreatclUseCase
    func exportModelAsImage() -> ExportModelAsImageUseCase
    func setComponentProperties() -> SetComponentPropertiesUseCase
    /// Where the layout search says how it is going, or nil when this root
    /// does not report.
    var layoutProgress: LayoutProgress? { get }

    func layOutModel() -> LayOutModelUseCase
    func importArchitecture() -> ImportArchitectureUseCase
    func exportArchitecture() -> ExportArchitectureUseCase
    func setControlStatus() -> SetControlStatusUseCase
    func listStaleAnswers() -> ListStaleAnswersUseCase
    func removeStaleAnswer() -> RemoveStaleAnswerUseCase
    func setLikelihoodFinding() -> SetLikelihoodFindingUseCase
    func removeLikelihoodFinding() -> RemoveLikelihoodFindingUseCase
    func setMitigatesEdge() -> SetMitigatesEdgeUseCase
    func removeMitigatesEdge() -> RemoveMitigatesEdgeUseCase
    func setAssumption() -> SetAssumptionUseCase
    func removeAssumption() -> RemoveAssumptionUseCase
    func setSystemUseCase() -> SetSystemUseCaseUseCase
    func removeSystemUseCase() -> RemoveSystemUseCaseUseCase
    func setExclusion() -> SetExclusionUseCase
    func removeExclusion() -> RemoveExclusionUseCase
    func setSystemAsset() -> SetSystemAssetUseCase
    func removeSystemAsset() -> RemoveSystemAssetUseCase
    func setConnectionAssets() -> SetConnectionAssetsUseCase
    func setCompensatingControl() -> SetCompensatingControlUseCase
    func compileControls() -> CompileControlsUseCase
    func applyControlAnswers() -> ApplyControlAnswersUseCase
    func checkControlAnswers() -> CheckControlAnswersUseCase
    func compileGovernance() -> CompileGovernanceUseCase
    func applyGovernance() -> ApplyGovernanceUseCase
    func checkGovernance() -> CheckGovernanceUseCase
    func readRiskHistory() -> ReadRiskHistoryUseCase
    func checkPolicy() -> CheckPolicyUseCase
    func applyPolicy() -> ApplyPolicyUseCase
    func openProject() -> OpenProjectUseCase
    func readProjectFingerprint() -> ReadProjectFingerprintUseCase
    func initialiseProject() -> InitialiseProjectUseCase
    func openSystem() -> OpenSystemUseCase
    func saveSystem() -> SaveSystemUseCase
    func saveSystemAnswers() -> SaveSystemAnswersUseCase
    func compileSystemReport() -> CompileSystemReportUseCase
    func viewCatalogueVersion() -> ViewCatalogueVersionUseCase
    func adoptCatalogueVersion() -> AdoptCatalogueVersionUseCase
    func listSampleModels() -> ListSampleModelsUseCase
    func loadSampleModel() -> LoadSampleModelUseCase
    func viewCustomTechnology() -> ViewCustomTechnologyUseCase
    func listTechnologies() -> ListTechnologiesUseCase
    func viewThreatModel() -> ViewThreatModelUseCase
    func addComponent() -> AddComponentUseCase
    func moveComponents() -> MoveComponentsUseCase
    func removeComponents() -> RemoveComponentsUseCase
    func connectComponents() -> ConnectComponentsUseCase
    func removeConnection() -> RemoveConnectionUseCase
    func setConnectionProperties() -> SetConnectionPropertiesUseCase
    func labelConnection() -> LabelConnectionUseCase
    func reverseConnection() -> ReverseConnectionUseCase
    func addZone() -> AddZoneUseCase
    func resizeZone() -> ResizeZoneUseCase
    func changeComponentTechnology() -> ChangeComponentTechnologyUseCase
    func arrangeDiagram() -> ArrangeDiagramUseCase
    func previewSampleModel() -> PreviewSampleModelUseCase
    func listCategories() -> ListCategoriesUseCase
    func listClassifications() -> ListClassificationsUseCase
    func moveTechnologyToLibrary() -> MoveTechnologyToLibraryUseCase
    /// What fetches a library, so the window can stop a fetch in flight.
    var fetcher: LibraryFetching { get }
    func readLibraryIndex() -> ReadLibraryIndexUseCase
    func synchroniseAttack() -> SynchroniseAttackUseCase
    func verifyAttack() -> VerifyAttackUseCase
    func listThreatActorsInUse() -> ListThreatActorsInUseUseCase
    /// The ATT&CK release this project states, or the one this application
    /// offers when it states none.
    func attackTag(root: String) -> String
    /// Reads the ATT&CK data again, after a synchronise wrote it.
    func forgetAttackData()
    func moveZones() -> MoveZonesUseCase
    func reorderZones() -> ReorderZonesUseCase
    func setZoneProperties() -> SetZonePropertiesUseCase
    func removeZone() -> RemoveZoneUseCase
    func overrideThreatSeverity() -> OverrideThreatSeverityUseCase
    func clearSeverityOverride() -> ClearSeverityOverrideUseCase
    func recordControlImplemented() -> RecordControlImplementedUseCase
    func recordControlNotImplemented() -> RecordControlNotImplementedUseCase
    func summariseRisk() -> SummariseRiskUseCase
    func listPathwayMitigations() -> ListPathwayMitigationsUseCase
    func configurePathwayMitigations() -> ConfigurePathwayMitigationsUseCase
    func assessThreatModel() -> AssessThreatModelUseCase
    func assessLeverage() -> AssessLeverageUseCase
    func loadLibraries() -> LoadLibrariesUseCase
    /// What the open project's libraries are, for every use case this root
    /// builds after the call.
    func useLibraries(_ libraries: [Library])
    func addLibrary() -> AddLibraryUseCase
    func updateLibraries() -> UpdateLibrariesUseCase
    func removeLibrary() -> RemoveLibraryUseCase
    func listLibraries() -> ListLibrariesUseCase
    func listOutdatedLibraries() -> ListOutdatedLibrariesUseCase
}

public extension UseCaseFactory {
    var layoutProgress: LayoutProgress? { nil }
}
