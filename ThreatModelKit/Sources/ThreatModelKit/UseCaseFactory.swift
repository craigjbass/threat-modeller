/// The set of use cases a delivery mechanism may call.
///
/// Two composition roots conform: `Dependencies` in the application, wired to
/// real gateways, and `TestDependencies` in `TestSupport`, wired to fakes.
/// The protocol keeps the two in step. A use case added here does not compile
/// until both roots vend it.
public protocol UseCaseFactory {
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
    func exportModelAsThreatcl() -> ExportModelAsThreatclUseCase
    func exportModelAsImage() -> ExportModelAsImageUseCase
    func exportModelAsPdf() -> ExportModelAsPdfUseCase
    func setComponentProperties() -> SetComponentPropertiesUseCase
    func layOutModel() -> LayOutModelUseCase
    func importArchitecture() -> ImportArchitectureUseCase
    func exportArchitecture() -> ExportArchitectureUseCase
    func compileControls() -> CompileControlsUseCase
    func applyControlAnswers() -> ApplyControlAnswersUseCase
    func checkControlAnswers() -> CheckControlAnswersUseCase
    func openProject() -> OpenProjectUseCase
    func openSystem() -> OpenSystemUseCase
    func saveSystem() -> SaveSystemUseCase
    func viewCatalogueVersion() -> ViewCatalogueVersionUseCase
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
    func addZone() -> AddZoneUseCase
    func resizeZone() -> ResizeZoneUseCase
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
}
