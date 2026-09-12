import ArchitectureDSL
import ThreatModelKit

/// The composition root the executable runs on: one model in memory, one
/// system at a time.
///
/// It vends only the use cases the verbs call. Everything else traps, so a verb
/// that grows a new need is a build failure rather than a surprise at run time.
struct CommandLineDependencies {
    let catalogue: TechnologyCatalogue
    let architectureSources: ArchitectureSourceGateway
    let controlsSources: ControlsSourceGateway
    private let models: ThreatModelGateway = InMemoryThreatModelGateway()

    func layOutModel() -> LayOutModelUseCase { LayOutModel() }

    func importArchitecture() -> ImportArchitectureUseCase {
        ImportArchitecture(
            models: models,
            catalogue: catalogue,
            sources: architectureSources,
            layout: layOutModel()
        )
    }

    func compileControls() -> CompileControlsUseCase {
        CompileControls(
            catalogue: catalogue,
            architectureSources: architectureSources,
            controlsSources: controlsSources,
            layout: layOutModel()
        )
    }

    func checkControlAnswers() -> CheckControlAnswersUseCase {
        CheckControlAnswers(compiles: compileControls(), sources: controlsSources)
    }

    func applyControlAnswers() -> ApplyControlAnswersUseCase {
        ApplyControlAnswers(models: models, catalogue: catalogue, sources: controlsSources)
    }

    func buildThreatModelReport() -> BuildThreatModelReportUseCase {
        BuildThreatModelReport(models: models, catalogue: catalogue)
    }

    func viewThreatModel() -> ViewThreatModelUseCase {
        ViewThreatModel(models: models, catalogue: catalogue)
    }

    func assessThreatModel() -> AssessThreatModelUseCase {
        AssessThreatModel(models: models, catalogue: catalogue)
    }

    func exportModelAsMarkdown() -> ExportModelAsMarkdownUseCase {
        ExportModelAsMarkdown(reports: buildThreatModelReport())
    }
}
