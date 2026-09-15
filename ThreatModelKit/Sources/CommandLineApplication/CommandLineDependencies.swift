import ArchitectureDSL
import ThreatModelKit

/// The composition root the executable runs on: one model in memory, one
/// system at a time.
///
/// It vends only the use cases the verbs call. Everything else traps, so a verb
/// that grows a new need is a build failure rather than a surprise at run time.
struct CommandLineDependencies {
    let catalogue: TechnologyCatalogue
    /// The ATT&CK groups on this machine, so a report reads a technique's
    /// name beside its id.
    var mitre: MitreActorSource?
    let architectureSources: ArchitectureSourceGateway
    let controlsSources: ControlsSourceGateway
    let attackTreeSources: AttackTreeSourceGateway = HclAttackTreeSource()
    let governanceSources: GovernanceSourceGateway = HclGovernanceSource()
    let policySources: PolicySourceGateway = HclPolicySource()
    let history: GitHistoryGateway
    /// The day a review date is measured against.
    let clock: Clock = SystemClock()
    private let models: ThreatModelGateway = InMemoryThreatModelGateway()

    func layOutModel() -> LayOutModelUseCase { LayOutModel() }

    func importArchitecture() -> ImportArchitectureUseCase {
        ImportArchitecture(
            models: models,
            catalogue: catalogue,
            sources: architectureSources,
            attackTreeSources: attackTreeSources,
            layout: layOutModel()
        )
    }

    func compileControls() -> CompileControlsUseCase {
        CompileControls(
            catalogue: catalogue,
            architectureSources: architectureSources,
            controlsSources: controlsSources,
            attackTreeSources: attackTreeSources
        )
    }

    func compileGovernance() -> CompileGovernanceUseCase {
        CompileGovernance(controlsSources: controlsSources, governanceSources: governanceSources)
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

    func applyControlAnswers() -> ApplyControlAnswersUseCase {
        ApplyControlAnswers(models: models, catalogue: catalogue, sources: controlsSources)
    }

    func buildThreatModelReport() -> BuildThreatModelReportUseCase {
        BuildThreatModelReport(
            models: models,
            catalogue: catalogue,
            clock: clock,
            mitre: mitre
        )
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

    func exportModelAsHtml() -> ExportModelAsHtmlUseCase {
        ExportModelAsHtml(markdown: exportModelAsMarkdown())
    }
}
