public protocol SaveSystemAnswersUseCase {
    func execute(_ request: SaveSystemAnswersRequest) -> SaveSystemAnswersResponse
}

public struct SaveSystemAnswersRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String

    public init(root: String, systemName: String) {
        self.root = root
        self.systemName = systemName
    }
}

public enum SaveSystemAnswersResponse: Equatable, Sendable {
    case saved(controlsPath: String, answered: Int, unanswered: Int, stale: Int)
    case noSuchSystem
    case refused(diagnostics: [Diagnostic])
    case cannotWrite(reason: String)
}

/// Merges what is on screen into the system's controls file.
///
/// The merge is `CompileControls`, so the application and the executable write
/// the same file from the same model.
public struct SaveSystemAnswers: SaveSystemAnswersUseCase {
    private let projects: ProjectSourceGateway
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue
    private let exports: ExportArchitectureUseCase
    private let compiles: CompileControlsUseCase
    private let controlsSources: ControlsSourceGateway
    private let governs: CompileGovernanceUseCase
    private let architectureSources: ArchitectureSourceGateway

    public init(
        projects: ProjectSourceGateway,
        models: ThreatModelGateway,
        catalogue: TechnologyCatalogue,
        exports: ExportArchitectureUseCase,
        compiles: CompileControlsUseCase,
        controlsSources: ControlsSourceGateway,
        governs: CompileGovernanceUseCase,
        architectureSources: ArchitectureSourceGateway
    ) {
        self.projects = projects
        self.models = models
        self.catalogue = catalogue
        self.exports = exports
        self.compiles = compiles
        self.controlsSources = controlsSources
        self.governs = governs
        self.architectureSources = architectureSources
    }

    public func execute(_ request: SaveSystemAnswersRequest) -> SaveSystemAnswersResponse {
        let system: ProjectSystem
        do {
            guard let found = try projects.discover(root: request.root)
                .system(named: request.systemName) else {
                return .noSuchSystem
            }
            system = found
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }

        // What is on screen, said as text, so the merge reads one architecture.
        let architectureText = exports.execute(ExportArchitectureRequest()).text
        let existing = projects.exists(path: system.controlsPath)
            ? try? projects.read(path: system.controlsPath)
            : nil

        let merged = compiles.execute(
            CompileControlsRequest(architectureText: architectureText, controlsText: existing)
        )
        guard case .compiled(let text, _, _, _, _, _, _) = merged else {
            guard case .refused(let diagnostics) = merged else { return .refused(diagnostics: []) }
            return .refused(diagnostics: diagnostics)
        }

        // The answers the user changed on screen win over the compiled stub.
        let onScreen = Self.answers(in: models.current(), catalogue: catalogue)
        guard let compiled = controlsSources.read(text).source else {
            return .refused(diagnostics: controlsSources.read(text).diagnostics)
        }

        var answered = 0
        var unanswered = 0
        var stale = 0
        let answers = compiled.answers.map { answer -> SourceThreatAnswer in
            guard answer.isStale == false else {
                stale += 1
                return answer
            }
            let updated = SourceThreatAnswer(
                threatId: answer.threatId,
                sourceKind: answer.sourceKind,
                sourceId: answer.sourceId,
                severityLabel: answer.severityLabel,
                score: answer.score,
                // This merge keeps the file's own likelihood block as it
                // stands. `WriteLikelihoodFinding` is the one place that
                // changes a likelihood block, so this save and that writer
                // never disagree about the same block.
                likelihood: answer.likelihood,
                severityDecision: answer.severityDecision,
                impacts: answer.impacts,
                controls: answer.controls.map { control in
                    SourceControlAnswer(
                        description: control.description,
                        status: onScreen.statuses[answer.key]?[control.description] ?? control.status,
                        note: onScreen.notes[answer.key]?[control.description] ?? control.note,
                        proof: onScreen.proofs[answer.key]?[control.description] ?? control.proof
                    )
                },
                compensating: onScreen.compensating[answer.key] ?? answer.compensating,
                recommendations: answer.recommendations
            )
            if updated.isAnswered { answered += 1 } else { unanswered += 1 }
            return updated
        }

        let savedControls = controlsSources.write(
            ControlsSource(
                systemName: compiled.systemName,
                catalogueTag: compiled.catalogueTag,
                riskTolerance: compiled.riskTolerance,
                answers: answers
            )
        )
        do {
            try projects.write(savedControls, to: system.controlsPath)
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }

        // The governance file is written from the answers this save just
        // wrote, the way the executable writes it after a compile, so the
        // window and the executable never disagree about what is governed.
        let governance = governs.execute(
            CompileGovernanceRequest(
                controlsText: savedControls,
                governanceText: projects.exists(path: system.governancePath)
                    ? try? projects.read(path: system.governancePath)
                    : nil,
                actionLabels: Self.actionLabels(
                    of: architectureText,
                    sources: architectureSources
                )
            )
        )
        switch governance {
        case .compiled(let governanceText, _, _):
            // A system that governs nothing writes no file.
            if let governanceText {
                do {
                    try projects.write(governanceText, to: system.governancePath)
                } catch {
                    return .cannotWrite(reason: String(describing: error))
                }
            }
        case .refused(let diagnostics):
            return .refused(diagnostics: diagnostics)
        }

        return .saved(
            controlsPath: system.controlsPath,
            answered: answered,
            unanswered: unanswered,
            stale: stale
        )
    }

    /// The labels the architecture's actions carry, in the order the file
    /// declares them. The governance file governs each one.
    private static func actionLabels(
        of architectureText: String,
        sources: ArchitectureSourceGateway
    ) -> [String] {
        guard let source = sources.read(architectureText).source else { return [] }

        var labels: [String] = []
        for edge in source.mitigates {
            guard let label = edge.action?.label, labels.contains(label) == false else { continue }
            labels.append(label)
        }
        return labels
    }

    /// What the model on screen says, keyed the way a file keys it.
    private static func answers(
        in model: ThreatModel,
        catalogue: TechnologyCatalogue
    ) -> (
        statuses: [ThreatKey: [String: ControlStatus]],
        proofs: [ThreatKey: [String: ControlProof]],
        notes: [ThreatKey: [String: String]],
        compensating: [ThreatKey: [CompensatingControl]]
    ) {
        var statuses: [ThreatKey: [String: ControlStatus]] = [:]
        var proofs: [ThreatKey: [String: ControlProof]] = [:]
        var notes: [ThreatKey: [String: String]] = [:]

        for threat in ThreatResolver(model: model, catalogue: catalogue).resolve() {
            let key = ThreatKey(threatId: threat.threat.id.value, sourceId: threat.source.id)
            statuses[key] = Dictionary(
                threat.controls.map { ($0.description, $0.status) },
                uniquingKeysWith: { first, _ in first }
            )
            // Every offered control lands here, empty proof included, so a
            // proof cleared on screen clears in the file.
            proofs[key] = Dictionary(
                threat.controls.map { ($0.description, model.controlProofs[$0.key] ?? ControlProof()) },
                uniquingKeysWith: { first, _ in first }
            )
            // Every offered control lands here, empty note included, so a
            // note cleared on screen clears in the file.
            notes[key] = Dictionary(
                threat.controls.map { ($0.description, model.controlNotes[$0.key] ?? "") },
                uniquingKeysWith: { first, _ in first }
            )
        }

        return (statuses, proofs, notes, model.compensatingControls)
    }
}
