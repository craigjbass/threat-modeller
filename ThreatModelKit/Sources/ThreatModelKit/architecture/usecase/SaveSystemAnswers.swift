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

    public init(
        projects: ProjectSourceGateway,
        models: ThreatModelGateway,
        catalogue: TechnologyCatalogue,
        exports: ExportArchitectureUseCase,
        compiles: CompileControlsUseCase,
        controlsSources: ControlsSourceGateway
    ) {
        self.projects = projects
        self.models = models
        self.catalogue = catalogue
        self.exports = exports
        self.compiles = compiles
        self.controlsSources = controlsSources
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
        guard case .compiled(let text, _, _, _) = merged else {
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
                controls: answer.controls.map { control in
                    SourceControlAnswer(
                        description: control.description,
                        status: onScreen.statuses[answer.key]?[control.description] ?? control.status,
                        note: control.note
                    )
                },
                compensating: onScreen.compensating[answer.key] ?? answer.compensating
            )
            if updated.isAnswered { answered += 1 } else { unanswered += 1 }
            return updated
        }

        do {
            try projects.write(
                controlsSources.write(
                    ControlsSource(
                        systemName: compiled.systemName,
                        catalogueTag: compiled.catalogueTag,
                        answers: answers
                    )
                ),
                to: system.controlsPath
            )
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }

        return .saved(
            controlsPath: system.controlsPath,
            answered: answered,
            unanswered: unanswered,
            stale: stale
        )
    }

    /// What the model on screen says, keyed the way a file keys it.
    private static func answers(
        in model: ThreatModel,
        catalogue: TechnologyCatalogue
    ) -> (statuses: [ThreatKey: [String: ControlStatus]], compensating: [ThreatKey: [CompensatingControl]]) {
        var statuses: [ThreatKey: [String: ControlStatus]] = [:]

        for threat in ThreatResolver(model: model, catalogue: catalogue).resolve() {
            let key = ThreatKey(threatId: threat.threat.id.value, sourceId: threat.source.id)
            statuses[key] = Dictionary(
                threat.controls.map { ($0.description, $0.status) },
                uniquingKeysWith: { first, _ in first }
            )
        }

        return (statuses, model.compensatingControls)
    }
}
