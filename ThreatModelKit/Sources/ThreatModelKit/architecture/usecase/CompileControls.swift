public protocol CompileControlsUseCase {
    func execute(_ request: CompileControlsRequest) -> CompileControlsResponse
}

public struct CompileControlsRequest: Equatable, Sendable {
    public let architectureText: String
    /// The answers as they are now, or nil the first time.
    public let controlsText: String?

    public init(architectureText: String, controlsText: String? = nil) {
        self.architectureText = architectureText
        self.controlsText = controlsText
    }
}

public enum CompileControlsResponse: Equatable, Sendable {
    case compiled(text: String, answered: Int, unanswered: Int, stale: Int)
    case refused(diagnostics: [Diagnostic])
}

/// Writes every threat the architecture raises into a file a person fills in.
///
/// It never deletes an answer. An answer whose threat is still raised is kept
/// whole; a threat with no answer appears with every control unanswered; an
/// answer whose threat is no longer raised moves into a stale block and waits
/// for a person to remove it.
public struct CompileControls: CompileControlsUseCase {
    private let catalogue: TechnologyCatalogue
    private let architectureSources: ArchitectureSourceGateway
    private let controlsSources: ControlsSourceGateway
    private let layout: LayOutModelUseCase

    public init(
        catalogue: TechnologyCatalogue,
        architectureSources: ArchitectureSourceGateway,
        controlsSources: ControlsSourceGateway,
        layout: LayOutModelUseCase
    ) {
        self.catalogue = catalogue
        self.architectureSources = architectureSources
        self.controlsSources = controlsSources
        self.layout = layout
    }

    public func execute(_ request: CompileControlsRequest) -> CompileControlsResponse {
        // The architecture is imported into a store of its own, so compiling
        // never changes what is on screen.
        let store = InMemoryThreatModelGateway()
        let imported = ImportArchitecture(
            models: store,
            catalogue: catalogue,
            sources: architectureSources,
            layout: layout
        ).execute(ImportArchitectureRequest(text: request.architectureText))

        guard case .imported = imported else {
            guard case .refused(let diagnostics) = imported else {
                return .refused(diagnostics: [])
            }
            return .refused(diagnostics: diagnostics)
        }

        var existing: ControlsSource?
        if let controlsText = request.controlsText, controlsText.isEmpty == false {
            let read = controlsSources.read(controlsText)
            guard let source = read.source, read.hasErrors == false else {
                return .refused(diagnostics: read.diagnostics)
            }
            existing = source
        }

        let model = store.current()
        let resolved = ThreatResolver(model: model, catalogue: catalogue).resolve()

        var answers: [SourceThreatAnswer] = []
        var answeredKeys: Set<String> = []
        var answered = 0
        var unanswered = 0

        for threat in resolved {
            let key = ThreatKey(threatId: threat.threat.id.value, sourceId: threat.source.id)
            answeredKeys.insert(key.value)
            let previous = existing?.answer(for: key)

            // A control that has left the catalogue is dropped, and its answer
            // with it: nothing keeps an answer to a question nobody asks.
            let controls = threat.controls.map { control in
                SourceControlAnswer(
                    description: control.description,
                    status: previous?.controls
                        .first { $0.description == control.description }?.status ?? .notImplemented,
                    note: previous?.controls
                        .first { $0.description == control.description }?.note
                )
            }

            let answer = SourceThreatAnswer(
                threatId: threat.threat.id.value,
                sourceKind: SourceThreatAnswer.fileKind(Self.kind(of: threat.source)),
                sourceId: Self.identifier(of: threat.source),
                severityLabel: threat.severity.label,
                score: threat.score.value,
                likelihood: previous?.likelihood,
                severityDecision: previous?.severityDecision,
                controls: controls,
                compensating: previous?.compensating ?? [],
                recommendations: previous?.recommendations ?? [],
                isStale: false
            )
            answers.append(answer)
            if answer.isAnswered { answered += 1 } else { unanswered += 1 }
        }

        // Everything the file answered that the architecture no longer raises.
        var stale = 0
        for previous in existing?.answers ?? []
        where answeredKeys.contains(previous.key.value) == false {
            answers.append(
                SourceThreatAnswer(
                    threatId: previous.threatId,
                    sourceKind: previous.sourceKind,
                    sourceId: previous.sourceId,
                    severityLabel: previous.severityLabel,
                    score: previous.score,
                    likelihood: previous.likelihood,
                    severityDecision: previous.severityDecision,
                    controls: previous.controls,
                    compensating: previous.compensating,
                    recommendations: previous.recommendations,
                    isStale: true
                )
            )
            stale += 1
        }

        return .compiled(
            text: controlsSources.write(
                ControlsSource(
                    systemName: model.name,
                    catalogueTag: model.catalogueVersion?.tag ?? catalogue.version().tag,
                    answers: answers
                )
            ),
            answered: answered,
            unanswered: unanswered,
            stale: stale
        )
    }

    private static func kind(of source: ResolvedSource) -> String {
        switch source {
        case .component: "component"
        case .connection: "connection"
        case .zone: "zone"
        }
    }

    private static func identifier(of source: ResolvedSource) -> String {
        switch source {
        case .component(let id, _, _): id.value
        case .connection(let id, _, _): id.value
        case .zone(let id, _): id.value
        }
    }
}
