public protocol CompileControlsUseCase {
    func execute(_ request: CompileControlsRequest) -> CompileControlsResponse
}

public struct CompileControlsRequest: Equatable, Sendable {
    public let architectureText: String
    /// The answers as they are now, or nil the first time.
    public let controlsText: String?
    /// The trees a person wrote, or nil when the project holds no such file.
    public let attackTreeText: String?

    public init(
        architectureText: String,
        controlsText: String? = nil,
        attackTreeText: String? = nil
    ) {
        self.architectureText = architectureText
        self.controlsText = controlsText
        self.attackTreeText = attackTreeText
    }
}

public enum CompileControlsResponse: Equatable, Sendable {
    case compiled(
        text: String,
        answered: Int,
        unanswered: Int,
        stale: Int,
        staleTrees: Int,
        /// The implemented controls a project's own rule says must state
        /// evidence and do not.
        unevidenced: [String],
        warnings: [Diagnostic]
    )
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
    private let attackTreeSources: AttackTreeSourceGateway

    public init(
        catalogue: TechnologyCatalogue,
        architectureSources: ArchitectureSourceGateway,
        controlsSources: ControlsSourceGateway,
        attackTreeSources: AttackTreeSourceGateway
    ) {
        self.catalogue = catalogue
        self.architectureSources = architectureSources
        self.controlsSources = controlsSources
        self.attackTreeSources = attackTreeSources
    }

    public func execute(_ request: CompileControlsRequest) -> CompileControlsResponse {
        // The architecture is imported into a store of its own, so compiling
        // never changes what is on screen.
        //
        // No layout: a compile scores a model and draws nothing, and zone
        // membership comes from the nesting the file states. The layout search
        // was 98 per cent of what a compile cost.
        let store = InMemoryThreatModelGateway()
        let imported = ImportArchitecture(
            models: store,
            catalogue: catalogue,
            sources: architectureSources,
            attackTreeSources: attackTreeSources,
            layout: nil
        ).execute(
            ImportArchitectureRequest(
                text: request.architectureText,
                attackTreeText: request.attackTreeText
            )
        )

        guard case .imported = imported else {
            guard case .refused(let diagnostics) = imported else {
                return .refused(diagnostics: [])
            }
            return .refused(diagnostics: diagnostics)
        }

        var existing: ControlsSource?
        var applyWarnings: [Diagnostic] = []
        if let controlsText = request.controlsText, controlsText.isEmpty == false {
            let read = controlsSources.read(controlsText)
            guard let source = read.source, read.hasErrors == false else {
                return .refused(diagnostics: read.diagnostics)
            }
            existing = source
            // A likelihood finding, a severity decision, a compensating
            // control and an implemented control each change the score. The
            // architecture alone carries none of them, so the file's own
            // answers go onto the model before it is resolved, the way the
            // report applies them before it exports. Without this the score
            // this compile writes is always the raw one, and a likelihood
            // finding can never answer a threat.
            //
            // A `severity_override` naming a severity the catalogue does not
            // hold is a warning, not an error: the block stays in the file
            // and a person reads why it moved no score.
            let applied = ApplyControlAnswers(models: store, catalogue: catalogue, sources: controlsSources)
                .execute(ApplyControlAnswersRequest(text: controlsText))
            if case .applied(_, let warnings) = applied {
                applyWarnings = warnings
            }
        }

        let model = store.current()
        // Stage 8 runs over the whole resolved set, because whether a step is
        // open depends on another threat's answers.
        let resolvedByStages = ThreatResolver(model: model, catalogue: catalogue).resolve()
        let bound = AttackTreeBinding.bind(trees: model.attackTrees, to: resolvedByStages)
        let staged = AttackTreeScoring.apply(trees: bound, to: resolvedByStages)
        let resolved = staged.threats

        var answers: [SourceThreatAnswer] = []
        var answeredKeys: Set<String> = []
        var answered = 0
        var unanswered = 0
        var unevidenced: [String] = []

        for threat in resolved {
            let key = ThreatKey(threatId: threat.threat.id.value, sourceId: threat.source.id)
            answeredKeys.insert(key.value)
            let previous = existing?.answer(for: key)

            // A control that has left the catalogue is dropped, and its answer
            // with it: nothing keeps an answer to a question nobody asks.
            let controls = threat.controls.map { control in
                let answered = previous?.controls.first { $0.description == control.description }
                return SourceControlAnswer(
                    description: control.description,
                    status: answered?.status ?? .notImplemented,
                    note: answered?.note,
                    // What proves the control is in place is the person's, so
                    // the merge keeps it whole.
                    proof: answered?.proof ?? ControlProof()
                )
            }

            // A project may rule that an implemented control above a stated
            // risk level must say what proves it. The level is read before the
            // controls: reading it after would let the controls lower the
            // score far enough to exempt themselves.
            if let level = model.requiresEvidenceAbove,
               RiskScore(value: threat.scoreBeforeControls).level.rank >= level.rank {
                for control in controls
                where control.status == .implemented && control.proof.evidence == nil {
                    unevidenced.append(
                        "\(key.value): \"\(control.description)\" is implemented above "
                            + "\(level.rawValue) risk with no evidence"
                    )
                }
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

        // A tree the `.attacktree` file no longer states writes no stanza: a
        // person owns that file, and deleting a tree there loses nothing.
        let treeAnswers = staged.trees.map { tree in
            SourceTreeAnswer(
                treeId: tree.id,
                goalKey: tree.goal.value,
                chain: tree.chainPercentage,
                raisesRiskBy: tree.raisesRiskBy,
                score: tree.score,
                scoreBefore: tree.scoreBefore,
                steps: tree.steps.map { step in
                    SourceTreeStepAnswer(
                        key: step.key.value,
                        state: step.state.rawValue,
                        closedBy: step.closedBy
                    )
                },
                isStale: tree.isStale
            )
        }

        return .compiled(
            text: controlsSources.write(
                ControlsSource(
                    systemName: model.name,
                    catalogueTag: model.catalogueVersion?.tag ?? catalogue.version().tag,
                    riskTolerance: model.effectiveRiskTolerance.rawValue,
                    answers: answers,
                    trees: treeAnswers
                )
            ),
            answered: answered,
            unanswered: unanswered,
            stale: stale,
            staleTrees: treeAnswers.filter(\.isStale).count,
            unevidenced: unevidenced,
            warnings: applyWarnings
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
