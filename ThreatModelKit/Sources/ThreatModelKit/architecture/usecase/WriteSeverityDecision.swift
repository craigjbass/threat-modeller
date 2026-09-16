/// Reading and writing one `severity_override` block of a system's
/// `.controls` file.
///
/// The window's severity decision editor writes through these. Each reads the
/// file, changes one block and writes every other block back unchanged,
/// because a person deciding one severity is deciding nothing about the rest.
///
/// The controls source gateway states the canonical shape, so a block written
/// here and the same block written by `threatmodeller compile` are the same
/// bytes.
public protocol WriteSeverityDecisionUseCase {
    func execute(_ request: WriteSeverityDecisionRequest) -> WriteSeverityDecisionResponse
}

public struct WriteSeverityDecisionRequest: Equatable, Sendable {
    public let root: String
    /// The system's own file name, which names the file to write.
    public let systemName: String
    /// The name the system states for itself, which a new file's header
    /// names. Nil writes the file name.
    public let systemDisplayName: String?
    /// The threat the decision names, the way the controls file states it.
    public let threatId: String
    /// `component`, `zone` or `flow`.
    public let sourceKind: String
    public let sourceId: String
    /// The decision to write. A threat holds one, so this replaces what the
    /// threat holds.
    public let decision: SeverityDecision

    public init(
        root: String,
        systemName: String,
        systemDisplayName: String? = nil,
        threatId: String,
        sourceKind: String,
        sourceId: String,
        decision: SeverityDecision
    ) {
        self.root = root
        self.systemName = systemName
        self.systemDisplayName = systemDisplayName
        self.threatId = threatId
        self.sourceKind = sourceKind
        self.sourceId = sourceId
        self.decision = decision
    }
}

public enum WriteSeverityDecisionResponse: Equatable, Sendable {
    case written(path: String)
    case noSuchSystem
    /// Why the block is not one the application would apply.
    case refused(reason: String)
    case cannotWrite(reason: String)

    public func describe(into message: inout String?) {
        switch self {
        case .written:
            message = nil
        case .noSuchSystem:
            message = "This project no longer holds that system."
        case .refused(let reason):
            message = "That decision was not written: \(reason)."
        case .cannotWrite(let reason):
            message = "That decision could not be written: \(reason)"
        }
    }
}

public struct WriteSeverityDecision: WriteSeverityDecisionUseCase {
    private let projects: ProjectSourceGateway
    private let sources: ControlsSourceGateway
    private let catalogue: TechnologyCatalogue

    public init(
        projects: ProjectSourceGateway,
        sources: ControlsSourceGateway,
        catalogue: TechnologyCatalogue
    ) {
        self.projects = projects
        self.sources = sources
        self.catalogue = catalogue
    }

    public func execute(_ request: WriteSeverityDecisionRequest) -> WriteSeverityDecisionResponse {
        // The parser drops a block with no rationale, and the apply step skips
        // a severity the catalogue does not hold. Neither is worth writing.
        guard request.decision.rationale.trimmingWhitespace().isEmpty == false else {
            return .refused(reason: "a severity decision needs a rationale")
        }
        guard catalogue.taxonomy().severity(id: request.decision.severityId) != nil else {
            return .refused(
                reason: "\"\(request.decision.severityId)\" is not a severity this catalogue holds"
            )
        }

        let held: ControlsFile.Held
        switch ControlsFile.read(
            root: request.root,
            systemName: request.systemName,
            named: request.systemDisplayName,
            key: ThreatKey(
                threatId: request.threatId,
                sourceId: "\(SourceThreatAnswer.resolverKind(request.sourceKind)):\(request.sourceId)"
            ),
            projects: projects,
            sources: sources
        ) {
        case .held(let found):
            held = found
        case .noSuchSystem:
            return .noSuchSystem
        case .cannotRead(let reason):
            return .cannotWrite(reason: reason)
        }

        var answers = held.source.answers
        if let already = held.answerIndex {
            answers[already] = ControlsFile.changing(answers[already], decisionTo: request.decision)
        } else {
            // The compile writes a block for every threat the architecture
            // raises. A file without one is behind it; the decision still
            // lands, and the next compile fills the rest in.
            answers.append(
                SourceThreatAnswer(
                    threatId: request.threatId,
                    sourceKind: request.sourceKind,
                    sourceId: request.sourceId,
                    severityDecision: request.decision
                )
            )
        }

        do {
            try projects.write(
                sources.write(ControlsFile.replacing(answers: answers, in: held.source)),
                to: held.path
            )
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
        return .written(path: held.path)
    }
}

public protocol RemoveSeverityDecisionUseCase {
    func execute(_ request: RemoveSeverityDecisionRequest) -> RemoveSeverityDecisionResponse
}

public struct RemoveSeverityDecisionRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String
    public let threatId: String
    /// `component`, `zone` or `flow`.
    public let sourceKind: String
    public let sourceId: String

    public init(
        root: String,
        systemName: String,
        threatId: String,
        sourceKind: String,
        sourceId: String
    ) {
        self.root = root
        self.systemName = systemName
        self.threatId = threatId
        self.sourceKind = sourceKind
        self.sourceId = sourceId
    }
}

public enum RemoveSeverityDecisionResponse: Equatable, Sendable {
    case removed(path: String)
    case noSuchDecision
    case noSuchSystem
    case cannotWrite(reason: String)

    public func describe(into message: inout String?) {
        switch self {
        case .removed:
            message = nil
        case .noSuchDecision:
            message = "This threat holds no severity decision."
        case .noSuchSystem:
            message = "This project no longer holds that system."
        case .cannotWrite(let reason):
            message = "That decision could not be removed: \(reason)"
        }
    }
}

public struct RemoveSeverityDecision: RemoveSeverityDecisionUseCase {
    private let projects: ProjectSourceGateway
    private let sources: ControlsSourceGateway

    public init(projects: ProjectSourceGateway, sources: ControlsSourceGateway) {
        self.projects = projects
        self.sources = sources
    }

    public func execute(_ request: RemoveSeverityDecisionRequest) -> RemoveSeverityDecisionResponse {
        let held: ControlsFile.Held
        switch ControlsFile.read(
            root: request.root,
            systemName: request.systemName,
            named: nil,
            key: ThreatKey(
                threatId: request.threatId,
                sourceId: "\(SourceThreatAnswer.resolverKind(request.sourceKind)):\(request.sourceId)"
            ),
            projects: projects,
            sources: sources
        ) {
        case .held(let found):
            held = found
        case .noSuchSystem:
            return .noSuchSystem
        case .cannotRead(let reason):
            return .cannotWrite(reason: reason)
        }

        guard let already = held.answerIndex,
              held.source.answers[already].severityDecision != nil else {
            return .noSuchDecision
        }

        var answers = held.source.answers
        answers[already] = ControlsFile.changing(answers[already], decisionTo: nil)

        do {
            try projects.write(
                sources.write(ControlsFile.replacing(answers: answers, in: held.source)),
                to: held.path
            )
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
        return .removed(path: held.path)
    }
}

/// One system's `.controls` file, read for a change to one threat's block.
///
/// A split system keeps one controls file per architecture file; the file
/// that answers the key is the one to change. A system with no file yet reads
/// as a file answering nothing, so writing the first block writes the file.
enum ControlsFile {
    struct Held {
        let source: ControlsSource
        let path: String
        /// Where the key's answer sits in `source.answers`, or nil when the
        /// file does not answer it yet.
        let answerIndex: Int?
    }

    enum Read {
        case held(Held)
        case noSuchSystem
        case cannotRead(reason: String)
    }

    static func read(
        root: String,
        systemName: String,
        named displayName: String?,
        key: ThreatKey,
        projects: ProjectSourceGateway,
        sources: ControlsSourceGateway
    ) -> Read {
        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: root)
        } catch {
            return .cannotRead(reason: String(describing: error))
        }
        guard let system = layout.systems.first(where: { $0.name == systemName }) else {
            return .noSuchSystem
        }

        var fallback: Held?
        for path in system.controlsPaths where projects.exists(path: path) {
            guard let text = try? projects.read(path: path) else {
                return .cannotRead(reason: "\(path) could not be read")
            }
            let found = sources.read(text)
            guard let source = found.source, found.hasErrors == false else {
                return .cannotRead(
                    reason: found.diagnostics.first?.described(in: path) ?? "\(path) does not parse"
                )
            }
            if let index = source.answers.firstIndex(where: { $0.key == key }) {
                return .held(Held(source: source, path: path, answerIndex: index))
            }
            if fallback == nil {
                fallback = Held(source: source, path: path, answerIndex: nil)
            }
        }
        if let fallback { return .held(fallback) }

        // No controls file yet: the first block writes the file, and the
        // header names the system the way the architecture does.
        return .held(
            Held(
                source: ControlsSource(systemName: displayName ?? systemName),
                path: system.controlsPath,
                answerIndex: nil
            )
        )
    }

    /// The answer with a different decision and nothing else moved.
    static func changing(
        _ answer: SourceThreatAnswer,
        decisionTo decision: SeverityDecision?
    ) -> SourceThreatAnswer {
        SourceThreatAnswer(
            threatId: answer.threatId,
            sourceKind: answer.sourceKind,
            sourceId: answer.sourceId,
            severityLabel: answer.severityLabel,
            score: answer.score,
            likelihood: answer.likelihood,
            severityDecision: decision,
            impacts: answer.impacts,
            controls: answer.controls,
            compensating: answer.compensating,
            recommendations: answer.recommendations,
            isStale: answer.isStale
        )
    }

    /// The answer with a different likelihood finding and nothing else
    /// moved.
    static func changing(
        _ answer: SourceThreatAnswer,
        likelihoodTo likelihood: LikelihoodFinding?
    ) -> SourceThreatAnswer {
        SourceThreatAnswer(
            threatId: answer.threatId,
            sourceKind: answer.sourceKind,
            sourceId: answer.sourceId,
            severityLabel: answer.severityLabel,
            score: answer.score,
            likelihood: likelihood,
            severityDecision: answer.severityDecision,
            impacts: answer.impacts,
            controls: answer.controls,
            compensating: answer.compensating,
            recommendations: answer.recommendations,
            isStale: answer.isStale
        )
    }

    /// The answer with a different `impacts` list and nothing else moved.
    static func changing(
        _ answer: SourceThreatAnswer,
        impactsTo impacts: [String]
    ) -> SourceThreatAnswer {
        SourceThreatAnswer(
            threatId: answer.threatId,
            sourceKind: answer.sourceKind,
            sourceId: answer.sourceId,
            severityLabel: answer.severityLabel,
            score: answer.score,
            likelihood: answer.likelihood,
            severityDecision: answer.severityDecision,
            impacts: impacts,
            controls: answer.controls,
            compensating: answer.compensating,
            recommendations: answer.recommendations,
            isStale: answer.isStale
        )
    }

    /// The answer with a different recommendation list and nothing else
    /// moved.
    static func changing(
        _ answer: SourceThreatAnswer,
        recommendationsTo recommendations: [SourceRecommendation]
    ) -> SourceThreatAnswer {
        SourceThreatAnswer(
            threatId: answer.threatId,
            sourceKind: answer.sourceKind,
            sourceId: answer.sourceId,
            severityLabel: answer.severityLabel,
            score: answer.score,
            likelihood: answer.likelihood,
            severityDecision: answer.severityDecision,
            impacts: answer.impacts,
            controls: answer.controls,
            compensating: answer.compensating,
            recommendations: recommendations,
            isStale: answer.isStale
        )
    }

    /// The source with different answers and nothing else moved.
    static func replacing(
        answers: [SourceThreatAnswer],
        in source: ControlsSource
    ) -> ControlsSource {
        ControlsSource(
            systemName: source.systemName,
            catalogueTag: source.catalogueTag,
            riskTolerance: source.riskTolerance,
            answers: answers,
            trees: source.trees
        )
    }
}
