/// An answer for a threat the architecture no longer raises.
///
/// Language guide section 5.4. Nothing deletes one and the application does
/// not apply what it holds. It is work for a person: read the answer, then
/// either restore what raised the threat or delete the block.
public struct StaleAnswer: Equatable, Sendable, Identifiable {
    /// The threat, the source kind and the source id together: the same
    /// three things a controls file keys the stanza on.
    public var id: String { "\(threatId)@\(sourceKind):\(sourceId)" }
    public let threatId: String
    public let sourceKind: String
    public let sourceId: String
    /// How many controls the answer holds, so a person sees what they lose by
    /// deleting it.
    public let controlCount: Int
    /// True when the answer holds a likelihood finding.
    public let hasLikelihoodFinding: Bool
    /// True when the answer holds a severity decision.
    public let hasSeverityDecision: Bool
    /// How many compensating controls the answer holds.
    public let compensatingCount: Int
    /// How many recommendations the answer holds.
    public let recommendationCount: Int

    public init(
        threatId: String,
        sourceKind: String,
        sourceId: String,
        controlCount: Int,
        hasLikelihoodFinding: Bool = false,
        hasSeverityDecision: Bool = false,
        compensatingCount: Int = 0,
        recommendationCount: Int = 0
    ) {
        self.threatId = threatId
        self.sourceKind = sourceKind
        self.sourceId = sourceId
        self.controlCount = controlCount
        self.hasLikelihoodFinding = hasLikelihoodFinding
        self.hasSeverityDecision = hasSeverityDecision
        self.compensatingCount = compensatingCount
        self.recommendationCount = recommendationCount
    }

    public var described: String {
        "\(threatId) on \(sourceKind) \"\(sourceId)\" is answered but no longer raised"
    }
}

/// A tree a person wrote that the architecture no longer supports.
///
/// Nothing deletes one. It is work for a person: read the tree, then either
/// restore what it names or delete it.
public struct StaleTree: Equatable, Sendable {
    public let treeId: String
    /// How many steps the tree holds, so a person sees what they lose by
    /// deleting it.
    public let stepCount: Int
    /// The sufficient controls no catalogue or library control states.
    public let unknownControls: [String]

    public init(treeId: String, stepCount: Int, unknownControls: [String] = []) {
        self.treeId = treeId
        self.stepCount = stepCount
        self.unknownControls = unknownControls
    }

    public var described: String {
        "the tree \"\(treeId)\" is written but no longer binds"
    }

    /// One line per fault: the binding line when a step or the goal no
    /// longer binds, and one line per unknown sufficient control.
    public func describe(stepsBind: Bool) -> [String] {
        var lines: [String] = []
        if stepsBind == false || unknownControls.isEmpty { lines.append(described) }
        for control in unknownControls {
            lines.append(
                "the tree \"\(treeId)\" is closed by \"\(control)\", "
                    + "which the catalogue and the libraries do not hold"
            )
        }
        return lines
    }
}

public protocol ListStaleAnswersUseCase {
    func execute(_ request: ListStaleAnswersRequest) -> ListStaleAnswersResponse
}

public struct ListStaleAnswersRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String

    public init(root: String, systemName: String) {
        self.root = root
        self.systemName = systemName
    }
}

public enum ListStaleAnswersResponse: Equatable, Sendable {
    case listed([StaleAnswer])
    case noSuchSystem
    case cannotRead(reason: String)
}

/// Says which answers the architecture no longer raises.
///
/// It reads the controls file rather than the model, because a stale answer
/// never reaches the model: `ApplyControlAnswers` skips one, so the file is
/// the only place it lives.
public struct ListStaleAnswers: ListStaleAnswersUseCase {
    private let projects: ProjectSourceGateway
    private let controlsSources: ControlsSourceGateway

    public init(projects: ProjectSourceGateway, controlsSources: ControlsSourceGateway) {
        self.projects = projects
        self.controlsSources = controlsSources
    }

    public func execute(_ request: ListStaleAnswersRequest) -> ListStaleAnswersResponse {
        switch StaleAnswerFile.read(
            root: request.root,
            systemName: request.systemName,
            projects: projects,
            controlsSources: controlsSources
        ) {
        case .read(let source, _):
            return .listed(
                source.answers.filter(\.isStale).map { answer in
                    StaleAnswer(
                        threatId: answer.threatId,
                        sourceKind: answer.sourceKind,
                        sourceId: answer.sourceId,
                        controlCount: answer.controls.count,
                        hasLikelihoodFinding: answer.likelihood != nil,
                        hasSeverityDecision: answer.severityDecision != nil,
                        compensatingCount: answer.compensating.count,
                        recommendationCount: answer.recommendations.count
                    )
                }
            )
        case .noSuchSystem:
            return .noSuchSystem
        case .cannotRead(let reason):
            return .cannotRead(reason: reason)
        }
    }
}

public protocol RemoveStaleAnswerUseCase {
    func execute(_ request: RemoveStaleAnswerRequest) -> RemoveStaleAnswerResponse
}

public struct RemoveStaleAnswerRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String
    public let threatId: String
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

public enum RemoveStaleAnswerResponse: Equatable, Sendable {
    case removed
    case noSuchAnswer
    case noSuchSystem
    case cannotWrite(reason: String)

    public func describe(into message: inout String?) {
        switch self {
        case .removed:
            message = nil
        case .noSuchAnswer:
            message = "This system holds no such stale answer."
        case .noSuchSystem:
            message = "This project no longer holds that system."
        case .cannotWrite(let reason):
            message = "That answer could not be deleted: \(reason)"
        }
    }
}

/// Deletes one stale answer, because a person decided to.
///
/// It writes every other answer back unchanged, stale or not: a person
/// deleting one answer is not deciding anything about the rest.
public struct RemoveStaleAnswer: RemoveStaleAnswerUseCase {
    private let projects: ProjectSourceGateway
    private let controlsSources: ControlsSourceGateway

    public init(projects: ProjectSourceGateway, controlsSources: ControlsSourceGateway) {
        self.projects = projects
        self.controlsSources = controlsSources
    }

    public func execute(_ request: RemoveStaleAnswerRequest) -> RemoveStaleAnswerResponse {
        let source: ControlsSource
        let path: String
        switch StaleAnswerFile.read(
            root: request.root,
            systemName: request.systemName,
            projects: projects,
            controlsSources: controlsSources
        ) {
        case .read(let read, let at):
            source = read
            path = at
        case .noSuchSystem:
            return .noSuchSystem
        case .cannotRead(let reason):
            return .cannotWrite(reason: reason)
        }

        let kept = source.answers.filter { answer in
            (answer.isStale
                && answer.threatId == request.threatId
                && answer.sourceKind == request.sourceKind
                && answer.sourceId == request.sourceId) == false
        }
        guard kept.count < source.answers.count else { return .noSuchAnswer }

        let written = ControlsSource(
            systemName: source.systemName,
            catalogueTag: source.catalogueTag,
            riskTolerance: source.riskTolerance,
            answers: kept,
            trees: source.trees
        )

        do {
            try projects.write(controlsSources.write(written), to: path)
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
        return .removed
    }
}

public protocol RemoveStaleAnswersUseCase {
    func execute(_ request: RemoveStaleAnswersRequest) -> RemoveStaleAnswersResponse
}

public struct RemoveStaleAnswersRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String

    public init(root: String, systemName: String) {
        self.root = root
        self.systemName = systemName
    }
}

public enum RemoveStaleAnswersResponse: Equatable, Sendable {
    case removed(count: Int)
    case noSuchSystem
    case cannotWrite(reason: String)

    public func describe(into message: inout String?) {
        switch self {
        case .removed:
            message = nil
        case .noSuchSystem:
            message = "This project no longer holds that system."
        case .cannotWrite(let reason):
            message = "Those answers could not be deleted: \(reason)"
        }
    }
}

/// Deletes every stale answer a system's controls file holds, because a
/// person decided to.
///
/// It reads the file once and writes it once, and every other block —
/// stale or not, and every tree — is written back unchanged, the way
/// `RemoveStaleAnswer` writes back everything but the one answer it deletes.
public struct RemoveStaleAnswers: RemoveStaleAnswersUseCase {
    private let projects: ProjectSourceGateway
    private let controlsSources: ControlsSourceGateway

    public init(projects: ProjectSourceGateway, controlsSources: ControlsSourceGateway) {
        self.projects = projects
        self.controlsSources = controlsSources
    }

    public func execute(_ request: RemoveStaleAnswersRequest) -> RemoveStaleAnswersResponse {
        let source: ControlsSource
        let path: String
        switch StaleAnswerFile.read(
            root: request.root,
            systemName: request.systemName,
            projects: projects,
            controlsSources: controlsSources
        ) {
        case .read(let read, let at):
            source = read
            path = at
        case .noSuchSystem:
            return .noSuchSystem
        case .cannotRead(let reason):
            return .cannotWrite(reason: reason)
        }

        let removed = source.answers.filter(\.isStale).count
        guard removed > 0 else { return .removed(count: 0) }

        let kept = source.answers.filter { $0.isStale == false }
        let written = ControlsSource(
            systemName: source.systemName,
            catalogueTag: source.catalogueTag,
            riskTolerance: source.riskTolerance,
            answers: kept,
            trees: source.trees
        )

        do {
            try projects.write(controlsSources.write(written), to: path)
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
        return .removed(count: removed)
    }
}

/// Reading a system's controls file, which both use cases above start with.
enum StaleAnswerFile {
    enum Outcome {
        case read(ControlsSource, path: String)
        case noSuchSystem
        case cannotRead(reason: String)
    }

    static func read(
        root: String,
        systemName: String,
        projects: ProjectSourceGateway,
        controlsSources: ControlsSourceGateway
    ) -> Outcome {
        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: root)
        } catch {
            return .cannotRead(reason: String(describing: error))
        }

        guard let system = layout.systems.first(where: { $0.name == systemName }) else {
            return .noSuchSystem
        }

        // A system with no controls file has answered nothing, so it holds
        // nothing stale either.
        guard projects.exists(path: system.controlsPath) else {
            return .read(ControlsSource(systemName: systemName), path: system.controlsPath)
        }

        let text: String
        do {
            text = try projects.read(path: system.controlsPath)
        } catch {
            return .cannotRead(reason: String(describing: error))
        }

        let parsed = controlsSources.read(text)
        guard let source = parsed.source else {
            return .cannotRead(reason: parsed.diagnostics.first?.message ?? "it did not parse")
        }
        return .read(source, path: system.controlsPath)
    }
}
