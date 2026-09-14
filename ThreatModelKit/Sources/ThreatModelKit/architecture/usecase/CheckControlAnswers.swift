public protocol CheckControlAnswersUseCase {
    func execute(_ request: CheckControlAnswersRequest) -> CheckControlAnswersResponse
}

public struct CheckControlAnswersRequest: Equatable, Sendable {
    public let architectureText: String
    public let controlsText: String?
    /// The trees a person wrote, or nil when the project holds no such file.
    public let attackTreeText: String?
    /// A risk level that overrides what the architecture file states, or nil.
    public let tolerance: String?

    public init(
        architectureText: String,
        controlsText: String? = nil,
        attackTreeText: String? = nil,
        tolerance: String? = nil
    ) {
        self.architectureText = architectureText
        self.controlsText = controlsText
        self.attackTreeText = attackTreeText
        self.tolerance = tolerance
    }
}

public struct UnansweredThreat: Equatable, Sendable {
    public let threatId: String
    public let sourceKind: String
    public let sourceId: String
    public let riskLevel: String

    public init(threatId: String, sourceKind: String, sourceId: String, riskLevel: String) {
        self.threatId = threatId
        self.sourceKind = sourceKind
        self.sourceId = sourceId
        self.riskLevel = riskLevel
    }

    public var described: String {
        "\(threatId) on \(sourceKind) \"\(sourceId)\" (\(riskLevel)) has no answer"
    }
}

public enum CheckControlAnswersResponse: Equatable, Sendable {
    case checked(
        unanswered: [UnansweredThreat],
        stale: [String],
        staleTrees: [String],
        diagnostics: [Diagnostic],
        tolerance: String
    )
    case refused(diagnostics: [Diagnostic])

    public var isClean: Bool {
        guard case .checked(let unanswered, let stale, let staleTrees, _, _) = self else {
            return false
        }
        return unanswered.isEmpty && stale.isEmpty && staleTrees.isEmpty
    }
}

/// Says what a pull request has not answered.
///
/// The executable's exit code reads this and nothing else does.
public struct CheckControlAnswers: CheckControlAnswersUseCase {
    private let compiles: CompileControlsUseCase
    private let sources: ControlsSourceGateway

    public init(compiles: CompileControlsUseCase, sources: ControlsSourceGateway) {
        self.compiles = compiles
        self.sources = sources
    }

    public func execute(_ request: CheckControlAnswersRequest) -> CheckControlAnswersResponse {
        // Checking is compiling and reading the result, so the two can never
        // disagree about what a threat needs.
        let compiled = compiles.execute(
            CompileControlsRequest(
                architectureText: request.architectureText,
                controlsText: request.controlsText,
                attackTreeText: request.attackTreeText
            )
        )

        guard case .compiled(let text, _, _, _, _, let compileWarnings) = compiled else {
            guard case .refused(let diagnostics) = compiled else {
                return .refused(diagnostics: [])
            }
            return .refused(diagnostics: diagnostics)
        }

        let read = sources.read(text)
        guard let source = read.source else {
            return .refused(diagnostics: read.diagnostics)
        }

        let tolerance = request.tolerance.flatMap(RiskLevel.init(rawValue:))
            ?? source.riskTolerance.flatMap(RiskLevel.init(rawValue:))
            ?? .low

        var unanswered: [UnansweredThreat] = []
        var stale: [String] = []

        for answer in source.answers {
            if answer.isStale {
                stale.append(answer.key.value)
                continue
            }
            guard answer.isAnswered(within: tolerance) == false else { continue }
            unanswered.append(
                UnansweredThreat(
                    threatId: answer.threatId,
                    sourceKind: answer.sourceKind,
                    sourceId: answer.sourceId,
                    riskLevel: answer.severityLabel ?? "unknown"
                )
            )
        }

        // A tree whose goal or whose step no longer binds is work for a
        // person: the route it describes is a claim about a system that is no
        // longer there.
        let staleTrees = source.trees
            .filter(\.isStale)
            .map { StaleTree(treeId: $0.treeId, stepCount: $0.steps.count).described }

        return .checked(
            unanswered: unanswered,
            stale: stale,
            staleTrees: staleTrees,
            diagnostics: read.warnings + compileWarnings,
            tolerance: tolerance.rawValue
        )
    }
}
