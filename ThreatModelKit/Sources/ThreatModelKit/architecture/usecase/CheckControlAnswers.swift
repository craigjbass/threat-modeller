public protocol CheckControlAnswersUseCase {
    func execute(_ request: CheckControlAnswersRequest) -> CheckControlAnswersResponse
}

public struct CheckControlAnswersRequest: Equatable, Sendable {
    public let architectureText: String
    public let controlsText: String?

    public init(architectureText: String, controlsText: String? = nil) {
        self.architectureText = architectureText
        self.controlsText = controlsText
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
    case checked(unanswered: [UnansweredThreat], stale: [String], diagnostics: [Diagnostic])
    case refused(diagnostics: [Diagnostic])

    public var isClean: Bool {
        guard case .checked(let unanswered, let stale, _) = self else { return false }
        return unanswered.isEmpty && stale.isEmpty
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
                controlsText: request.controlsText
            )
        )

        guard case .compiled(let text, _, _, _) = compiled else {
            guard case .refused(let diagnostics) = compiled else {
                return .refused(diagnostics: [])
            }
            return .refused(diagnostics: diagnostics)
        }

        let read = sources.read(text)
        guard let source = read.source else {
            return .refused(diagnostics: read.diagnostics)
        }

        var unanswered: [UnansweredThreat] = []
        var stale: [String] = []

        for answer in source.answers {
            if answer.isStale {
                stale.append(answer.key.value)
                continue
            }
            guard answer.isAnswered == false else { continue }
            unanswered.append(
                UnansweredThreat(
                    threatId: answer.threatId,
                    sourceKind: answer.sourceKind,
                    sourceId: answer.sourceId,
                    riskLevel: answer.severityLabel ?? "unknown"
                )
            )
        }

        return .checked(unanswered: unanswered, stale: stale, diagnostics: read.warnings)
    }
}
