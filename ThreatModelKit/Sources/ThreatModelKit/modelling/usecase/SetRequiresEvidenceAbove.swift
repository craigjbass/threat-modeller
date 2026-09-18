public protocol SetRequiresEvidenceAboveUseCase {
    func execute(_ request: SetRequiresEvidenceAboveRequest) -> SetRequiresEvidenceAboveResponse
}

public struct SetRequiresEvidenceAboveRequest: Equatable, Sendable {
    /// One of `low`, `medium`, `high` or `critical`, or empty to state that no
    /// tier needs evidence.
    public let level: String

    public init(level: String) {
        self.level = level
    }
}

public enum SetRequiresEvidenceAboveResponse: Equatable, Sendable {
    case recorded
    case unknownLevel(String)

    public func describe(into message: inout String?) {
        switch self {
        case .recorded: message = nil
        case .unknownLevel(let level):
            message = "This application holds no risk level called \"\(level)\"."
        }
    }
}

/// States the risk level at and above which an implemented control must state
/// evidence.
///
/// `threatmodeller check` reads this from the `.arch` file's
/// `requires_evidence_above`. `AttackTreeContext` combines it with the
/// policy file's own demand. The window writes the same attribute here, so
/// the value it shows and the value the verb reports never disagree.
public struct SetRequiresEvidenceAbove: SetRequiresEvidenceAboveUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetRequiresEvidenceAboveRequest) -> SetRequiresEvidenceAboveResponse {
        let word = request.level.trimmingWhitespace()

        guard word.isEmpty == false else {
            return models.mutate(label: ChangeLabel.setRequiresEvidenceAbove) { model in
                model.requiresEvidenceAbove = nil
                return .recorded
            }
        }

        guard let level = RiskLevel(rawValue: word) else {
            return .unknownLevel(word)
        }

        return models.mutate(label: ChangeLabel.setRequiresEvidenceAbove) { model in
            model.requiresEvidenceAbove = level
            return .recorded
        }
    }
}
