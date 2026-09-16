public protocol SetRiskToleranceUseCase {
    func execute(_ request: SetRiskToleranceRequest) -> SetRiskToleranceResponse
}

public struct SetRiskToleranceRequest: Equatable, Sendable {
    /// One of `low`, `medium`, `high` or `critical`.
    public let level: String

    public init(level: String) {
        self.level = level
    }
}

public enum SetRiskToleranceResponse: Equatable, Sendable {
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

/// States the risk level a likelihood finding may answer up to.
///
/// `threatmodeller check` reads this from the `.arch` file's
/// `risk_tolerance`, and a system that states none reads as `low`. The window
/// writes the same attribute here, so the value it shows and the value the
/// verb reports never disagree.
public struct SetRiskTolerance: SetRiskToleranceUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetRiskToleranceRequest) -> SetRiskToleranceResponse {
        guard let level = RiskLevel(rawValue: request.level) else {
            return .unknownLevel(request.level)
        }

        return models.mutate(label: ChangeLabel.setRiskTolerance) { model in
            model.riskTolerance = level
            return .recorded
        }
    }
}
