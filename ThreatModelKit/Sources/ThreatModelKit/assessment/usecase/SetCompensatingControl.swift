public protocol SetCompensatingControlUseCase {
    func execute(_ request: SetCompensatingControlRequest) -> SetCompensatingControlResponse
}

public struct SetCompensatingControlRequest: Equatable, Sendable {
    public let threatKey: String
    /// An empty label removes what compensates this threat.
    public let label: String
    public let reducesRiskBy: Int
    public let rationale: String

    public init(threatKey: String, label: String, reducesRiskBy: Int, rationale: String) {
        self.threatKey = threatKey
        self.label = label
        self.reducesRiskBy = reducesRiskBy
        self.rationale = rationale
    }
}

public enum SetCompensatingControlResponse: Equatable, Sendable {
    case recorded
    case removed
    case reductionOutOfRange
    case noRationale

    public func describe(into message: inout String?) {
        switch self {
        case .recorded, .removed:
            message = nil
        case .reductionOutOfRange:
            message = "A risk reduction runs from 0 to 100."
        case .noRationale:
            message = "A compensating control needs a rationale."
        }
    }
}

/// Records what compensates one threat.
///
/// Spec section 5: this is the one thing a person sets that moves a score, so
/// it carries a rationale. A reduction nobody can justify is not one.
public struct SetCompensatingControl: SetCompensatingControlUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetCompensatingControlRequest) -> SetCompensatingControlResponse {
        let key = ThreatKey(request.threatKey)
        let label = request.label.trimmingWhitespace()

        guard label.isEmpty == false else {
            return models.mutate { model in
                model.compensatingControls[key] = nil
                return .removed
            }
        }
        guard request.reducesRiskBy >= 0, request.reducesRiskBy <= 100 else {
            return .reductionOutOfRange
        }
        let rationale = request.rationale.trimmingWhitespace()
        guard rationale.isEmpty == false else { return .noRationale }

        return models.mutate { model in
            model.compensatingControls[key] = [
                CompensatingControl(
                    label: label,
                    reducesRiskBy: request.reducesRiskBy,
                    rationale: rationale
                )
            ]
            return .recorded
        }
    }
}
