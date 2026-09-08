public protocol SetControlStatusUseCase {
    func execute(_ request: SetControlStatusRequest) -> SetControlStatusResponse
}

public struct SetControlStatusRequest: Equatable, Sendable {
    public let controlKey: String
    public let statusId: String

    public init(controlKey: String, statusId: String) {
        self.controlKey = controlKey
        self.statusId = statusId
    }
}

public enum SetControlStatusResponse: Equatable, Sendable {
    case recorded
    case unknownStatus

    /// Puts what went wrong where a delivery mechanism shows it, or clears it.
    public func describe(into message: inout String?) {
        switch self {
        case .recorded: message = nil
        case .unknownStatus: message = "That control status is not one this application holds."
        }
    }
}

/// Records what a person said about one control.
///
/// `implemented` records the control, exactly as `RecordControlImplemented`
/// does; the other three say something a report reads and a score does not.
public struct SetControlStatus: SetControlStatusUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetControlStatusRequest) -> SetControlStatusResponse {
        guard let status = ControlStatus(rawValue: request.statusId) else {
            return .unknownStatus
        }

        return models.mutate { model in
            model.controlStatuses[ControlKey(request.controlKey)] = status
            return .recorded
        }
    }
}
