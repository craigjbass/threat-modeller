public protocol RedoChangeUseCase {
    func execute(_ request: RedoChangeRequest) -> RedoChangeResponse
}

public struct RedoChangeRequest: Equatable, Sendable {
    public init() {}
}

public enum RedoChangeResponse: Equatable, Sendable {
    case redone(canRedoMore: Bool)
    case nothingToRedo
}

/// Puts back a change that was taken back.
public struct RedoChange: RedoChangeUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RedoChangeRequest) -> RedoChangeResponse {
        guard models.redo() else { return .nothingToRedo }
        return .redone(canRedoMore: models.canRedo)
    }
}
