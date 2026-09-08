public protocol UndoLastChangeUseCase {
    func execute(_ request: UndoLastChangeRequest) -> UndoLastChangeResponse
}

public struct UndoLastChangeRequest: Equatable, Sendable {
    public init() {}
}

public enum UndoLastChangeResponse: Equatable, Sendable {
    /// Says whether there is more to take back, so a menu item can dim itself
    /// without asking a second question.
    case undone(canUndoMore: Bool)
    case nothingToUndo
}

/// Takes the model back one change.
public struct UndoLastChange: UndoLastChangeUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: UndoLastChangeRequest) -> UndoLastChangeResponse {
        guard models.undo() else { return .nothingToUndo }
        return .undone(canUndoMore: models.canUndo)
    }
}
