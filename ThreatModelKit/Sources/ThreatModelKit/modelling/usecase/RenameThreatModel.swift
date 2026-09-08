public protocol RenameThreatModelUseCase {
    func execute(_ request: RenameThreatModelRequest) -> RenameThreatModelResponse
}

public struct RenameThreatModelRequest: Equatable, Sendable {
    public let name: String
    public init(name: String) { self.name = name }
}

public enum RenameThreatModelResponse: Equatable, Sendable {
    case renamed
    case emptyName
}

/// Renames the model. A model with no name is not a document anyone can find
/// again, so an empty name is refused rather than accepted and hidden.
public struct RenameThreatModel: RenameThreatModelUseCase {
    private let models: ThreatModelGateway
    private let clock: Clock

    public init(models: ThreatModelGateway, clock: Clock) {
        self.models = models
        self.clock = clock
    }

    public func execute(_ request: RenameThreatModelRequest) -> RenameThreatModelResponse {
        let name = request.name.trimmingWhitespace()
        guard name.isEmpty == false else { return .emptyName }

        let now = clock.now()
        return models.mutate { model in
            model.name = name
            model.updatedAt = now
            return .renamed
        }
    }
}
