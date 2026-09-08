public protocol RemoveConnectionUseCase {
    func execute(_ request: RemoveConnectionRequest) -> RemoveConnectionResponse
}

public struct RemoveConnectionRequest: Equatable, Sendable {
    public let connectionId: String

    public init(connectionId: String) {
        self.connectionId = connectionId
    }
}

public enum RemoveConnectionResponse: Equatable, Sendable {
    case removed
    case unknownConnection
}

/// Removes one link. The components at each end stay on the model.
public struct RemoveConnection: RemoveConnectionUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RemoveConnectionRequest) -> RemoveConnectionResponse {
        let id = ConnectionId(request.connectionId)

        var model = models.current()
        guard model.connections.contains(where: { $0.id == id }) else {
            return .unknownConnection
        }

        model.connections.removeAll { $0.id == id }
        models.save(model)

        return .removed
    }
}
