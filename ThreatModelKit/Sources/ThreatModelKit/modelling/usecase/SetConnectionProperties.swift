public protocol SetConnectionPropertiesUseCase {
    func execute(_ request: SetConnectionPropertiesRequest) -> SetConnectionPropertiesResponse
}

public struct SetConnectionPropertiesRequest: Equatable, Sendable {
    public let connectionId: String
    /// A flow kind: network, ipc, file, syscall or human.
    public let kind: String
    /// Why the flow is there, or nil. An empty text is the same as nil.
    public let description: String?

    public init(connectionId: String, kind: String, description: String?) {
        self.connectionId = connectionId
        self.kind = kind
        self.description = description
    }
}

public enum SetConnectionPropertiesResponse: Equatable, Sendable {
    case updated
    case unknownConnection
    case unknownKind
}

/// Changes what a flow is and why it is there.
///
/// The kind decides which threats the flow raises, so the sidebar rescores as
/// soon as a user changes it.
public struct SetConnectionProperties: SetConnectionPropertiesUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetConnectionPropertiesRequest) -> SetConnectionPropertiesResponse {
        let id = ConnectionId(request.connectionId)

        return models.mutate { model in
            guard let index = model.connections.firstIndex(where: { $0.id == id }) else {
                return .unknownConnection
            }
            guard let kind = FlowKind(rawValue: request.kind) else { return .unknownKind }

            let trimmed = request.description?.trimmingWhitespace() ?? ""
            model.connections[index].kind = kind
            model.connections[index].description = trimmed.isEmpty ? nil : trimmed
            return .updated
        }
    }
}
