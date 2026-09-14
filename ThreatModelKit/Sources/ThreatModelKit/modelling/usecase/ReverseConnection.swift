public protocol ReverseConnectionUseCase {
    func execute(_ request: ReverseConnectionRequest) -> ReverseConnectionResponse
}

public struct ReverseConnectionRequest: Equatable, Sendable {
    public let connectionId: String

    public init(connectionId: String) {
        self.connectionId = connectionId
    }
}

public enum ReverseConnectionResponse: Equatable, Sendable {
    case reversed
    case unknownConnection
    /// The model already holds a flow the other way round, and a second one
    /// between the same two components is refused the way `ConnectComponents`
    /// refuses it.
    case alreadyConnected
}

/// Turns a flow round.
///
/// A flow drawn the wrong way was deleted and drawn again, and its kind and
/// its description went with it. The kind decides which threats the flow
/// raises, so the direction is a scoring matter and not a drawing one.
public struct ReverseConnection: ReverseConnectionUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: ReverseConnectionRequest) -> ReverseConnectionResponse {
        let id = ConnectionId(request.connectionId)

        return models.mutate(label: ChangeLabel.reverseConnection) { model in
            guard let index = model.connections.firstIndex(where: { $0.id == id }) else {
                return .unknownConnection
            }
            let flow = model.connections[index]

            let taken = model.connections.contains {
                $0.id != flow.id && $0.source == flow.target && $0.target == flow.source
            }
            guard taken == false else { return .alreadyConnected }

            model.connections[index] = Connection(
                id: flow.id,
                source: flow.target,
                target: flow.source,
                kind: flow.kind,
                description: flow.description
            )
            return .reversed
        }
    }
}
