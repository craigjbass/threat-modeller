public protocol ConnectComponentsUseCase {
    func execute(_ request: ConnectComponentsRequest) -> ConnectComponentsResponse
}

public struct ConnectComponentsRequest: Equatable, Sendable {
    public let sourceComponentId: String
    public let targetComponentId: String

    public init(sourceComponentId: String, targetComponentId: String) {
        self.sourceComponentId = sourceComponentId
        self.targetComponentId = targetComponentId
    }
}

public enum ConnectComponentsResponse: Equatable, Sendable {
    case connected(connectionId: String)
    case unknownComponent(componentId: String)
    case selfConnection
    /// The pair is already linked in this direction. Carries the identifier of
    /// the link that already exists, so the canvas can select it.
    case duplicateConnection(connectionId: String)
}

/// Links one component to another.
///
/// Both components must exist, a component may not link to itself, and one
/// source and target pair carries at most one link. A link back the other way
/// is a separate link and is allowed. The use case takes no identifier from
/// the generator until every rule passes.
public struct ConnectComponents: ConnectComponentsUseCase {
    private let models: ThreatModelGateway
    private let ids: IdentityGenerator

    public init(models: ThreatModelGateway, ids: IdentityGenerator) {
        self.models = models
        self.ids = ids
    }

    public func execute(_ request: ConnectComponentsRequest) -> ConnectComponentsResponse {
        let source = ComponentId(request.sourceComponentId)
        let target = ComponentId(request.targetComponentId)

        return models.mutate { model in
            guard model.component(source) != nil else {
                return .unknownComponent(componentId: source.value)
            }
            guard model.component(target) != nil else {
                return .unknownComponent(componentId: target.value)
            }
            guard source != target else {
                return .selfConnection
            }
            if let existing = model.connections.first(where: { $0.source == source && $0.target == target }) {
                return .duplicateConnection(connectionId: existing.id.value)
            }

            // The identifier is taken only once every rule has passed.
            let connection = Connection(id: ConnectionId(ids.next()), source: source, target: target)
            model.connections.append(connection)
            return .connected(connectionId: connection.id.value)
        }
    }
}
