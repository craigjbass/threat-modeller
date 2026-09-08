public protocol RemoveComponentsUseCase {
    func execute(_ request: RemoveComponentsRequest) -> RemoveComponentsResponse
}

public struct RemoveComponentsRequest: Equatable, Sendable {
    public let componentIds: [String]

    public init(componentIds: [String]) {
        self.componentIds = componentIds
    }
}

public enum RemoveComponentsResponse: Equatable, Sendable {
    /// What left the model, both listed in model order, not request order.
    /// `connectionIds` holds the links removed because a component they touch
    /// was removed.
    case removed(componentIds: [String], connectionIds: [String])
    case unknownComponent(componentId: String)
}

/// Removes components and every link that touches one of them.
///
/// The removal is all or nothing: one unknown component leaves the model as it
/// was. The response lists what left so the canvas can drop those rows from
/// its selection.
public struct RemoveComponents: RemoveComponentsUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RemoveComponentsRequest) -> RemoveComponentsResponse {
        var model = models.current()
        var doomed: Set<ComponentId> = []

        for raw in request.componentIds {
            let id = ComponentId(raw)
            guard model.component(id) != nil else {
                return .unknownComponent(componentId: raw)
            }
            doomed.insert(id)
        }

        guard doomed.isEmpty == false else {
            return .removed(componentIds: [], connectionIds: [])
        }

        let removedComponents = model.components
            .filter { doomed.contains($0.id) }
            .map(\.id.value)
        let removedConnections = model.connections
            .filter { connection in doomed.contains(where: connection.touches) }
            .map(\.id.value)

        model.components.removeAll { doomed.contains($0.id) }
        model.connections.removeAll { connection in doomed.contains(where: connection.touches) }
        models.save(model)

        return .removed(componentIds: removedComponents, connectionIds: removedConnections)
    }
}
