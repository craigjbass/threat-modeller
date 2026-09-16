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
        return models.mutate(label: ChangeLabel.removeComponents) { model in
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
            // A user reaches what is on the diagram. A reach naming a removed
            // component would be a fault the next open refuses.
            let removedIds = Set(doomed.map(\.value))
            for index in model.components.indices where model.components[index].user != nil {
                model.components[index].user?.reaches.removeAll { removedIds.contains($0) }
            }

            // Spec section 5.3: removing a component prunes every key scoped to
            // it. A severity override is keyed by the component too, so the
            // overrides on a removed component go with it.
            let prefixes = doomed.map(ControlIdentity.componentPrefix)
            model.implementedControls = model.implementedControls.filter { key in
                prefixes.contains(where: key.value.hasPrefix) == false
            }
            let overridePrefixes = doomed.map(SeverityOverrideKey.componentPrefix)
            model.severityOverrides = model.severityOverrides.filter { key, _ in
                overridePrefixes.contains(where: key.value.hasPrefix) == false
            }

            return .removed(componentIds: removedComponents, connectionIds: removedConnections)
        }
    }
}
