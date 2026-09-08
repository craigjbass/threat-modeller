public protocol DeleteCustomTechnologyUseCase {
    func execute(_ request: DeleteCustomTechnologyRequest) -> DeleteCustomTechnologyResponse
}

public struct DeleteCustomTechnologyRequest: Equatable, Sendable {
    public let technologyId: String
    public init(technologyId: String) { self.technologyId = technologyId }
}

public enum DeleteCustomTechnologyResponse: Equatable, Sendable {
    /// What went with it, so the canvas can drop those rows from its selection.
    case deleted(removedComponentIds: [String], removedConnectionIds: [String])
    case unknownTechnology
}

/// Removes a technology this model defines, and everything using it.
///
/// Leaving the components behind would leave nodes the application cannot name
/// or score. A saved file can reach that state and the drift report says so;
/// reaching it deliberately would be a bug.
public struct DeleteCustomTechnology: DeleteCustomTechnologyUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: DeleteCustomTechnologyRequest) -> DeleteCustomTechnologyResponse {
        let id = TechnologyId(request.technologyId)

        return models.mutate { model in
            guard model.customTechnologies.contains(where: { $0.id == id }) else {
                return .unknownTechnology
            }

            let doomed = Set(model.components.filter { $0.technologyId == id }.map(\.id))
            let removedComponents = model.components
                .filter { doomed.contains($0.id) }
                .map(\.id.value)
            let removedConnections = model.connections
                .filter { connection in doomed.contains(where: connection.touches) }
                .map(\.id.value)

            model.components.removeAll { doomed.contains($0.id) }
            model.connections.removeAll { connection in doomed.contains(where: connection.touches) }
            model.customTechnologies.removeAll { $0.id == id }

            let prefixes = doomed.map(ControlIdentity.componentPrefix)
            model.implementedControls = model.implementedControls.filter { key in
                prefixes.contains(where: key.value.hasPrefix) == false
            }

            return .deleted(
                removedComponentIds: removedComponents,
                removedConnectionIds: removedConnections
            )
        }
    }
}
