public protocol SetComponentPropertiesUseCase {
    func execute(_ request: SetComponentPropertiesRequest) -> SetComponentPropertiesResponse
}

public struct SetComponentPropertiesRequest: Equatable, Sendable {
    public let componentId: String
    /// The user's own name for the node, or nil to go back to the technology's
    /// name. An empty name is the same as nil.
    public let name: String?
    public let sensitivity: String
    /// True to leave the node on the diagram but raise nothing for it.
    public let threatsDisabled: Bool
    /// The privilege the component runs at: user, admin, root, system or
    /// kernel.
    public let runsAs: String

    public init(
        componentId: String,
        name: String?,
        sensitivity: String,
        threatsDisabled: Bool,
        runsAs: String
    ) {
        self.componentId = componentId
        self.name = name
        self.sensitivity = sensitivity
        self.threatsDisabled = threatsDisabled
        self.runsAs = runsAs
    }
}

public enum SetComponentPropertiesResponse: Equatable, Sendable {
    case updated
    case unknownComponent
    case unknownSensitivity
    case unknownPrivilegeLevel
}

/// Changes what a node is called, how sensitive its data is, and whether it
/// raises threats at all.
///
/// One use case for all three, the way `SetZoneProperties` does it: the panel
/// writes what the user sees, and the model takes it or refuses it whole.
public struct SetComponentProperties: SetComponentPropertiesUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetComponentPropertiesRequest) -> SetComponentPropertiesResponse {
        let componentId = ComponentId(request.componentId)
        guard let sensitivity = DataSensitivity(rawValue: request.sensitivity) else {
            return .unknownSensitivity
        }
        guard let runsAs = PrivilegeLevel(rawValue: request.runsAs) else {
            return .unknownPrivilegeLevel
        }
        let name = request.name?.trimmingWhitespace() ?? ""

        return models.mutate { model in
            guard let index = model.components.firstIndex(where: { $0.id == componentId }) else {
                return .unknownComponent
            }

            model.components[index].customName = name.isEmpty ? nil : name
            model.components[index].sensitivity = sensitivity
            model.components[index].threatsDisabled = request.threatsDisabled
            model.components[index].runsAs = runsAs
            return .updated
        }
    }
}
