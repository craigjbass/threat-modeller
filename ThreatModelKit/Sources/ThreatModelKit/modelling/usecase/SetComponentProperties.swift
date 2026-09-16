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
    /// The shape the user forced, or nil to let the derivation decide.
    public let shape: String?
    /// The system asset ids this component holds. Nil leaves what it holds
    /// alone, so a panel that does not offer assets changes none.
    public let holds: [String]?
    /// The words the component is filed under. Nil leaves the tags alone, so a
    /// panel that does not offer tags changes none.
    public let tags: [String]?
    /// The status the component takes: `live` or `proposed`. Nil leaves the
    /// status alone, so a panel that does not offer a status changes none. A
    /// word outside the vocabulary leaves the status alone too.
    public let status: String?

    public init(
        componentId: String,
        name: String?,
        sensitivity: String,
        threatsDisabled: Bool,
        runsAs: String,
        shape: String? = nil,
        holds: [String]? = nil,
        tags: [String]? = nil,
        status: String? = nil
    ) {
        self.status = status
        self.tags = tags
        self.holds = holds
        self.componentId = componentId
        self.name = name
        self.sensitivity = sensitivity
        self.threatsDisabled = threatsDisabled
        self.runsAs = runsAs
        self.shape = shape
    }
}

public enum SetComponentPropertiesResponse: Equatable, Sendable {
    case updated
    case unknownComponent
    case unknownSensitivity
    case unknownPrivilegeLevel
    case unknownShape
    case unknownAsset
}

/// Changes what a node is called, how sensitive its data is, what shape it
/// draws as, and whether it raises threats at all.
///
/// One use case for all three, the way `SetZoneProperties` does it: the panel
/// writes what the user sees, and the model takes it or refuses it whole.
public struct SetComponentProperties: SetComponentPropertiesUseCase {
    private let models: ThreatModelGateway
    /// The scheme in use, so a word this project does not hold is refused.
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: SetComponentPropertiesRequest) -> SetComponentPropertiesResponse {
        let componentId = ComponentId(request.componentId)
        guard let sensitivity = DataSensitivity.validated(
            request.sensitivity,
            in: catalogue.classifications()
        ) else {
            return .unknownSensitivity
        }
        guard let runsAs = PrivilegeLevel(rawValue: request.runsAs) else {
            return .unknownPrivilegeLevel
        }
        var shape: DiagramShape?
        if let word = request.shape {
            guard let picked = DiagramShape(rawValue: word) else { return .unknownShape }
            shape = picked
        }
        let name = request.name?.trimmingWhitespace() ?? ""

        return models.mutate(label: ChangeLabel.setComponentProperties) { model in
            guard let index = model.components.firstIndex(where: { $0.id == componentId }) else {
                return .unknownComponent
            }
            if let holds = request.holds {
                let declared = Set(model.systemAssets.map(\.id))
                guard holds.allSatisfy(declared.contains) else { return .unknownAsset }
                model.components[index].holds = holds
            }
            if let tags = request.tags {
                model.components[index].tags = tags
            }
            if let status = request.status.flatMap(ComponentStatus.init(rawValue:)) {
                model.components[index].status = status
            }

            model.components[index].customName = name.isEmpty ? nil : name
            model.components[index].sensitivity = sensitivity
            model.components[index].threatsDisabled = request.threatsDisabled
            model.components[index].runsAs = runsAs
            model.components[index].shape = shape
            return .updated
        }
    }
}
