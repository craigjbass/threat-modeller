public protocol SetComponentAssetUseCase {
    func execute(_ request: SetComponentAssetRequest) -> SetComponentAssetResponse
}

public struct SetComponentAssetRequest: Equatable, Sendable {
    public let componentId: String
    /// Names the asset on the component. Writing the same name again changes
    /// the asset that is there.
    public let name: String
    /// A classification id, taking the words a component's `data` takes.
    public let classification: String

    public init(componentId: String, name: String, classification: String) {
        self.componentId = componentId
        self.name = name
        self.classification = classification
    }
}

public enum SetComponentAssetResponse: Equatable, Sendable {
    case recorded
    case noName
    case unknownComponent
    case unknownClassification

    public func describe(into message: inout String?) {
        switch self {
        case .recorded: message = nil
        case .noName: message = "An asset needs a name."
        case .unknownComponent: message = "This system holds no such component."
        case .unknownClassification:
            message = "This project holds no such classification."
        }
    }
}

/// Writes one `asset` block on a component.
///
/// Language guide section 4.5. The block names a thing of value the component
/// holds, stated on the component rather than on the system. The component
/// scores at the highest sensitivity among its own `data` word and every
/// asset it states.
public struct SetComponentAsset: SetComponentAssetUseCase {
    private let models: ThreatModelGateway
    /// The scheme in use, so a word this project does not hold is refused.
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: SetComponentAssetRequest) -> SetComponentAssetResponse {
        let name = request.name.trimmingWhitespace()

        guard name.isEmpty == false else { return .noName }
        guard let classification = DataSensitivity.validated(
            request.classification,
            in: catalogue.classifications()
        ) else {
            return .unknownClassification
        }
        let componentId = ComponentId(request.componentId)

        return models.mutate(label: ChangeLabel.setComponentAsset) { model in
            guard let index = model.components.firstIndex(where: { $0.id == componentId }) else {
                return .unknownComponent
            }
            let written = Asset(name: name, sensitivity: classification)
            if let already = model.components[index].assets
                .firstIndex(where: { $0.name == name }) {
                model.components[index].assets[already] = written
            } else {
                model.components[index].assets.append(written)
            }
            return .recorded
        }
    }
}

public protocol RemoveComponentAssetUseCase {
    func execute(_ request: RemoveComponentAssetRequest) -> RemoveComponentAssetResponse
}

public struct RemoveComponentAssetRequest: Equatable, Sendable {
    public let componentId: String
    public let name: String

    public init(componentId: String, name: String) {
        self.componentId = componentId
        self.name = name
    }
}

public enum RemoveComponentAssetResponse: Equatable, Sendable {
    case removed
    case unknownComponent
    case noSuchAsset

    public func describe(into message: inout String?) {
        switch self {
        case .removed: message = nil
        case .unknownComponent: message = "This system holds no such component."
        case .noSuchAsset: message = "This component states no such asset."
        }
    }
}

/// Takes one `asset` block off a component. The component then scores at its
/// own `data` word and the assets that are left.
public struct RemoveComponentAsset: RemoveComponentAssetUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RemoveComponentAssetRequest) -> RemoveComponentAssetResponse {
        let componentId = ComponentId(request.componentId)
        let name = request.name.trimmingWhitespace()

        return models.mutate(label: ChangeLabel.removeComponentAsset) { model in
            guard let index = model.components.firstIndex(where: { $0.id == componentId }) else {
                return .unknownComponent
            }
            guard model.components[index].assets.contains(where: { $0.name == name }) else {
                return .noSuchAsset
            }
            model.components[index].assets.removeAll { $0.name == name }
            return .removed
        }
    }
}
