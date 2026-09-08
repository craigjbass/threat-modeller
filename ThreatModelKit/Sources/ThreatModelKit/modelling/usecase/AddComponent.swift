public protocol AddComponentUseCase {
    func execute(_ request: AddComponentRequest) -> AddComponentResponse
}

public struct AddComponentRequest: Equatable, Sendable {
    public let technologyId: String
    public let x: Double
    public let y: Double
    public let sensitivity: String

    public init(technologyId: String, x: Double, y: Double, sensitivity: String) {
        self.technologyId = technologyId
        self.x = x
        self.y = y
        self.sensitivity = sensitivity
    }
}

public enum AddComponentResponse: Equatable, Sendable {
    case added(componentId: String)
    case unknownTechnology
    case unknownSensitivity
}

public struct AddComponent: AddComponentUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue
    private let ids: IdentityGenerator

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue, ids: IdentityGenerator) {
        self.models = models
        self.catalogue = catalogue
        self.ids = ids
    }

    public func execute(_ request: AddComponentRequest) -> AddComponentResponse {
        let technologyId = TechnologyId(request.technologyId)
        guard catalogue.findById(technologyId) != nil else {
            return .unknownTechnology
        }
        guard let sensitivity = DataSensitivity(rawValue: request.sensitivity) else {
            return .unknownSensitivity
        }

        let component = Component(
            id: ComponentId(ids.next()),
            technologyId: technologyId,
            position: Point(x: request.x, y: request.y),
            sensitivity: sensitivity
        )

        return models.mutate { model in
            model.components.append(component)
            return .added(componentId: component.id.value)
        }
    }
}
