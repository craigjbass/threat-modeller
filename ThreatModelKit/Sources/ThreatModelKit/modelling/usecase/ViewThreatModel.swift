public protocol ViewThreatModelUseCase {
    func execute(_ request: ViewThreatModelRequest) -> ViewThreatModelResponse
}

public struct ViewThreatModelRequest: Equatable, Sendable {
    public init() {}
}

public struct ViewedComponent: Equatable, Sendable {
    public let id: String
    public let technologyId: String
    /// The user's own name when they set one, else the technology's name, else
    /// the technology id when the catalogue no longer holds that technology.
    public let name: String
    /// Empty when the catalogue no longer holds the technology.
    public let providerId: String
    /// Empty when the catalogue no longer holds the technology.
    public let categoryId: String
    public let x: Double
    public let y: Double
    public let sensitivityId: String
    public let threatsDisabled: Bool
    /// True when the catalogue has no entry for `technologyId`. A model saved
    /// against an older catalogue can carry one. The canvas still draws it.
    public let isUnknownTechnology: Bool

    public init(
        id: String,
        technologyId: String,
        name: String,
        providerId: String,
        categoryId: String,
        x: Double,
        y: Double,
        sensitivityId: String,
        threatsDisabled: Bool,
        isUnknownTechnology: Bool
    ) {
        self.id = id
        self.technologyId = technologyId
        self.name = name
        self.providerId = providerId
        self.categoryId = categoryId
        self.x = x
        self.y = y
        self.sensitivityId = sensitivityId
        self.threatsDisabled = threatsDisabled
        self.isUnknownTechnology = isUnknownTechnology
    }
}

public struct ViewedConnection: Equatable, Sendable {
    public let id: String
    public let sourceComponentId: String
    public let targetComponentId: String

    public init(id: String, sourceComponentId: String, targetComponentId: String) {
        self.id = id
        self.sourceComponentId = sourceComponentId
        self.targetComponentId = targetComponentId
    }
}

public struct ViewThreatModelResponse: Equatable, Sendable {
    public let name: String
    public let components: [ViewedComponent]
    public let connections: [ViewedConnection]

    public init(name: String, components: [ViewedComponent], connections: [ViewedConnection]) {
        self.name = name
        self.components = components
        self.connections = connections
    }
}

/// Everything the canvas draws, as plain values. The canvas never reads a
/// gateway, so this use case supplies the drawing.
public struct ViewThreatModel: ViewThreatModelUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: ViewThreatModelRequest) -> ViewThreatModelResponse {
        let model = models.current()

        return ViewThreatModelResponse(
            name: model.name,
            components: model.components.map { component in
                let technology = catalogue.findById(component.technologyId)
                return ViewedComponent(
                    id: component.id.value,
                    technologyId: component.technologyId.value,
                    name: component.customName ?? technology?.name ?? component.technologyId.value,
                    providerId: technology?.provider.value ?? "",
                    categoryId: technology?.category.value ?? "",
                    x: component.position.x,
                    y: component.position.y,
                    sensitivityId: component.sensitivity.rawValue,
                    threatsDisabled: component.threatsDisabled,
                    isUnknownTechnology: technology == nil
                )
            },
            connections: model.connections.map {
                ViewedConnection(
                    id: $0.id.value,
                    sourceComponentId: $0.source.value,
                    targetComponentId: $0.target.value
                )
            }
        )
    }
}
