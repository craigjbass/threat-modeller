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
    /// The zone whose rectangle holds this component's centre, or nil.
    /// Derived from the geometry every time; nothing stores it.
    public let zoneId: String?

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
        isUnknownTechnology: Bool,
        zoneId: String?
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
        self.zoneId = zoneId
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

public struct ViewedZone: Equatable, Sendable {
    public let id: String
    /// What the canvas shows in the zone header: the user's own name, else the
    /// network type, else the zone kind.
    public let name: String
    /// The user's own name, or nil when they have not set one. The panel edits
    /// this, not `name`.
    public let customName: String?
    public let networkZoneId: String
    public let networkTypeId: String
    public let riskReductionEnabled: Bool
    public let riskReductionPercent: Int
    public let x: Double
    public let y: Double
    public let width: Double
    public let height: Double

    public init(
        id: String,
        name: String,
        customName: String?,
        networkZoneId: String,
        networkTypeId: String,
        riskReductionEnabled: Bool,
        riskReductionPercent: Int,
        x: Double,
        y: Double,
        width: Double,
        height: Double
    ) {
        self.id = id
        self.name = name
        self.customName = customName
        self.networkZoneId = networkZoneId
        self.networkTypeId = networkTypeId
        self.riskReductionEnabled = riskReductionEnabled
        self.riskReductionPercent = riskReductionPercent
        self.x = x
        self.y = y
        self.width = width
        self.height = height
    }
}

public struct ViewThreatModelResponse: Equatable, Sendable {
    public let name: String
    public let components: [ViewedComponent]
    public let connections: [ViewedConnection]
    /// In drawing order. A later zone wins where two overlap.
    public let zones: [ViewedZone]
    /// Whether there is anything to take back or put in again, so a menu item
    /// can dim itself from the same read that draws the canvas.
    public let canUndo: Bool
    public let canRedo: Bool

    public init(
        name: String,
        components: [ViewedComponent],
        connections: [ViewedConnection],
        zones: [ViewedZone],
        canUndo: Bool = false,
        canRedo: Bool = false
    ) {
        self.name = name
        self.components = components
        self.connections = connections
        self.zones = zones
        self.canUndo = canUndo
        self.canRedo = canRedo
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
                    isUnknownTechnology: technology == nil,
                    zoneId: ZoneContainment.zone(holding: component.centre, in: model.zones)?.id.value
                )
            },
            connections: model.connections.map {
                ViewedConnection(
                    id: $0.id.value,
                    sourceComponentId: $0.source.value,
                    targetComponentId: $0.target.value
                )
            },
            zones: model.zones.map {
                ViewedZone(
                    id: $0.id.value,
                    name: $0.displayName,
                    customName: $0.name,
                    networkZoneId: $0.networkZone.rawValue,
                    networkTypeId: $0.networkType.rawValue,
                    riskReductionEnabled: $0.riskReductionEnabled,
                    riskReductionPercent: $0.riskReductionPercent,
                    x: $0.rect.origin.x,
                    y: $0.rect.origin.y,
                    width: $0.rect.size.width,
                    height: $0.rect.size.height
                )
            },
            canUndo: models.canUndo,
            canRedo: models.canRedo
        )
    }
}
