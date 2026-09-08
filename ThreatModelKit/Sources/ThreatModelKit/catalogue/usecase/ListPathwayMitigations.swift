public protocol ListPathwayMitigationsUseCase {
    func execute(_ request: ListPathwayMitigationsRequest) -> ListPathwayMitigationsResponse
}

public struct ListPathwayMitigationsRequest: Equatable, Sendable {
    public init() {}
}

public struct ListedPathwayMitigation: Equatable, Sendable {
    public let id: String
    public let label: String
    public let description: String
    public let isEnabled: Bool
    public let mode: String
    public let reductionPercent: Int
    /// The technologies that provide it, by name, so the screen can say what
    /// the user would have to add.
    public let providedByTechnologyNames: [String]
    /// The threats it answers, by name.
    public let mitigatedThreatNames: [String]
    /// True when something on this diagram provides it. A switch turned on
    /// that nothing provides changes no score.
    public let isProvidedOnThisModel: Bool

    public init(
        id: String,
        label: String,
        description: String,
        isEnabled: Bool,
        mode: String,
        reductionPercent: Int,
        providedByTechnologyNames: [String],
        mitigatedThreatNames: [String],
        isProvidedOnThisModel: Bool
    ) {
        self.id = id
        self.label = label
        self.description = description
        self.isEnabled = isEnabled
        self.mode = mode
        self.reductionPercent = reductionPercent
        self.providedByTechnologyNames = providedByTechnologyNames
        self.mitigatedThreatNames = mitigatedThreatNames
        self.isProvidedOnThisModel = isProvidedOnThisModel
    }
}

public struct ListPathwayMitigationsResponse: Equatable, Sendable {
    public let isMasterEnabled: Bool
    public let mitigations: [ListedPathwayMitigation]

    public init(isMasterEnabled: Bool, mitigations: [ListedPathwayMitigation]) {
        self.isMasterEnabled = isMasterEnabled
        self.mitigations = mitigations
    }
}

/// The pathway mitigation settings screen's contents.
///
/// It reads the model as well as the catalogue, because a mitigation nothing
/// on this diagram provides changes no score however the user sets it, and the
/// screen should say so rather than leave them guessing.
public struct ListPathwayMitigations: ListPathwayMitigationsUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: ListPathwayMitigationsRequest) -> ListPathwayMitigationsResponse {
        let model = models.current()
        let settings = model.pathwayMitigations
        let present = Set(model.components.map(\.technologyId))
        let lookup = TechnologyLookup(model: model, catalogue: catalogue)

        // Every threat the catalogue knows, so a mitigation can be named after
        // what it answers rather than after threat ids.
        var threatNames: [ThreatId: String] = [:]
        for technology in catalogue.all() {
            for threat in catalogue.threatsFor(technologyId: technology.id) {
                threatNames[threat.id] = threat.name
            }
        }
        for threat in catalogue.connectionThreats() + catalogue.zoneThreats() {
            threatNames[threat.id] = threat.name
        }

        return ListPathwayMitigationsResponse(
            isMasterEnabled: settings.isMasterEnabled,
            mitigations: catalogue.pathwayMitigations().map { definition in
                let config = settings.config(for: definition.id)
                return ListedPathwayMitigation(
                    id: definition.id.value,
                    label: definition.label,
                    description: definition.description,
                    isEnabled: config.isEnabled,
                    mode: config.mode.rawValue,
                    reductionPercent: config.reductionPercent,
                    providedByTechnologyNames: definition.technologyIds.compactMap {
                        lookup.findById($0)?.name
                    },
                    mitigatedThreatNames: definition.mitigatesThreatIds.compactMap { threatNames[$0] },
                    isProvidedOnThisModel: definition.technologyIds.contains(where: present.contains)
                )
            }
        )
    }
}
