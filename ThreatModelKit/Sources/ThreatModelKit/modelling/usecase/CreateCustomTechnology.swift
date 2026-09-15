public protocol CreateCustomTechnologyUseCase {
    func execute(_ request: CreateCustomTechnologyRequest) -> CreateCustomTechnologyResponse
}

public struct CreateCustomTechnologyRequest: Equatable, Sendable {
    public let name: String
    public let categoryId: String
    public let description: String
    public let threatIds: [String]
    public let enforcesEncryption: Bool
    /// The controls this technology brings, in the team's own words.
    public let controls: [String]

    public init(
        name: String,
        categoryId: String,
        description: String,
        threatIds: [String],
        enforcesEncryption: Bool,
        controls: [String] = []
    ) {
        self.name = name
        self.categoryId = categoryId
        self.description = description
        self.threatIds = threatIds
        self.enforcesEncryption = enforcesEncryption
        self.controls = controls
    }
}

public enum CreateCustomTechnologyResponse: Equatable, Sendable {
    case created(technologyId: String)
    case emptyName
    case unknownCategory
    /// Another technology this model defines is already called that. Two of
    /// one name on the palette is two rows a person cannot tell apart.
    case nameAlreadyUsed(byTechnologyId: String)
}

/// Adds a technology this model defines for itself.
///
/// A threat it names that the catalogue does not hold is dropped when the
/// threats are read, the same way a dangling id in the vendored data is. The
/// editor only offers real ones.
public struct CreateCustomTechnology: CreateCustomTechnologyUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue
    private let ids: IdentityGenerator

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue, ids: IdentityGenerator) {
        self.models = models
        self.catalogue = catalogue
        self.ids = ids
    }

    public func execute(_ request: CreateCustomTechnologyRequest) -> CreateCustomTechnologyResponse {
        let name = request.name.trimmingWhitespace()
        guard name.isEmpty == false else { return .emptyName }

        let category = CategoryId(request.categoryId)
        guard catalogue.taxonomy().category(id: category) != nil else { return .unknownCategory }

        if let clash = models.current().customTechnologies.first(
            where: { $0.name.caseInsensitiveCompare(name) == .orderedSame }
        ) {
            return .nameAlreadyUsed(byTechnologyId: clash.id.value)
        }

        let technology = CustomTechnology(
            id: TechnologyId("custom-\(ids.next())"),
            name: name,
            category: category,
            description: request.description.trimmingWhitespace(),
            threatIds: request.threatIds.map(ThreatId.init),
            enforcesEncryption: request.enforcesEncryption,
            controls: request.controls.map { $0.trimmingWhitespace() }.filter { $0.isEmpty == false }
        )

        return models.mutate(label: ChangeLabel.createCustomTechnology) { model in
            model.customTechnologies.append(technology)
            return .created(technologyId: technology.id.value)
        }
    }
}
