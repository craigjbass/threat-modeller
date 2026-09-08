public protocol EditCustomTechnologyUseCase {
    func execute(_ request: EditCustomTechnologyRequest) -> EditCustomTechnologyResponse
}

public struct EditCustomTechnologyRequest: Equatable, Sendable {
    public let technologyId: String
    public let name: String
    public let categoryId: String
    public let description: String
    public let threatIds: [String]
    public let enforcesEncryption: Bool

    public init(
        technologyId: String,
        name: String,
        categoryId: String,
        description: String,
        threatIds: [String],
        enforcesEncryption: Bool
    ) {
        self.technologyId = technologyId
        self.name = name
        self.categoryId = categoryId
        self.description = description
        self.threatIds = threatIds
        self.enforcesEncryption = enforcesEncryption
    }
}

public enum EditCustomTechnologyResponse: Equatable, Sendable {
    case updated
    case unknownTechnology
    case emptyName
    case unknownCategory
}

/// Changes a technology this model defines. All or nothing: one bad value
/// leaves every property as it was.
public struct EditCustomTechnology: EditCustomTechnologyUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: EditCustomTechnologyRequest) -> EditCustomTechnologyResponse {
        let id = TechnologyId(request.technologyId)
        let name = request.name.trimmingWhitespace()
        let category = CategoryId(request.categoryId)
        let knowsCategory = catalogue.taxonomy().category(id: category) != nil

        return models.mutate { model in
            guard let index = model.customTechnologies.firstIndex(where: { $0.id == id }) else {
                return .unknownTechnology
            }
            guard name.isEmpty == false else { return .emptyName }
            guard knowsCategory else { return .unknownCategory }

            model.customTechnologies[index].name = name
            model.customTechnologies[index].category = category
            model.customTechnologies[index].description = request.description.trimmingWhitespace()
            model.customTechnologies[index].threatIds = request.threatIds.map(ThreatId.init)
            model.customTechnologies[index].enforcesEncryption = request.enforcesEncryption
            return .updated
        }
    }
}
