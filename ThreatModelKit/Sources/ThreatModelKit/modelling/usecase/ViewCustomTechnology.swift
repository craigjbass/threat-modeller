public protocol ViewCustomTechnologyUseCase {
    func execute(_ request: ViewCustomTechnologyRequest) -> ViewCustomTechnologyResponse
}

public struct ViewCustomTechnologyRequest: Equatable, Sendable {
    public let technologyId: String
    public init(technologyId: String) { self.technologyId = technologyId }
}

public enum ViewCustomTechnologyResponse: Equatable, Sendable {
    case found(ViewedCustomTechnology)
    case unknownTechnology
}

public struct ViewedCustomTechnology: Equatable, Sendable {
    public let id: String
    public let name: String
    public let categoryId: String
    public let description: String
    public let threatIds: [String]
    public let enforcesEncryption: Bool
    /// The controls this technology brings, in the team's own words.
    public let controls: [String]

    public init(
        id: String,
        name: String,
        categoryId: String,
        description: String,
        threatIds: [String],
        enforcesEncryption: Bool,
        controls: [String] = []
    ) {
        self.id = id
        self.name = name
        self.categoryId = categoryId
        self.description = description
        self.threatIds = threatIds
        self.enforcesEncryption = enforcesEncryption
        self.controls = controls
    }
}

/// Reads back what the user typed, so the editor opens on the values the
/// model holds rather than on what a view remembered.
public struct ViewCustomTechnology: ViewCustomTechnologyUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: ViewCustomTechnologyRequest) -> ViewCustomTechnologyResponse {
        guard let technology = models.current().customTechnology(TechnologyId(request.technologyId)) else {
            return .unknownTechnology
        }

        return .found(
            ViewedCustomTechnology(
                id: technology.id.value,
                name: technology.name,
                categoryId: technology.category.value,
                description: technology.description,
                threatIds: technology.threatIds.map(\.value),
                enforcesEncryption: technology.enforcesEncryption,
                controls: technology.controls
            )
        )
    }
}
