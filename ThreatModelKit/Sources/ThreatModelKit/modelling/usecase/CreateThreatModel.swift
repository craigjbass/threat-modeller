public protocol CreateThreatModelUseCase {
    func execute(_ request: CreateThreatModelRequest) -> CreateThreatModelResponse
}

public struct CreateThreatModelRequest: Equatable, Sendable {
    public let name: String
    public init(name: String) { self.name = name }
}

public enum CreateThreatModelResponse: Equatable, Sendable {
    case created
    case emptyName
}

/// Starts a new, empty model, stamped with the time and the catalogue.
public struct CreateThreatModel: CreateThreatModelUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue
    private let clock: Clock

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue, clock: Clock) {
        self.models = models
        self.catalogue = catalogue
        self.clock = clock
    }

    public func execute(_ request: CreateThreatModelRequest) -> CreateThreatModelResponse {
        let name = request.name.trimmingWhitespace()
        guard name.isEmpty == false else { return .emptyName }

        let now = clock.now()
        models.save(
            ThreatModel(
                name: name,
                createdAt: now,
                updatedAt: now,
                catalogueVersion: catalogue.version()
            )
        )

        return .created
    }
}
