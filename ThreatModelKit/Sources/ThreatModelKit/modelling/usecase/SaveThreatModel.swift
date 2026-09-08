import Foundation

public protocol SaveThreatModelUseCase {
    func execute(_ request: SaveThreatModelRequest) -> SaveThreatModelResponse
}

public struct SaveThreatModelRequest: Equatable, Sendable {
    public init() {}
}

public enum SaveThreatModelResponse: Equatable, Sendable {
    /// The bytes to write. The delivery mechanism owns the file; the core owns
    /// what goes in it.
    case saved(data: Data)
    case notWritable(reason: String)
}

/// Stamps the model with the time and the catalogue it was last assessed
/// against, then turns it into bytes.
public struct SaveThreatModel: SaveThreatModelUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue
    private let clock: Clock
    private let files: ThreatModelFileGateway

    public init(
        models: ThreatModelGateway,
        catalogue: TechnologyCatalogue,
        clock: Clock,
        files: ThreatModelFileGateway
    ) {
        self.models = models
        self.catalogue = catalogue
        self.clock = clock
        self.files = files
    }

    public func execute(_ request: SaveThreatModelRequest) -> SaveThreatModelResponse {
        let now = clock.now()
        let version = catalogue.version()

        let stamped = models.mutate { model -> ThreatModel in
            model.updatedAt = now
            model.catalogueVersion = version
            return model
        }

        do {
            return .saved(data: try files.encode(stamped))
        } catch {
            return .notWritable(reason: String(describing: error))
        }
    }
}
