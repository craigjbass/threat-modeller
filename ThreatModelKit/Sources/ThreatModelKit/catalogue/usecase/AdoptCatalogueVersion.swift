public protocol AdoptCatalogueVersionUseCase {
    func execute(_ request: AdoptCatalogueVersionRequest) -> AdoptCatalogueVersionResponse
}

public struct AdoptCatalogueVersionRequest: Equatable, Sendable {
    public init() {}
}

public enum AdoptCatalogueVersionResponse: Equatable, Sendable {
    /// The tag the model now states.
    case adopted(tag: String)
}

/// Stamps the model with the catalogue in use.
///
/// A model states the catalogue it was last assessed against, and the
/// application reports the difference rather than hiding it. This is how a
/// person takes the new one: the next save writes the tag into the file.
public struct AdoptCatalogueVersion: AdoptCatalogueVersionUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: AdoptCatalogueVersionRequest) -> AdoptCatalogueVersionResponse {
        models.mutate { model in
            model.catalogueVersion = catalogue.version()
            return .adopted(tag: catalogue.version().tag)
        }
    }
}
