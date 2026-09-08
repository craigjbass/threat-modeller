public protocol ViewCatalogueVersionUseCase {
    func execute(_ request: ViewCatalogueVersionRequest) -> ViewCatalogueVersionResponse
}

public struct ViewCatalogueVersionRequest: Equatable, Sendable {
    public init() {}
}

public struct ViewCatalogueVersionResponse: Equatable, Sendable {
    public let repository: String
    public let tag: String
    public let technologyCount: Int

    public init(repository: String, tag: String, technologyCount: Int) {
        self.repository = repository
        self.tag = tag
        self.technologyCount = technologyCount
    }
}

/// What the About window says about the catalogue.
///
/// Spec section 7: this application records the vendored catalogue's
/// repository and release tag where a user can read them. The tag comes from
/// the catalogue itself, so it cannot fall out of step with what is assessed.
public struct ViewCatalogueVersion: ViewCatalogueVersionUseCase {
    private let catalogue: TechnologyCatalogue

    public init(catalogue: TechnologyCatalogue) {
        self.catalogue = catalogue
    }

    public func execute(_ request: ViewCatalogueVersionRequest) -> ViewCatalogueVersionResponse {
        let version = catalogue.version()
        return ViewCatalogueVersionResponse(
            repository: version.repository,
            tag: version.tag,
            technologyCount: catalogue.all().count
        )
    }
}
