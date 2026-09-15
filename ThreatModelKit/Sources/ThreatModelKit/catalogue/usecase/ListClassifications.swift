public protocol ListClassificationsUseCase {
    func execute(_ request: ListClassificationsRequest) -> ListClassificationsResponse
}

public struct ListClassificationsRequest: Equatable, Sendable {
    public init() {}
}

public struct ListedClassification: Equatable, Sendable {
    public let id: String
    public let label: String
    /// The colour a chip is painted, as a hex string, or nil to let the
    /// application choose.
    public let colour: String?

    public init(id: String, label: String, colour: String? = nil) {
        self.id = id
        self.label = label
        self.colour = colour
    }
}

public struct ListClassificationsResponse: Equatable, Sendable {
    /// Least sensitive first, which is the order the scheme states.
    public let classifications: [ListedClassification]
    /// The library that states the scheme, or nil for the standard four.
    public let libraryLabel: String?

    public init(classifications: [ListedClassification], libraryLabel: String? = nil) {
        self.classifications = classifications
        self.libraryLabel = libraryLabel
    }
}

/// How this project names the sensitivity of what a component holds.
///
/// The component bar, the context menu and the palette chips all read this,
/// so a project whose library states its own scheme states it everywhere.
public struct ListClassifications: ListClassificationsUseCase {
    private let catalogue: TechnologyCatalogue

    public init(catalogue: TechnologyCatalogue) {
        self.catalogue = catalogue
    }

    public func execute(_ request: ListClassificationsRequest) -> ListClassificationsResponse {
        let scheme = catalogue.classifications()
        return ListClassificationsResponse(
            classifications: scheme.levels.map {
                ListedClassification(id: $0.id, label: $0.label, colour: $0.colour)
            },
            libraryLabel: scheme.libraryLabel
        )
    }
}
