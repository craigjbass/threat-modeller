public protocol ListCategoriesUseCase {
    func execute(_ request: ListCategoriesRequest) -> ListCategoriesResponse
}

public struct ListCategoriesRequest: Equatable, Sendable {
    public init() {}
}

public struct ListedCategoryChoice: Equatable, Sendable {
    public let id: String
    public let label: String

    public init(id: String, label: String) {
        self.id = id
        self.label = label
    }
}

public struct ListCategoriesResponse: Equatable, Sendable {
    /// Every category, by label, so a list reads the same every time.
    public let categories: [ListedCategoryChoice]

    public init(categories: [ListedCategoryChoice]) {
        self.categories = categories
    }
}

/// Every category a technology can belong to.
///
/// The custom technology editor offers these. It used to read the palette,
/// which lists only the categories something is already in, so a category with
/// no technology in it could not be picked. The taxonomy states them all,
/// including the ones a library adds.
public struct ListCategories: ListCategoriesUseCase {
    private let catalogue: TechnologyCatalogue

    public init(catalogue: TechnologyCatalogue) {
        self.catalogue = catalogue
    }

    public func execute(_ request: ListCategoriesRequest) -> ListCategoriesResponse {
        ListCategoriesResponse(
            categories: catalogue.taxonomy().categories
                .map { ListedCategoryChoice(id: $0.id.value, label: $0.label) }
                .sorted { $0.label < $1.label }
        )
    }
}
