import Foundation

public protocol ListTechnologiesUseCase {
    func execute(_ request: ListTechnologiesRequest) -> ListTechnologiesResponse
}

public struct ListTechnologiesRequest: Equatable, Sendable {
    public init() {}
}

public struct ListTechnologiesResponse: Equatable, Sendable {
    public let providers: [ListedProvider]

    public init(providers: [ListedProvider]) {
        self.providers = providers
    }
}

public struct ListedProvider: Equatable, Sendable {
    public let id: String
    public let displayName: String
    public let categories: [ListedCategory]

    public init(id: String, displayName: String, categories: [ListedCategory]) {
        self.id = id
        self.displayName = displayName
        self.categories = categories
    }
}

public struct ListedCategory: Equatable, Sendable {
    public let id: String
    public let label: String
    public let technologies: [ListedTechnology]

    public init(id: String, label: String, technologies: [ListedTechnology]) {
        self.id = id
        self.label = label
        self.technologies = technologies
    }
}

public struct ListedTechnology: Equatable, Sendable {
    public let id: String
    public let name: String
    public let description: String

    public init(id: String, name: String, description: String) {
        self.id = id
        self.name = name
        self.description = description
    }
}

public struct ListTechnologies: ListTechnologiesUseCase {
    private let catalogue: TechnologyCatalogue

    public init(catalogue: TechnologyCatalogue) {
        self.catalogue = catalogue
    }

    public func execute(_ request: ListTechnologiesRequest) -> ListTechnologiesResponse {
        let taxonomy = catalogue.taxonomy()
        let byProvider = Dictionary(grouping: catalogue.all(), by: \.provider)

        let providers = catalogue.providers().compactMap { provider -> ListedProvider? in
            let technologies = byProvider[provider.id] ?? []
            guard technologies.isEmpty == false else { return nil }

            let byCategory = Dictionary(grouping: technologies, by: \.category)
            let categories = taxonomy.categories.compactMap { category -> ListedCategory? in
                guard let members = byCategory[category.id], members.isEmpty == false else { return nil }
                return ListedCategory(
                    id: category.id.value,
                    label: category.label,
                    technologies: members
                        .sorted { $0.name.caseInsensitiveCompare($1.name) == .orderedAscending }
                        .map {
                            ListedTechnology(id: $0.id.value, name: $0.name, description: $0.description)
                        }
                )
            }

            return ListedProvider(
                id: provider.id.value,
                displayName: provider.displayName,
                categories: categories
            )
        }

        return ListTechnologiesResponse(providers: providers)
    }
}
