import ThreatModelKit

/// A working catalogue backed by arrays. Honours the same contract as the real one.
public final class InMemoryTechnologyCatalogue: TechnologyCatalogue {
    private let technologies: [Technology]
    private let threats: [ThreatId: Threat]
    private let taxonomyValue: Taxonomy
    private let providersValue: [Provider]

    public init(
        technologies: [Technology],
        threats: [Threat],
        taxonomy: Taxonomy,
        providers: [Provider]
    ) {
        self.technologies = technologies
        self.threats = Dictionary(uniqueKeysWithValues: threats.map { ($0.id, $0) })
        self.taxonomyValue = taxonomy
        self.providersValue = providers
    }

    public func all() -> [Technology] { technologies }

    public func findById(_ id: TechnologyId) -> Technology? {
        technologies.first { $0.id == id }
    }

    public func threatsFor(technologyId: TechnologyId) -> [Threat] {
        guard let technology = findById(technologyId) else { return [] }
        return technology.threatIds.compactMap { threats[$0] }
    }

    public func taxonomy() -> Taxonomy { taxonomyValue }

    public func providers() -> [Provider] { providersValue }
}
