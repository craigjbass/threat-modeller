/// The vendored catalogue and the open project's libraries, read as one.
///
/// Nothing downstream can tell a library entry from a vendored one, which is
/// what keeps the resolver, the palette, the compiler and the report unchanged.
public struct MergedCatalogue: TechnologyCatalogue {
    private let base: TechnologyCatalogue
    private let store: LibraryStore

    public init(base: TechnologyCatalogue, store: LibraryStore) {
        self.base = base
        self.store = store
    }

    public func all() -> [Technology] {
        base.all() + store.all().flatMap(\.technologies)
    }

    public func findById(_ id: TechnologyId) -> Technology? {
        if let found = base.findById(id) { return found }
        for library in store.all() {
            if let found = library.technologies.first(where: { $0.id == id }) { return found }
        }
        return nil
    }

    public func threatsFor(technologyId: TechnologyId) -> [Threat] {
        if base.findById(technologyId) != nil {
            return base.threatsFor(technologyId: technologyId)
        }
        guard let technology = findById(technologyId) else { return [] }
        return technology.threatIds.compactMap { threat(id: $0) }
    }

    public func connectionThreats() -> [Threat] {
        base.connectionThreats() + store.all().flatMap { $0.threats.filter(\.isConnectionThreat) }
    }

    public func zoneThreats() -> [Threat] {
        base.zoneThreats() + store.all().flatMap { $0.threats.filter(\.isZoneThreat) }
    }

    /// A library defines no pathway mitigation, so these are the vendored ones.
    public func pathwayMitigations() -> [PathwayMitigationDefinition] {
        base.pathwayMitigations()
    }

    /// The vendored catalogue's version. A library's tag is in the lock file.
    public func version() -> CatalogueVersion { base.version() }

    /// A library adds no category, no severity and no stride category.
    public func taxonomy() -> Taxonomy { base.taxonomy() }

    public func providers() -> [Provider] {
        base.providers() + store.all().map(\.provider)
    }

    /// A threat a library declares, else the same id in the base catalogue.
    private func threat(id: ThreatId) -> Threat? {
        for library in store.all() {
            if let found = library.threats.first(where: { $0.id == id }) { return found }
        }
        for technology in base.all() {
            if let found = base.threatsFor(technologyId: technology.id).first(where: { $0.id == id }) {
                return found
            }
        }
        return base.connectionThreats().first { $0.id == id }
            ?? base.zoneThreats().first { $0.id == id }
    }
}
