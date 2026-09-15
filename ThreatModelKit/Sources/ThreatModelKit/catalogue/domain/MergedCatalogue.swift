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

    /// The base catalogue, then every library technology whose id the base
    /// catalogue does not already hold. A duplicate id is a fault, not a
    /// second row in the palette.
    public func all() -> [Technology] {
        CatalogueAudit.deduplicate(base.all() + store.all().flatMap(\.technologies)).kept
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

    /// The vendored mitigations and every mitigation the libraries define.
    public func pathwayMitigations() -> [PathwayMitigationDefinition] {
        base.pathwayMitigations() + store.all().flatMap(\.pathwayMitigations)
    }

    /// The vendored catalogue's version. A library's tag is in the lock file.
    public func version() -> CatalogueVersion { base.version() }

    /// The vendored taxonomy, and every word the libraries add to it.
    ///
    /// A word the vendored taxonomy already holds stands: the vendored
    /// catalogue is the common ground, and a library adds to it rather than
    /// changing what a word already means. Two libraries that declare one id
    /// is a fault `LoadLibraries` reports, and the first one read stands.
    public func taxonomy() -> Taxonomy {
        let base = base.taxonomy()
        let libraries = store.all()

        var categories = base.categories
        var severities = base.severities
        var strides = base.stride

        for library in libraries {
            for category in library.categories
            where categories.contains(where: { $0.id == category.id }) == false {
                categories.append(category)
            }
            for stride in library.strides
            where strides.contains(where: { $0.id == stride.id }) == false {
                strides.append(stride)
            }
            for severity in library.severities
            where severities.contains(where: { $0.id == severity.id }) == false {
                // The rank counts on from what the taxonomy already holds, so
                // a library severity is worse than every vendored one and two
                // libraries do not fight over one rank.
                severities.append(
                    ThreatSeverity(
                        id: severity.id,
                        label: severity.label,
                        rank: severities.count + 1
                    )
                )
            }
        }

        return Taxonomy(stride: strides, severities: severities, categories: categories)
    }

    public func providers() -> [Provider] {
        base.providers() + store.all().map(\.provider)
    }

    /// The base catalogue's actors, then every actor the libraries define. An
    /// id the base catalogue already holds keeps the base catalogue's actor.
    public func threatActors() -> [ThreatActor] {
        var seen: Set<ThreatActorId> = []
        var actors: [ThreatActor] = []
        for actor in base.threatActors() + store.all().flatMap(\.threatActors)
        where seen.insert(actor.id).inserted {
            actors.append(actor)
        }
        return actors
    }

    public func findActor(_ id: ThreatActorId) -> ThreatActor? {
        threatActors().first { $0.id == id }
    }

    /// The base catalogue's faults, then every fault a library adds.
    public func faults() -> [CatalogueFault] {
        var found = base.faults()
        var seen = Set(base.all().map(\.id))
        for library in store.all() {
            for technology in library.technologies {
                guard seen.insert(technology.id).inserted else {
                    found.append(.duplicateTechnologyId(technology.id))
                    continue
                }
                for threatId in technology.threatIds where threat(id: threatId) == nil {
                    found.append(.danglingThreatId(technologyId: technology.id, threatId: threatId))
                }
            }
        }
        return found
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
