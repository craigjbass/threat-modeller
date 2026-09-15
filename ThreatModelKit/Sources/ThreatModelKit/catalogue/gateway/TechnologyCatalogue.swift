/// Reads the technology and threat catalogue.
///
/// This is every method the spec's section 6 lists.
public protocol TechnologyCatalogue: Sendable {
    func all() -> [Technology]
    func findById(_ id: TechnologyId) -> Technology?
    /// The technology's threats, in the order the technology declares them.
    /// Empty for an unknown technology.
    func threatsFor(technologyId: TechnologyId) -> [Threat]
    /// Every threat the catalogue flags as belonging to a link between two
    /// components, in catalogue order. These threats belong to no technology.
    func connectionThreats() -> [Threat]
    /// Every threat the catalogue flags as belonging to a network zone, in
    /// catalogue order. A zone threat may also be a technology's own threat.
    func zoneThreats() -> [Threat]
    /// Every pathway mitigation the catalogue defines, in catalogue order.
    func pathwayMitigations() -> [PathwayMitigationDefinition]
    /// The vendored catalogue this gateway reads.
    func version() -> CatalogueVersion
    func taxonomy() -> Taxonomy
    func providers() -> [Provider]
    /// Every threat actor this catalogue holds, in catalogue order.
    func threatActors() -> [ThreatActor]
    /// The threat actor with that id, or nil.
    func findActor(_ id: ThreatActorId) -> ThreatActor?
    /// Every fault found while this catalogue was read. Empty for a sound
    /// catalogue. Nothing is dropped without a fault naming what was dropped.
    func faults() -> [CatalogueFault]
    /// What the project's libraries change about a threat this catalogue
    /// holds, by threat id. Empty for a catalogue no library sits over.
    func overrides() -> [ThreatId: ThreatOverride]
    /// Every threat this catalogue holds, wherever it holds it, in catalogue
    /// order.
    ///
    /// One read. A caller that wants the whole set used to walk every
    /// technology and ask for its threats, which is 277 reads of the
    /// catalogue for one list.
    func everyThreat() -> [Threat]
    /// How this project names the sensitivity of what a component holds. The
    /// standard four unless a library states its own.
    func classifications() -> ClassificationScheme
}

public extension TechnologyCatalogue {
    /// The standard four, for a catalogue no library sits over.
    func classifications() -> ClassificationScheme { .standard }

    /// A catalogue no library sits over changes nothing.
    func overrides() -> [ThreatId: ThreatOverride] { [:] }

    /// The slow answer, for a catalogue that holds no index: walk every
    /// technology. A gateway that can answer in one read overrides this.
    func everyThreat() -> [Threat] {
        var found: [ThreatId: Threat] = [:]
        var ordered: [Threat] = []
        for technology in all() {
            for threat in threatsFor(technologyId: technology.id)
            where found.updateValue(threat, forKey: threat.id) == nil {
                ordered.append(threat)
            }
        }
        for threat in connectionThreats() + zoneThreats()
        where found.updateValue(threat, forKey: threat.id) == nil {
            ordered.append(threat)
        }
        return ordered
    }
}
