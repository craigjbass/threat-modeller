/// Reads the technology and threat catalogue.
///
/// A later milestone extends this port with `pathwayMitigations()`. Do not add
/// it before the milestone that needs it.
public protocol TechnologyCatalogue {
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
    func taxonomy() -> Taxonomy
    func providers() -> [Provider]
}
