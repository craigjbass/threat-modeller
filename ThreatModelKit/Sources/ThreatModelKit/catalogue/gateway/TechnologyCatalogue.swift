/// Reads the technology and threat catalogue.
///
/// Later milestones extend this port with `zoneThreats()` and
/// `pathwayMitigations()`. Do not add them before the milestone that needs them.
public protocol TechnologyCatalogue {
    func all() -> [Technology]
    func findById(_ id: TechnologyId) -> Technology?
    /// The technology's threats, in the order the technology declares them.
    /// Empty for an unknown technology.
    func threatsFor(technologyId: TechnologyId) -> [Threat]
    /// Every threat the catalogue flags as belonging to a link between two
    /// components, in catalogue order. These threats belong to no technology.
    func connectionThreats() -> [Threat]
    func taxonomy() -> Taxonomy
    func providers() -> [Provider]
}
