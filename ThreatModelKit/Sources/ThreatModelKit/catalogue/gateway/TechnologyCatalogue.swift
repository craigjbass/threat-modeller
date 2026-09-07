/// Reads the technology and threat catalogue.
///
/// Later milestones extend this port with `connectionThreats()`, `zoneThreats()`
/// and `pathwayMitigations()`. Do not add them before the milestone that needs them.
public protocol TechnologyCatalogue {
    func all() -> [Technology]
    func findById(_ id: TechnologyId) -> Technology?
    /// The technology's threats, in the order the technology declares them.
    /// Empty for an unknown technology.
    func threatsFor(technologyId: TechnologyId) -> [Threat]
    func taxonomy() -> Taxonomy
    func providers() -> [Provider]
}
