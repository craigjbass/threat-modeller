/// Answers "which actors does this system face?" from the model first and the
/// catalogue second.
///
/// A `threat_actor` block in the `.arch` file beats a library actor of the
/// same id, whole: the local block's attributes are the actor, and the
/// library's are not merged in.
public struct ThreatActorLookup {
    private let local: [ThreatActorId: ThreatActor]
    private let facedIds: [ThreatActorId]
    private let catalogue: TechnologyCatalogue

    public init(model: ThreatModel, catalogue: TechnologyCatalogue) {
        local = Dictionary(
            model.localActors.map { ($0.id, $0) },
            uniquingKeysWith: { _, later in later }
        )
        facedIds = model.facedActorIds.map(ThreatActorId.init)
        self.catalogue = catalogue
    }

    public func findById(_ id: ThreatActorId) -> ThreatActor? {
        local[id] ?? catalogue.findActor(id)
    }

    /// The faced actors, in the order the file states them. An id nothing
    /// holds is left out; the project reader states that as an error.
    public func faced() -> [ThreatActor] {
        facedIds.compactMap(findById)
    }

    /// The faced ids nothing holds an actor for.
    public func unknownFacedIds() -> [ThreatActorId] {
        facedIds.filter { findById($0) == nil }
    }
}
