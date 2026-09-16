/// Answers "which actors does this system face?" from the model first and the
/// catalogue second.
///
/// A `threat_actor` block in the `.arch` file beats a library actor of the
/// same id, whole: the local block's attributes are the actor, and the
/// library's are not merged in.
///
/// The faced actors are what `faces` states and the actor each user names,
/// so an insider written as a user is faced the way a listed actor is.
public struct ThreatActorLookup {
    private let local: [ThreatActorId: ThreatActor]
    private let facedIds: [ThreatActorId]
    private let listedIds: [ThreatActorId]
    private let userActors: [(userId: ComponentId, actorId: ThreatActorId)]
    private let catalogue: TechnologyCatalogue

    public init(model: ThreatModel, catalogue: TechnologyCatalogue) {
        local = Dictionary(
            model.localActors.map { ($0.id, $0) },
            uniquingKeysWith: { _, later in later }
        )
        facedIds = model.everyFacedActorId.map(ThreatActorId.init)
        listedIds = model.facedActorIds.map(ThreatActorId.init)
        userActors = model.components.compactMap { component in
            component.user?.threatActorId.map { (userId: component.id, actorId: ThreatActorId($0)) }
        }
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

    /// The `faces` entries nothing holds an actor for.
    public func unknownFacedIds() -> [ThreatActorId] {
        listedIds.filter { findById($0) == nil }
    }

    /// Each user whose `threat_actor` names an actor nothing holds.
    public func unknownUserActors() -> [(userId: ComponentId, actorId: ThreatActorId)] {
        userActors.filter { findById($0.actorId) == nil }
    }
}
