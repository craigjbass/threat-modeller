/// Where each faced actor performs.
///
/// Section 5 of the user-through-a-client design. An actor `faces` lists
/// performs everywhere. An actor a user names performs everywhere when the
/// user states no `uses`, because the user states no reach. A user with
/// `uses` reaches each client it holds, each flow that leaves a client and
/// the component that flow ends at, each component `reaches` names, and
/// each flow that leaves the user itself with its end; the user's actor
/// performs only on those sources. An actor two users name performs
/// wherever either reaches.
///
/// A pure value built once from the model. It reads no gateway.
public struct ActorReach: Sendable {
    /// The source ids each actor performs on. No entry for an actor that
    /// performs everywhere.
    private let reach: [ThreatActorId: Set<String>]

    public init(model: ThreatModel) {
        var everywhere = Set(model.facedActorIds.map(ThreatActorId.init))
        var reach: [ThreatActorId: Set<String>] = [:]

        for user in model.components {
            guard let facts = user.user, let actorId = facts.threatActorId else { continue }
            let actor = ThreatActorId(actorId)
            guard facts.uses.isEmpty == false else {
                everywhere.insert(actor)
                continue
            }
            reach[actor, default: []].formUnion(Self.sources(of: user, facts: facts, in: model))
        }
        for actor in everywhere { reach[actor] = nil }
        self.reach = reach
    }

    /// The actors among these that perform on the source.
    public func performing(_ actors: [ThreatActor], on sourceId: String) -> [ThreatActor] {
        actors.filter { actor in
            guard let sources = reach[actor.id] else { return true }
            return sources.contains(sourceId)
        }
    }

    private static func sources(of user: Component, facts: UserFacts, in model: ThreatModel) -> Set<String> {
        var sources: Set<String> = []
        func leaving(_ id: String) {
            for connection in model.connections where connection.source.value == id {
                sources.insert("connection:\(connection.id.value)")
                sources.insert("component:\(connection.target.value)")
            }
        }
        for use in facts.uses {
            sources.insert("component:\(use.clientId)")
            leaving(use.clientId)
            for reached in use.reaches {
                sources.insert("component:\(reached)")
                sources.insert(
                    "connection:"
                        + UserUse.reachId(
                            user: user.id.value,
                            client: use.clientId,
                            reached: reached
                        )
                )
            }
        }
        for reached in facts.reaches { sources.insert("component:\(reached)") }
        leaving(user.id.value)
        return sources
    }
}
