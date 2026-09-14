/// Turns the actors a system faces into one likelihood per threat.
///
/// A pure function of its inputs: it reads no gateway and holds no state.
public enum ActorLikelihood {
    /// The faced actors that perform this threat.
    ///
    /// An actor performs a threat when any one of three tests passes:
    ///
    /// 1. `performs` holds the threat's id;
    /// 2. `techniques` holds a technique whose parent matches the parent of
    ///    one of the threat's own techniques, so `T1550.001` matches `T1550`;
    /// 3. `performsCatalogueTier` equals the threat's catalogue likelihood.
    public static func performers(of threat: Threat, among actors: [ThreatActor]) -> [ThreatActor] {
        let threatParents = Set(threat.mitreTechniques.map { parent(of: $0.id) })

        return actors.filter { actor in
            if actor.performs.contains(threat.id) { return true }
            if actor.techniques.contains(where: { threatParents.contains(parent(of: $0)) }) {
                return true
            }
            if let tier = actor.performsCatalogueTier, tier == threat.likelihood { return true }
            return false
        }
    }

    /// The likelihood this threat is scored with, and what set it.
    ///
    /// WARNING: a threat no faced actor performs keeps the catalogue's own
    /// likelihood. A short or wrong actor list never lowers a score by leaving
    /// a threat out.
    ///
    /// The likelihood is the highest factor among the performers, because a
    /// threat two actors perform happens as often as the busier of the two.
    public static func likelihood(of threat: Threat, faced actors: [ThreatActor]) -> LikelihoodSource {
        let performing = performers(of: threat, among: actors)
        guard let strongest = performing.max(by: { $0.capability.factor < $1.capability.factor })
        else {
            return .catalogue(threat.likelihood)
        }
        return .actor(strongest.capability, actorId: strongest.id, actorName: strongest.name)
    }

    /// The text before the first full stop. `T1550.001` has the parent
    /// `T1550`, and `T1550` is its own parent.
    public static func parent(of techniqueId: String) -> String {
        guard let stop = techniqueId.firstIndex(of: ".") else { return techniqueId }
        return String(techniqueId[techniqueId.startIndex..<stop])
    }
}
