/// An adversary a system faces.
///
/// A threat actor is not a box on the diagram. `ExternalActor`, in
/// `Resources/Actors/actors.json`, is the box; it states no capability and
/// performs no threat. A threat actor states how many attackers of its kind
/// there are and which threats they perform, and a system names the ones it
/// faces.
public struct ThreatActor: Equatable, Sendable {
    public let id: ThreatActorId
    public let name: String
    public let description: String
    public let aliases: [String]
    /// The tier, which carries the factor the score uses. A capability says
    /// how many attackers of this kind there are, not how skilled one is.
    public let capability: Likelihood
    public let intent: String
    public let performs: [ThreatId]
    /// MITRE technique ids, matched at parent level.
    public let techniques: [String]
    /// When set, this actor performs every threat the catalogue marks at this
    /// tier.
    public let performsCatalogueTier: Likelihood?

    public init(
        id: ThreatActorId,
        name: String,
        description: String = "",
        aliases: [String] = [],
        capability: Likelihood = .targeted,
        intent: String = "",
        performs: [ThreatId] = [],
        techniques: [String] = [],
        performsCatalogueTier: Likelihood? = nil
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.aliases = aliases
        self.capability = capability
        self.intent = intent
        self.performs = performs
        self.techniques = techniques
        self.performsCatalogueTier = performsCatalogueTier
    }
}
