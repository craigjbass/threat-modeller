/// A technology a model defines for itself.
///
/// It belongs to one diagram and travels in its file: an in-house service has
/// no entry in anybody's library. It reuses the catalogue's threats — a user can
/// say their service carries credential theft, but cannot invent a threat the
/// rest of the application knows nothing about.
public struct CustomTechnology: Equatable, Sendable {
    /// The provider every custom technology belongs to, so the palette can
    /// group them together.
    public static let provider = ProviderId("custom")

    /// What the palette calls that group.
    public static let providerDisplayName = "This Model"

    public let id: TechnologyId
    public var name: String
    public var provider: ProviderId
    public var category: CategoryId
    public var description: String
    public var threatIds: [ThreatId]
    public var enforcesEncryption: Bool
    /// The controls this technology brings, in the team's own words.
    ///
    /// They answer every threat the technology carries, the way a catalogue
    /// technology's own mitigations do, so they appear on every card the
    /// technology raises and in the report.
    public var controls: [String]

    public init(
        id: TechnologyId,
        name: String,
        provider: ProviderId = CustomTechnology.provider,
        category: CategoryId,
        description: String,
        threatIds: [ThreatId],
        enforcesEncryption: Bool = false,
        controls: [String] = []
    ) {
        self.id = id
        self.name = name
        self.provider = provider
        self.category = category
        self.description = description
        self.threatIds = threatIds
        self.enforcesEncryption = enforcesEncryption
        self.controls = controls
    }

    /// The same thing, said the way the rest of the application says it.
    public var asTechnology: Technology {
        Technology(
            id: id,
            name: name,
            provider: provider,
            category: category,
            description: description,
            threatIds: threatIds,
            enforcesEncryption: enforcesEncryption,
            // A control this technology brings answers every threat it
            // carries, so each threat is offered every one of them.
            threatMitigations: Dictionary(
                uniqueKeysWithValues: threatIds.map { ($0, controls) }
            )
        )
    }
}
