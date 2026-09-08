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

    public let id: TechnologyId
    public var name: String
    public var provider: ProviderId
    public var category: CategoryId
    public var description: String
    public var threatIds: [ThreatId]
    public var enforcesEncryption: Bool

    public init(
        id: TechnologyId,
        name: String,
        provider: ProviderId = CustomTechnology.provider,
        category: CategoryId,
        description: String,
        threatIds: [ThreatId],
        enforcesEncryption: Bool = false
    ) {
        self.id = id
        self.name = name
        self.provider = provider
        self.category = category
        self.description = description
        self.threatIds = threatIds
        self.enforcesEncryption = enforcesEncryption
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
            enforcesEncryption: enforcesEncryption
        )
    }
}
