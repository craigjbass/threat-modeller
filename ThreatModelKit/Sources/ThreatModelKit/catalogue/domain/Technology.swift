public struct Technology: Equatable, Sendable {
    public let id: TechnologyId
    public let name: String
    public let provider: ProviderId
    public let category: CategoryId
    public let description: String
    public let threatIds: [ThreatId]
    public let enforcesEncryption: Bool
    public let internalOnly: Bool
    /// Technology-specific wording for a threat, keyed by threat id. Sparse.
    public let threatContext: [ThreatId: String]
    /// Technology-specific controls that supersede a threat's generic controls. Sparse.
    public let threatMitigations: [ThreatId: [String]]

    public init(
        id: TechnologyId,
        name: String,
        provider: ProviderId,
        category: CategoryId,
        description: String,
        threatIds: [ThreatId] = [],
        enforcesEncryption: Bool = false,
        internalOnly: Bool = false,
        threatContext: [ThreatId: String] = [:],
        threatMitigations: [ThreatId: [String]] = [:]
    ) {
        self.id = id
        self.name = name
        self.provider = provider
        self.category = category
        self.description = description
        self.threatIds = threatIds
        self.enforcesEncryption = enforcesEncryption
        self.internalOnly = internalOnly
        self.threatContext = threatContext
        self.threatMitigations = threatMitigations
    }
}
