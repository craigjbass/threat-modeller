public struct Control: Equatable, Sendable {
    public let id: String
    public let description: String

    public init(id: String, description: String) {
        self.id = id
        self.description = description
    }
}

public struct MitreTechnique: Equatable, Sendable {
    public let id: String
    public let name: String
    public let tactic: String

    public init(id: String, name: String, tactic: String) {
        self.id = id
        self.name = name
        self.tactic = tactic
    }
}

public struct Threat: Equatable, Sendable {
    public let id: ThreatId
    public let name: String
    public let description: String
    public let severity: ThreatSeverity
    public let stride: [StrideId]
    public let mitreTechniques: [MitreTechnique]
    public let controls: [Control]
    public let isConnectionThreat: Bool
    public let isZoneThreat: Bool
    public let isPathwayThreat: Bool
    public let zoneContext: String?
    /// The flow kinds this threat applies to. Empty means every kind, which is
    /// what the resolver treats a connection threat as today.
    public let appliesToFlowKinds: [FlowKind]
    /// The zone boundary this threat applies to, or nil for every boundary.
    public let boundary: ZoneBoundary?
    /// The privilege levels this threat applies to. Empty means every level.
    public let appliesToPrivilegeLevels: [PrivilegeLevel]
    /// How often an attack of this kind happens. A threat that states none is
    /// `commodity`, so an old catalogue keeps its numbers.
    public let likelihood: Likelihood

    public init(
        id: ThreatId,
        name: String,
        description: String,
        severity: ThreatSeverity,
        stride: [StrideId] = [],
        mitreTechniques: [MitreTechnique] = [],
        controls: [Control] = [],
        isConnectionThreat: Bool = false,
        isZoneThreat: Bool = false,
        isPathwayThreat: Bool = false,
        zoneContext: String? = nil,
        appliesToFlowKinds: [FlowKind] = [],
        boundary: ZoneBoundary? = nil,
        appliesToPrivilegeLevels: [PrivilegeLevel] = [],
        likelihood: Likelihood = .commodity
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.severity = severity
        self.stride = stride
        self.mitreTechniques = mitreTechniques
        self.controls = controls
        self.isConnectionThreat = isConnectionThreat
        self.isZoneThreat = isZoneThreat
        self.isPathwayThreat = isPathwayThreat
        self.zoneContext = zoneContext
        self.appliesToFlowKinds = appliesToFlowKinds
        self.boundary = boundary
        self.appliesToPrivilegeLevels = appliesToPrivilegeLevels
        self.likelihood = likelihood
    }
}
