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
        zoneContext: String? = nil
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
    }
}
