/// One thing the assessment recommends, and where it came from.
public struct ReportRecommendation: Equatable, Sendable {
    public let text: String
    public let note: String?
    public let threatName: String
    public let sourceName: String
    public let riskScore: Int
    /// Where the recommendation comes from. Empty when a person names none.
    public let sources: [String]

    public init(
        text: String,
        note: String?,
        threatName: String,
        sourceName: String,
        riskScore: Int,
        sources: [String] = []
    ) {
        self.text = text
        self.note = note
        self.threatName = threatName
        self.sourceName = sourceName
        self.riskScore = riskScore
        self.sources = sources
    }
}

/// What one protector's reductions rest on, in report form.
public struct ReportProtectionDependency: Equatable, Sendable {
    public let protectorName: String
    public let protects: [String]
    public let unanswered: [ReportUnansweredThreat]

    public init(
        protectorName: String,
        protects: [String] = [],
        unanswered: [ReportUnansweredThreat] = []
    ) {
        self.protectorName = protectorName
        self.protects = protects
        self.unanswered = unanswered
    }
}

/// A threat on a protector that nobody has answered, in report form.
public struct ReportUnansweredThreat: Equatable, Sendable {
    public let name: String
    public let riskScore: Int
    public let riskLevel: String

    public init(name: String, riskScore: Int, riskLevel: String) {
        self.name = name
        self.riskScore = riskScore
        self.riskLevel = riskLevel
    }
}

/// One step on an attack path, from a component the path passes through to
/// the worst threat raised there.
public struct ReportAttackPathHop: Equatable, Sendable {
    public let componentName: String
    /// The kind of flow that carried the path onto this hop, or nil for the
    /// first hop.
    public let flowKindLabel: String?
    public let worstThreatName: String?
    public let riskScore: Int
    /// The controls and mitigations that lowered the score at this hop.
    public let reducedBy: [String]

    public init(
        componentName: String,
        flowKindLabel: String?,
        worstThreatName: String?,
        riskScore: Int,
        reducedBy: [String] = []
    ) {
        self.componentName = componentName
        self.flowKindLabel = flowKindLabel
        self.worstThreatName = worstThreatName
        self.riskScore = riskScore
        self.reducedBy = reducedBy
    }
}

/// A path from an entry point to the sensitive data it can reach.
public struct ReportAttackPath: Equatable, Sendable {
    public let startName: String
    public let endName: String
    public let hops: [ReportAttackPathHop]
    public let worstScore: Int

    public init(
        startName: String,
        endName: String,
        hops: [ReportAttackPathHop] = [],
        worstScore: Int
    ) {
        self.startName = startName
        self.endName = endName
        self.hops = hops
        self.worstScore = worstScore
    }
}

/// The threats raised inside one zone, rolled up.
public struct ReportZoneRollup: Equatable, Sendable {
    public let zoneName: String
    public let componentCount: Int
    public let byLevel: [ReportCount]
    public let worstScore: Int
    /// The worst score among this zone's threats when every assumed edge
    /// holds. Equal to `worstScore` when no assumed edge touches the zone.
    public let worstScoreIfAssumptionsHold: Int

    public init(
        zoneName: String,
        componentCount: Int,
        byLevel: [ReportCount] = [],
        worstScore: Int,
        worstScoreIfAssumptionsHold: Int? = nil
    ) {
        self.zoneName = zoneName
        self.componentCount = componentCount
        self.byLevel = byLevel
        self.worstScore = worstScore
        self.worstScoreIfAssumptionsHold = worstScoreIfAssumptionsHold ?? worstScore
    }
}

/// The rollup tables a report shows above the threat list.
public struct ReportRollupTables: Equatable, Sendable {
    public let byZone: [ReportZoneRollup]
    /// The threats with the highest residual score, worst first.
    public let topResidual: [ReportThreat]
    public let bySourceKind: [ReportCount]

    public init(
        byZone: [ReportZoneRollup] = [],
        topResidual: [ReportThreat] = [],
        bySourceKind: [ReportCount] = []
    ) {
        self.byZone = byZone
        self.topResidual = topResidual
        self.bySourceKind = bySourceKind
    }
}

public extension ReportRollupTables {
    static let empty = ReportRollupTables(byZone: [], topResidual: [], bySourceKind: [])
}
