/// One thing the assessment recommends, and where it came from.
/// One rule a project states for itself, and whether this system keeps it.
public struct ReportPolicyRule: Equatable, Sendable {
    public let name: String
    public let asks: String
    /// What breached the rule, one line per breach, in the words the check
    /// prints. Empty when this system keeps the rule.
    public let breaches: [String]

    public init(name: String, asks: String, breaches: [String]) {
        self.name = name
        self.asks = asks
        self.breaches = breaches
    }

    public var holds: Bool { breaches.isEmpty }
}

/// One risk the organisation decided to carry.
///
/// A row is written for every accepted control, governed or not, so a reader
/// sees the ungoverned ones as a row of dashes rather than not at all.
public struct ReportAcceptedRisk: Equatable, Sendable {
    public let threatName: String
    public let sourceName: String
    public let riskScore: Int
    public let control: String
    public let owner: String
    /// A date written `YYYY-MM-DD`, or nil when the file states none.
    public let acceptedOn: String?
    public let reviewBy: String?
    public let rationale: String
    /// True when the review date has passed.
    public let isOverdue: Bool
    /// Where the acceptance comes from. Empty when a person names none.
    public let sources: [String]

    public init(
        threatName: String,
        sourceName: String,
        riskScore: Int,
        control: String,
        owner: String = "",
        acceptedOn: String? = nil,
        reviewBy: String? = nil,
        rationale: String = "",
        isOverdue: Bool = false,
        sources: [String] = []
    ) {
        self.threatName = threatName
        self.sourceName = sourceName
        self.riskScore = riskScore
        self.control = control
        self.owner = owner
        self.acceptedOn = acceptedOn
        self.reviewBy = reviewBy
        self.rationale = rationale
        self.isOverdue = isOverdue
        self.sources = sources
    }
}

public struct ReportRecommendation: Equatable, Sendable {
    public let text: String
    public let note: String?
    public let threatName: String
    public let sourceName: String
    public let riskScore: Int
    /// Where the recommendation comes from. Empty when a person names none.
    public let sources: [String]
    /// The threat this answers, and what raised it. A name is not unique, so
    /// anything matching a recommendation to a threat matches on these.
    public let threatId: String
    public let sourceId: String
    /// Who does it, how big it is, by when and where it stands, or nil when
    /// the governance file states nothing about it.
    public let governance: String?
    /// What the governance file states proves this work is done, or nil when
    /// it states none.
    public let planAcceptance: String?
    /// What a person wrote about the planned work, beside its acceptance, or
    /// nil when the governance file states none.
    public let planNote: String?
    /// Where the planned work comes from. Empty when the governance file
    /// names none.
    public let planSources: [String]

    public init(
        text: String,
        note: String?,
        threatName: String,
        sourceName: String,
        riskScore: Int,
        sources: [String] = [],
        threatId: String = "",
        sourceId: String = "",
        governance: String? = nil,
        planAcceptance: String? = nil,
        planNote: String? = nil,
        planSources: [String] = []
    ) {
        self.text = text
        self.note = note
        self.threatName = threatName
        self.sourceName = sourceName
        self.riskScore = riskScore
        self.sources = sources
        self.threatId = threatId
        self.sourceId = sourceId
        self.governance = governance
        self.planAcceptance = planAcceptance
        self.planNote = planNote
        self.planSources = planSources
    }

    /// Identifies the threat a recommendation answers, the way a report keys
    /// a threat to its source.
    public static func key(threatId: String, sourceId: String) -> String {
        "\(threatId)@\(sourceId)"
    }

    public var threatKey: String {
        Self.key(threatId: threatId, sourceId: sourceId)
    }
}

/// What one protector's reductions rest on, in report form.
public struct ReportProtectionDependency: Equatable, Sendable {
    public let protectorName: String
    public let protects: [String]
    public let unanswered: [ReportUnansweredThreat]
    /// The component the reductions come from. A picture of this dependency
    /// needs the id, and `protectorName` is a name a reader chose.
    public let protectorId: String
    /// How many threats this protector answers on each component it protects,
    /// by component id. A picture labels the line to a component with it.
    public let answeredByElementId: [String: Int]
    /// What this protector answers, by component, named for a reader. Empty
    /// when the caller built no names, and then the section writes the
    /// `protects` lines instead.
    public let protectsElements: [ReportProtectedElement]

    public init(
        protectorName: String,
        protects: [String] = [],
        unanswered: [ReportUnansweredThreat] = [],
        protectorId: String = "",
        answeredByElementId: [String: Int] = [:],
        protectsElements: [ReportProtectedElement] = []
    ) {
        self.protectorName = protectorName
        self.protects = protects
        self.unanswered = unanswered
        self.protectorId = protectorId
        self.answeredByElementId = answeredByElementId
        self.protectsElements = protectsElements
    }
}

/// A component a control protects, and what the control answers on it.
public struct ReportProtectedElement: Equatable, Sendable {
    public let elementId: String
    public let elementName: String
    public let zoneName: String?
    public let threats: [ReportAnsweredThreat]

    public init(
        elementId: String,
        elementName: String,
        zoneName: String? = nil,
        threats: [ReportAnsweredThreat] = []
    ) {
        self.elementId = elementId
        self.elementName = elementName
        self.zoneName = zoneName
        self.threats = threats
    }
}

/// A threat a control answers, with the risk that is left after it.
public struct ReportAnsweredThreat: Equatable, Sendable {
    public let threatId: String
    public let name: String
    public let riskScore: Int
    public let riskLevel: String

    public init(threatId: String, name: String, riskScore: Int, riskLevel: String) {
        self.threatId = threatId
        self.name = name
        self.riskScore = riskScore
        self.riskLevel = riskLevel
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
    /// The likelihood tier of the hop that set `worstScore`. Empty when no
    /// threat set it.
    public let likelihoodLabel: String

    public init(
        startName: String,
        endName: String,
        hops: [ReportAttackPathHop] = [],
        worstScore: Int,
        likelihoodLabel: String = ""
    ) {
        self.startName = startName
        self.endName = endName
        self.hops = hops
        self.worstScore = worstScore
        self.likelihoodLabel = likelihoodLabel
    }
}

/// A path the narrative did not carry, in one line.
public struct ReportAttackPathSummary: Equatable, Sendable {
    public let startName: String
    public let endName: String
    public let worstScore: Int

    public init(startName: String, endName: String, worstScore: Int) {
        self.startName = startName
        self.endName = endName
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
