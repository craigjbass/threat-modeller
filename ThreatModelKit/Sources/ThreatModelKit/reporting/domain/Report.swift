/// What a report says, whoever reads it.
///
/// One tree, four outputs: Markdown, threatcl HCL and the PDF renderer all read
/// this and none of them reads a gateway. It carries the assessment, not the
/// positions: a reader of a report does not place components.
public struct Report: Equatable, Sendable {
    public let modelName: String
    /// The catalogue this assessment was made against, or nil for a model that
    /// has never been saved.
    public let catalogueTag: String?
    public let summary: ReportSummary
    public let components: [ReportComponent]
    public let connections: [ReportConnection]
    public let zones: [ReportZone]
    /// Worst first, then by source, so two reports of one model read the same.
    public let threats: [ReportThreat]
    public let recommendations: [ReportRecommendation]
    public let protectionDependencies: [ReportProtectionDependency]
    public let attackPaths: [ReportAttackPath]
    /// How many attack paths the trace found but did not list.
    public let attackPathsNotListed: Int
    public let rollups: ReportRollupTables

    public init(
        modelName: String,
        catalogueTag: String?,
        summary: ReportSummary,
        components: [ReportComponent],
        connections: [ReportConnection],
        zones: [ReportZone],
        threats: [ReportThreat],
        recommendations: [ReportRecommendation] = [],
        protectionDependencies: [ReportProtectionDependency] = [],
        attackPaths: [ReportAttackPath] = [],
        attackPathsNotListed: Int = 0,
        rollups: ReportRollupTables = .empty
    ) {
        self.modelName = modelName
        self.catalogueTag = catalogueTag
        self.summary = summary
        self.components = components
        self.connections = connections
        self.zones = zones
        self.threats = threats
        self.recommendations = recommendations
        self.protectionDependencies = protectionDependencies
        self.attackPaths = attackPaths
        self.attackPathsNotListed = attackPathsNotListed
        self.rollups = rollups
    }
}

public struct ReportSummary: Equatable, Sendable {
    public let totalThreats: Int
    public let byLevel: [ReportCount]
    public let byStride: [ReportCount]
    public let controlsOffered: Int
    public let controlsRecorded: Int
    /// How many controls carry each status, worst answered first.
    public let byControlStatus: [ReportCount]

    public init(
        totalThreats: Int,
        byLevel: [ReportCount],
        byStride: [ReportCount],
        controlsOffered: Int,
        controlsRecorded: Int,
        byControlStatus: [ReportCount] = []
    ) {
        self.byControlStatus = byControlStatus
        self.totalThreats = totalThreats
        self.byLevel = byLevel
        self.byStride = byStride
        self.controlsOffered = controlsOffered
        self.controlsRecorded = controlsRecorded
    }
}

public struct ReportCount: Equatable, Sendable {
    public let label: String
    public let count: Int

    public init(label: String, count: Int) {
        self.label = label
        self.count = count
    }
}

public struct ReportComponent: Equatable, Sendable {
    public let id: String
    public let name: String
    public let technologyId: String
    public let categoryId: String
    public let sensitivityLabel: String
    /// The zone holding it, or nil when it sits outside every zone.
    public let zoneName: String?
    public let assetNames: [String]
    /// The privilege level it runs at: User, Administrator, Root, System or
    /// Kernel.
    public let privilegeLabel: String

    public init(
        id: String,
        name: String,
        technologyId: String,
        categoryId: String,
        sensitivityLabel: String,
        zoneName: String?,
        assetNames: [String] = [],
        privilegeLabel: String = PrivilegeLevel.default.label
    ) {
        self.id = id
        self.name = name
        self.technologyId = technologyId
        self.categoryId = categoryId
        self.sensitivityLabel = sensitivityLabel
        self.zoneName = zoneName
        self.assetNames = assetNames
        self.privilegeLabel = privilegeLabel
    }
}

public struct ReportConnection: Equatable, Sendable {
    public let sourceName: String
    public let targetName: String
    /// The flow's kind: Network, Local IPC, File, System Call or Human.
    public let kindLabel: String
    public let description: String?

    public init(
        sourceName: String,
        targetName: String,
        kindLabel: String = FlowKind.default.label,
        description: String? = nil
    ) {
        self.sourceName = sourceName
        self.targetName = targetName
        self.kindLabel = kindLabel
        self.description = description
    }
}

public struct ReportZone: Equatable, Sendable {
    public let name: String
    public let networkZoneLabel: String
    public let networkTypeLabel: String
    public let componentNames: [String]
    /// The ids of the components this zone holds, same order as
    /// `componentNames`. A rollup matches a threat to a zone by id, because
    /// a display name is not unique.
    public let componentIds: [String]
    public let riskReductionPercent: Int?
    /// What the zone is a boundary of: Network Boundary or Privilege Boundary.
    public let boundaryLabel: String

    public init(
        name: String,
        networkZoneLabel: String,
        networkTypeLabel: String,
        componentNames: [String],
        componentIds: [String] = [],
        riskReductionPercent: Int?,
        boundaryLabel: String = ZoneBoundary.default.label
    ) {
        self.name = name
        self.networkZoneLabel = networkZoneLabel
        self.networkTypeLabel = networkTypeLabel
        self.componentNames = componentNames
        self.componentIds = componentIds
        self.riskReductionPercent = riskReductionPercent
        self.boundaryLabel = boundaryLabel
    }
}

public struct ReportThreat: Equatable, Sendable {
    public let threatId: String
    public let name: String
    public let description: String
    public let severityLabel: String
    public let riskScore: Int
    public let riskLevel: String
    public let strideLabels: [String]
    public let mitreTechniqueIds: [String]
    public let sourceName: String
    /// "Component", "Connection" or "Zone", so a reader can group by what
    /// raised the threat.
    public let sourceKind: String
    /// The identifier `ThreatResolver` mints for the source: `component:<id>`,
    /// `connection:<id>` or `zone:<id>`. Task 14 keys the recommendations on
    /// it.
    public let sourceId: String
    public let controls: [ReportControl]
    public let pathwayMitigationLabels: [String]
    /// What compensates this threat, and what it bought.
    public let compensating: [ReportCompensatingControl]
    /// The score before the compensating control. Equal to `riskScore` when
    /// none applied.
    public let scoreBeforeCompensation: Int
    /// The score before the implemented controls lowered it.
    public let inherentScore: Int
    /// The components whose `mitigates` edges lowered this threat, by label.
    /// Empty when none did.
    public let mitigatedByComponentLabels: [String]

    public init(
        threatId: String,
        name: String,
        description: String,
        severityLabel: String,
        riskScore: Int,
        riskLevel: String,
        strideLabels: [String],
        mitreTechniqueIds: [String],
        sourceName: String,
        sourceKind: String,
        sourceId: String = "",
        controls: [ReportControl],
        pathwayMitigationLabels: [String],
        compensating: [ReportCompensatingControl] = [],
        scoreBeforeCompensation: Int? = nil,
        inherentScore: Int? = nil,
        mitigatedByComponentLabels: [String] = []
    ) {
        self.sourceId = sourceId
        self.compensating = compensating
        self.scoreBeforeCompensation = scoreBeforeCompensation ?? riskScore
        self.inherentScore = inherentScore ?? riskScore
        self.mitigatedByComponentLabels = mitigatedByComponentLabels
        self.threatId = threatId
        self.name = name
        self.description = description
        self.severityLabel = severityLabel
        self.riskScore = riskScore
        self.riskLevel = riskLevel
        self.strideLabels = strideLabels
        self.mitreTechniqueIds = mitreTechniqueIds
        self.sourceName = sourceName
        self.sourceKind = sourceKind
        self.controls = controls
        self.pathwayMitigationLabels = pathwayMitigationLabels
    }
}

public struct ReportControl: Equatable, Sendable {
    public let description: String
    public let isImplemented: Bool
    /// What the user said about it: Implemented, Not implemented, Not
    /// applicable or Accepted.
    public let statusLabel: String

    public init(description: String, isImplemented: Bool, statusLabel: String? = nil) {
        self.description = description
        self.isImplemented = isImplemented
        self.statusLabel = statusLabel ?? (isImplemented ? "Implemented" : "Not implemented")
    }
}

/// Something a team does that answers a threat the catalogue's controls do not.
public struct ReportCompensatingControl: Equatable, Sendable {
    public let label: String
    public let reducesRiskBy: Int
    public let rationale: String

    public init(label: String, reducesRiskBy: Int, rationale: String) {
        self.label = label
        self.reducesRiskBy = reducesRiskBy
        self.rationale = rationale
    }
}
