/// What a report says, whoever reads it.
///
/// One tree, four outputs: Markdown, threatcl HCL and the PDF renderer all read
/// this and none of them reads a gateway. It carries the assessment, not the
/// positions: a reader of a report does not place components.
public struct Report: Equatable, Sendable {
    public let modelName: String
    /// What the report says about the document itself: who owns it, who wrote
    /// it, which version, and when it was last read again.
    public let documentControl: DocumentControl
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
    /// The attack paths the trace found and the narrative did not carry.
    public let attackPathsNotListed: [ReportAttackPathSummary]
    /// The hops every listed path starts with, stated once above them. Empty
    /// when the listed paths share no first hop.
    public let attackPathPrefix: [ReportAttackPathHop]
    /// How many paths the trace found that not even the appendix names.
    public let attackPathsBeyondAppendix: Int
    public let rollups: ReportRollupTables
    /// What the model takes on trust. Empty for a model that assumes nothing.
    public let assumptions: [ReportAssumption]
    /// What a person does with this system, in file order.
    public let useCases: [ReportUseCase]
    /// The humans who use the system, in model order. The Scope section
    /// lists them; the component table does not.
    public let users: [ReportUser]
    /// One row per named asset: what holds it, what carries it and the worst
    /// open threat on any of them.
    public let dataInventory: [ReportAssetRow]
    /// One row per party outside this team the system depends on.
    public let thirdParties: [ReportThirdParty]
    /// One row per CVE per component, in model order. Empty when no
    /// component states a CVE.
    public let knownVulnerabilities: [ReportKnownVulnerability]
    /// The thresholds the priorities were ranked by: the policy's, or the
    /// defaults.
    public let vulnerabilityThresholds: VulnerabilityPriority.Thresholds
    /// The pictures the team keeps beside the diagram, in model order.
    public let diagrams: [ReportDiagram]
    /// What this model does not cover, in file order.
    public let exclusions: [ReportExclusion]
    /// The `mitigates` edges marked assumed rather than adopted, in report
    /// form. An edge names no assumption, so this travels beside
    /// `assumptions` rather than nested inside one.
    public let assumedMitigations: [ReportAssumedMitigation]
    /// The threats a reader must act on, and how many more qualified.
    public let findings: ReportFindingsCut
    /// The risk level the project accepts, for the reader.
    public let toleranceLabel: String
    /// The one page a reader reads first.
    public let executiveSummary: ReportExecutiveSummary
    /// What the scores mean, and how they were reached.
    public let methodology: ReportMethodology
    /// What a team could do, worst first by what it removes. Empty when the
    /// model declares no action.
    public let actions: [ReportAction]
    /// The adversaries this assessment is written against, in the order the
    /// model faces them. Empty for a model that faces nobody.
    public let threatActors: [ReportThreatActor]
    /// What the model scored at each sampled commit, newest first. Empty when
    /// nobody asked for the history.
    public let history: [RiskHistoryRow]
    /// True when the bound left commits out.
    public let historyTruncated: Bool
    /// What changed between the previous sampled commit and the working tree,
    /// or nil when there is nothing to compare.
    public let change: RiskChange?
    /// The rules this project states for itself, and whether this system
    /// keeps them. Empty for a project with no policy file.
    public let policy: [ReportPolicyRule]
    /// The risks the organisation decided to carry, worst first. Empty for a
    /// model that accepts nothing.
    public let acceptedRisks: [ReportAcceptedRisk]
    /// The trees a person wrote, bound and scored. Empty for a model that
    /// states no tree.
    public let attackTrees: [BoundAttackTree]
    /// How many routes the attack path walk found, listed and not listed.
    public let attackPathCount: Int

    public init(
        modelName: String,
        documentControl: DocumentControl? = nil,
        catalogueTag: String?,
        summary: ReportSummary,
        components: [ReportComponent],
        connections: [ReportConnection],
        zones: [ReportZone],
        threats: [ReportThreat],
        recommendations: [ReportRecommendation] = [],
        protectionDependencies: [ReportProtectionDependency] = [],
        attackPaths: [ReportAttackPath] = [],
        attackPathsNotListed: [ReportAttackPathSummary] = [],
        attackPathPrefix: [ReportAttackPathHop] = [],
        attackPathsBeyondAppendix: Int = 0,
        rollups: ReportRollupTables = .empty,
        assumptions: [ReportAssumption] = [],
        useCases: [ReportUseCase] = [],
        users: [ReportUser] = [],
        dataInventory: [ReportAssetRow] = [],
        thirdParties: [ReportThirdParty] = [],
        knownVulnerabilities: [ReportKnownVulnerability] = [],
        vulnerabilityThresholds: VulnerabilityPriority.Thresholds = .default,
        diagrams: [ReportDiagram] = [],
        exclusions: [ReportExclusion] = [],
        assumedMitigations: [ReportAssumedMitigation] = [],
        findings: ReportFindingsCut = ReportFindingsCut(),
        toleranceLabel: String = RiskLevel.low.label,
        executiveSummary: ReportExecutiveSummary = ReportExecutiveSummary(),
        methodology: ReportMethodology = ReportMethodology(),
        actions: [ReportAction] = [],
        threatActors: [ReportThreatActor] = [],
        history: [RiskHistoryRow] = [],
        historyTruncated: Bool = false,
        change: RiskChange? = nil,
        policy: [ReportPolicyRule] = [],
        acceptedRisks: [ReportAcceptedRisk] = [],
        attackTrees: [BoundAttackTree] = [],
        attackPathCount: Int = 0
    ) {
        self.modelName = modelName
        self.documentControl = documentControl ?? DocumentControl(systemName: modelName)
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
        self.attackPathPrefix = attackPathPrefix
        self.attackPathsBeyondAppendix = attackPathsBeyondAppendix
        self.rollups = rollups
        self.assumptions = assumptions
        self.useCases = useCases
        self.users = users
        self.dataInventory = dataInventory
        self.thirdParties = thirdParties
        self.knownVulnerabilities = knownVulnerabilities
        self.vulnerabilityThresholds = vulnerabilityThresholds
        self.diagrams = diagrams
        self.exclusions = exclusions
        self.assumedMitigations = assumedMitigations
        self.findings = findings
        self.toleranceLabel = toleranceLabel
        self.executiveSummary = executiveSummary
        self.methodology = methodology
        self.actions = actions
        self.threatActors = threatActors
        self.history = history
        self.historyTruncated = historyTruncated
        self.change = change
        self.policy = policy
        self.acceptedRisks = acceptedRisks
        self.attackTrees = attackTrees
        self.attackPathCount = attackPathCount
    }
}

/// One CVE one component states, ranked, in report form.
public struct ReportKnownVulnerability: Equatable, Sendable {
    public let cveId: String
    public let componentName: String
    /// The version the component states. Empty when it states none.
    public let version: String
    public let cvss: Double?
    public let epss: Double?
    public let isKnownExploited: Bool
    /// `1+` to `4`, or nil when the lock file does not hold the CVE.
    public let priorityLabel: String?

    public init(
        cveId: String,
        componentName: String,
        version: String,
        cvss: Double?,
        epss: Double?,
        isKnownExploited: Bool,
        priorityLabel: String?
    ) {
        self.cveId = cveId
        self.componentName = componentName
        self.version = version
        self.cvss = cvss
        self.epss = epss
        self.isKnownExploited = isKnownExploited
        self.priorityLabel = priorityLabel
    }

    /// True when the lock file holds the CVE.
    public var isSynchronised: Bool { priorityLabel != nil }
}

/// One adversary the assessment is written against.
public struct ReportThreatActor: Equatable, Sendable {
    public let name: String
    public let capabilityLabel: String
    /// What the actor is after. Empty when the file states none.
    public let intent: String
    /// How many of this model's threats this actor performs.
    public let threatsPerformed: Int

    public init(name: String, capabilityLabel: String, intent: String, threatsPerformed: Int) {
        self.name = name
        self.capabilityLabel = capabilityLabel
        self.intent = intent
        self.threatsPerformed = threatsPerformed
    }
}

/// The threats a findings section shows, and how many more qualified.
///
/// A model whose tolerance is `low` raises nearly every threat above it, so
/// the cut is bounded. The overflow count is stated, because a silent
/// truncation reads as full coverage.
public struct ReportFindingsCut: Equatable, Sendable {
    /// The threats above the project's tolerance, worst first.
    public let above: [ReportThreat]
    /// How many more qualified and did not fit.
    public let notShown: Int

    public init(above: [ReportThreat] = [], notShown: Int = 0) {
        self.above = above
        self.notShown = notShown
    }

    /// The most a findings section shows.
    public static let maximum = 25

    /// Every threat ranking above the tolerance, worst first, capped.
    public static func build(from threats: [ReportThreat], tolerance: RiskLevel) -> ReportFindingsCut {
        let qualifying = threats.filter { threat in
            guard let level = RiskLevel(rawValue: threat.riskLevel) else { return false }
            return level.rank > tolerance.rank
        }
        let sorted = qualifying.sorted(by: ReportThreat.worstFirst)
        return ReportFindingsCut(
            above: Array(sorted.prefix(maximum)),
            notShown: max(0, sorted.count - maximum)
        )
    }
}

/// What a reader who reads one page reads.
///
/// The sentences here are the one place the report writes as a consultancy
/// deliverable rather than in the tool's plain register.
public struct ReportExecutiveSummary: Equatable, Sendable {
    /// One sentence on the posture, against the project's own tolerance.
    public let verdict: String
    public let toleranceLabel: String
    /// The three worst threats by residual score.
    public let topRisks: [ReportThreat]
    /// The three recommendations answering the worst threats.
    public let topActions: [ReportRecommendation]
    /// The actions that remove the most risk, worst first. Empty when the
    /// model declares none, and then `topActions` is what the summary writes.
    public let topLeverageActions: [ReportAction]
    /// How many threats hold no answered control and no compensating control.
    public let unansweredCount: Int
    public let totalThreats: Int
    /// The threats in `topRisks` that no recommendation names, keyed the way
    /// `ReportRecommendation.key` keys them.
    ///
    /// A recommendation is ranked by the score of the threat it is written
    /// against, so the worst risk in a model can carry none and never be
    /// named among the actions. The summary states that rather than leaving
    /// the reader to notice it.
    public let topRisksWithNoAction: Set<String>
    /// How many accepted risks are past the date their owner set to read them
    /// again. A risk nobody has read again is a decision nobody has checked.
    public let acceptedRisksOverdue: Int
    /// How many implemented controls state no evidence, and how many are
    /// implemented at all. A reader who reads one page should see both.
    public let unevidencedControls: Int
    public let implementedControls: Int
    /// True when nobody has read the model again inside the interval
    /// `DocumentControl.reviewIntervalDays` states.
    public let isReviewOverdue: Bool
    /// When the model was last read again, for the sentence that says so.
    public let reviewedOn: String?
    /// How many unanswered threats harm each of confidentiality, integrity
    /// and availability. One threat that harms two counts in both.
    public let openByImpact: [ReportCount]
    /// How many things this model states it does not cover. A reader of one
    /// page reads what the model left out as well as what it found.
    public let exclusionCount: Int
    /// How many third parties this system cannot run without. A reader of one
    /// page reads what stops the system as well as what threatens it.
    public let hardDependencyCount: Int

    public init(
        verdict: String = "",
        toleranceLabel: String = RiskLevel.low.label,
        topRisks: [ReportThreat] = [],
        topActions: [ReportRecommendation] = [],
        unansweredCount: Int = 0,
        totalThreats: Int = 0,
        topLeverageActions: [ReportAction] = [],
        topRisksWithNoAction: Set<String> = [],
        acceptedRisksOverdue: Int = 0,
        unevidencedControls: Int = 0,
        implementedControls: Int = 0,
        isReviewOverdue: Bool = false,
        reviewedOn: String? = nil,
        openByImpact: [ReportCount] = [],
        exclusionCount: Int = 0,
        hardDependencyCount: Int = 0
    ) {
        self.verdict = verdict
        self.toleranceLabel = toleranceLabel
        self.topRisks = topRisks
        self.topActions = topActions
        self.topLeverageActions = topLeverageActions
        self.unansweredCount = unansweredCount
        self.totalThreats = totalThreats
        self.topRisksWithNoAction = topRisksWithNoAction
        self.acceptedRisksOverdue = acceptedRisksOverdue
        self.unevidencedControls = unevidencedControls
        self.implementedControls = implementedControls
        self.isReviewOverdue = isReviewOverdue
        self.reviewedOn = reviewedOn
        self.openByImpact = openByImpact
        self.exclusionCount = exclusionCount
        self.hardDependencyCount = hardDependencyCount
    }

    /// How many of each the summary names.
    public static let topCount = 3

    /// `findings` is the one cut `BuildThreatModelReport` computed for the
    /// whole report. Reusing it here, rather than computing a second cut,
    /// keeps this verdict and the Findings section unable to disagree.
    public static func build(
        threats: [ReportThreat],
        recommendations: [ReportRecommendation],
        tolerance: RiskLevel,
        findings: ReportFindingsCut,
        actions: [ReportAction] = [],
        acceptedRisks: [ReportAcceptedRisk] = [],
        documentControl: DocumentControl? = nil,
        today: GovernanceDate? = nil,
        exclusionCount: Int = 0,
        hardDependencyCount: Int = 0
    ) -> ReportExecutiveSummary {
        // Counted once per distinct control key the way `SummariseRisk`
        // counts, so a control shared across links is one control.
        var seen: Set<String> = []
        var implemented: [ReportControl] = []
        for threat in threats {
            for control in threat.controls
            where control.isImplemented && seen.insert(control.description).inserted {
                implemented.append(control)
            }
        }

        let above = findings.above.count + findings.notShown
        let word = tolerance.label.lowercased()

        let verdict: String
        switch above {
        case 0:
            verdict = "No residual exposure exceeds the project's \(word) risk tolerance."
        case 1:
            verdict = "The assessment identifies a single residual exposure above"
                + " the project's \(word) risk tolerance."
        default:
            verdict = "The assessment identifies \(above) residual exposures above"
                + " the project's \(word) risk tolerance."
        }

        let sorted = threats.sorted(by: ReportThreat.worstFirst)
        let topRisks = Array(sorted.prefix(topCount))
        let answered = Set(recommendations.map(\.threatKey))

        let overdue = documentControl.flatMap { control in
            today.map(control.isOverdue(on:))
        } ?? false

        return ReportExecutiveSummary(
            verdict: verdict,
            toleranceLabel: tolerance.label,
            topRisks: topRisks,
            // Worst first, and ties broken by text, the way
            // `RecommendationsReport.build` breaks them. Sorting by score
            // alone reorders two recommendations that answer threats of one
            // score, so two runs of one model name a different three.
            topActions: Array(
                recommendations
                    .sorted { left, right in
                        if left.riskScore != right.riskScore { return left.riskScore > right.riskScore }
                        return left.text < right.text
                    }
                    .prefix(topCount)
            ),
            unansweredCount: threats.filter { isUnanswered($0) }.count,
            totalThreats: threats.count,
            topLeverageActions: Array(actions.prefix(topCount)),
            topRisksWithNoAction: Set(
                topRisks
                    .map { ReportRecommendation.key(threatId: $0.threatId, sourceId: $0.sourceId) }
                    .filter { answered.contains($0) == false }
            ),
            acceptedRisksOverdue: acceptedRisks.filter(\.isOverdue).count,
            unevidencedControls: implemented.filter { $0.evidence == "no evidence" }.count,
            implementedControls: implemented.count,
            isReviewOverdue: overdue,
            reviewedOn: documentControl?.reviewed,
            openByImpact: openByImpact(threats.filter { isUnanswered($0) }),
            exclusionCount: exclusionCount,
            hardDependencyCount: hardDependencyCount
        )
    }

    /// How many of these threats harm each impact, in the order
    /// `ThreatImpact.allCases` states. An impact no threat harms is left out.
    private static func openByImpact(_ threats: [ReportThreat]) -> [ReportCount] {
        ThreatImpact.allCases.compactMap { impact in
            let count = threats.filter { $0.impactLabels.contains(impact.label) }.count
            return count == 0 ? nil : ReportCount(label: impact.label, count: count)
        }
    }

    /// A threat nobody has answered: no control carries an answer, and no
    /// compensating control stands.
    private static func isUnanswered(_ threat: ReportThreat) -> Bool {
        threat.isOpen
    }
}

/// One risk level and the scores that reach it.
public struct ReportLevelThreshold: Equatable, Sendable {
    public let label: String
    public let lowest: Int
    public let highest: Int

    public init(label: String, lowest: Int, highest: Int) {
        self.label = label
        self.lowest = lowest
        self.highest = highest
    }
}

/// What the numbers in this report mean, taken from the code that made them.
public struct ReportMethodology: Equatable, Sendable {
    public let levelThresholds: [ReportLevelThreshold]
    /// The most the implemented controls take off, as a percentage.
    public let controlCapPercent: Int
    /// Each likelihood tier and its factor. The `count` is a percentage, not
    /// a tally.
    public let likelihoodTiers: [ReportCount]
    /// Each zone that reduces risk, and by how much. The `count` is a
    /// percentage, not a tally.
    public let zoneReductions: [ReportCount]
    public let toleranceLabel: String

    public init(
        levelThresholds: [ReportLevelThreshold] = [],
        controlCapPercent: Int = 0,
        likelihoodTiers: [ReportCount] = [],
        zoneReductions: [ReportCount] = [],
        toleranceLabel: String = RiskLevel.low.label
    ) {
        self.levelThresholds = levelThresholds
        self.controlCapPercent = controlCapPercent
        self.likelihoodTiers = likelihoodTiers
        self.zoneReductions = zoneReductions
        self.toleranceLabel = toleranceLabel
    }

    /// The highest score the base arithmetic can reach: four severity ranks
    /// multiplied by four sensitivity ranks.
    /// The top of the scale, which `RiskScore` owns. The report states it in
    /// prose, and one number in two files is one number that can drift.
    public static let highestScore = RiskScore.maximum

    /// Reads the thresholds out of `RiskScore.level` rather than repeating
    /// them. A second copy would disagree with the scoring the day a
    /// threshold moves.
    public static func build(zones: [ReportZone], tolerance: RiskLevel) -> ReportMethodology {
        var lowestByLevel: [RiskLevel: Int] = [:]
        var highestByLevel: [RiskLevel: Int] = [:]
        for score in 1...highestScore {
            let level = RiskScore(value: score).level
            if lowestByLevel[level] == nil { lowestByLevel[level] = score }
            highestByLevel[level] = score
        }

        return ReportMethodology(
            levelThresholds: RiskLevel.allCases
                // A no-op today, because the cases already declare in rank
                // order. Keep it: it is what stops the table reordering the
                // day a case is declared out of rank order.
                .sorted { $0.rank < $1.rank }
                .compactMap { level in
                    guard let lowest = lowestByLevel[level],
                          let highest = highestByLevel[level] else { return nil }
                    return ReportLevelThreshold(label: level.label, lowest: lowest, highest: highest)
                },
            controlCapPercent: Int((ControlCoverage.maxReduction * 100).rounded()),
            likelihoodTiers: Likelihood.allTiers.map {
                ReportCount(label: $0.label, count: Int(($0.factor * 100).rounded()))
            },
            zoneReductions: zones.compactMap { zone in
                zone.riskReductionPercent.map { ReportCount(label: zone.name, count: $0) }
            },
            toleranceLabel: tolerance.label
        )
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
    /// The shape the diagram draws it as: `actor`, `process` or `store`. An
    /// export that states a kind of element reads it.
    public let shapeId: String
    /// Whether the component runs in Production today or is a planned change:
    /// Live or Proposed.
    public let statusLabel: String

    public init(
        id: String,
        name: String,
        technologyId: String,
        categoryId: String,
        sensitivityLabel: String,
        zoneName: String?,
        assetNames: [String] = [],
        privilegeLabel: String = PrivilegeLevel.default.label,
        shapeId: String = DiagramShape.process.rawValue,
        statusLabel: String = ComponentStatus.default.label
    ) {
        self.statusLabel = statusLabel
        self.id = id
        self.name = name
        self.technologyId = technologyId
        self.categoryId = categoryId
        self.sensitivityLabel = sensitivityLabel
        self.zoneName = zoneName
        self.assetNames = assetNames
        self.privilegeLabel = privilegeLabel
        self.shapeId = shapeId
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
    /// What this threat harms, as labels a person reads: `Confidentiality`,
    /// `Integrity`, `Availability`.
    public let impactLabels: [String]
    /// The named assets on the element this threat is raised against.
    public let assetsAtRisk: [String]
    public let mitreTechniqueIds: [String]
    /// What each technique is called and its first tactic, by technique id,
    /// from the ATT&CK data on this machine. A machine that has not
    /// synchronised holds none, and the report prints bare ids.
    public let mitreTechniqueNames: [String: String]
    /// The faced threat actors that perform this threat, by name. Empty when
    /// the system faces nobody who performs it.
    public let performedByLabels: [String]
    /// What set the likelihood: `from the catalogue`, `set by <actor>`, or the
    /// label of the finding that answered it.
    public let likelihoodReason: String
    /// The score before the attack tree stage, or nil when no open tree names
    /// this threat as its goal.
    public let scoreBeforeTree: Int?
    /// The tree that raised this threat, or nil when none did.
    public let raisedByTree: String?
    /// The library that changed this threat, or nil when the catalogue's own
    /// words stand. A reader can then tell an overridden value from the
    /// catalogue's.
    public let overriddenBy: String?
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
    /// What a reader sees for the likelihood tier the score used.
    public let likelihoodLabel: String
    /// Why the likelihood is what it is, or nil when the library's prior
    /// stands.
    public let likelihoodRationale: String?
    /// Where the likelihood finding comes from. Empty when the library's
    /// prior stands.
    public let likelihoodSources: [String]
    /// The score before the likelihood stage. Equal to `riskScore` when the
    /// likelihood left it unchanged.
    public let scoreBeforeLikelihood: Int
    /// The score when every assumed mitigation is in place. Equal to
    /// `riskScore` when no assumed edge answers this threat.
    public let scoreIfAssumptionsHold: Int
    /// What an assessor decided this threat's severity is, and why, or nil
    /// when no decision names it.
    public let severityDecision: ReportSeverityDecision?

    public init(
        threatId: String,
        name: String,
        description: String,
        severityLabel: String,
        riskScore: Int,
        riskLevel: String,
        strideLabels: [String],
        impactLabels: [String] = [],
        assetsAtRisk: [String] = [],
        mitreTechniqueIds: [String],
        mitreTechniqueNames: [String: String] = [:],
        performedByLabels: [String] = [],
        likelihoodReason: String = LikelihoodSource.catalogue(.commodity).reason,
        scoreBeforeTree: Int? = nil,
        raisedByTree: String? = nil,
        overriddenBy: String? = nil,
        sourceName: String,
        sourceKind: String,
        sourceId: String = "",
        controls: [ReportControl],
        pathwayMitigationLabels: [String],
        compensating: [ReportCompensatingControl] = [],
        scoreBeforeCompensation: Int? = nil,
        inherentScore: Int? = nil,
        mitigatedByComponentLabels: [String] = [],
        likelihoodLabel: String = Likelihood.commodity.label,
        likelihoodRationale: String? = nil,
        likelihoodSources: [String] = [],
        scoreBeforeLikelihood: Int? = nil,
        scoreIfAssumptionsHold: Int? = nil,
        severityDecision: ReportSeverityDecision? = nil
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
        self.impactLabels = impactLabels
        self.assetsAtRisk = assetsAtRisk
        self.mitreTechniqueIds = mitreTechniqueIds
        self.mitreTechniqueNames = mitreTechniqueNames
        self.performedByLabels = performedByLabels
        self.likelihoodReason = likelihoodReason
        self.scoreBeforeTree = scoreBeforeTree
        self.raisedByTree = raisedByTree
        self.overriddenBy = overriddenBy
        self.sourceName = sourceName
        self.sourceKind = sourceKind
        self.controls = controls
        self.pathwayMitigationLabels = pathwayMitigationLabels
        self.likelihoodLabel = likelihoodLabel
        self.likelihoodRationale = likelihoodRationale
        self.likelihoodSources = likelihoodSources
        self.scoreBeforeLikelihood = scoreBeforeLikelihood ?? riskScore
        self.scoreIfAssumptionsHold = scoreIfAssumptionsHold ?? riskScore
        self.severityDecision = severityDecision
    }

    /// A threat nobody has answered: no control carries an answer, and no
    /// compensating control stands. The executive summary and the data
    /// inventory both read this, so neither can disagree with the other.
    public var isOpen: Bool {
        guard compensating.isEmpty else { return false }
        return controls.contains { $0.statusLabel != ControlStatus.notImplemented.label } == false
    }

    /// Worst risk score first, a tie breaking on the name, so every section
    /// that ranks threats by residual risk orders them the same way.
    public static func worstFirst(_ left: ReportThreat, _ right: ReportThreat) -> Bool {
        if left.riskScore != right.riskScore { return left.riskScore > right.riskScore }
        return left.name < right.name
    }
}

/// The severity an assessor chose for one threat, and why.
public struct ReportSeverityDecision: Equatable, Sendable {
    public let fromLabel: String
    public let toLabel: String
    public let rationale: String
    public let sources: [String]

    public init(fromLabel: String, toLabel: String, rationale: String, sources: [String] = []) {
        self.fromLabel = fromLabel
        self.toLabel = toLabel
        self.rationale = rationale
        self.sources = sources
    }
}

/// Something the model takes on trust, in report form.
/// One picture the team keeps beside the diagram, in report form.
public struct ReportDiagram: Equatable, Sendable {
    public let label: String
    public let kind: String
    public let text: String

    public init(label: String, kind: String, text: String) {
        self.label = label
        self.kind = kind
        self.text = text
    }
}

/// One party outside this team the system depends on, in report form.
public struct ReportThirdParty: Equatable, Sendable {
    public let id: String
    public let name: String
    public let description: String
    public let kindLabel: String
    public let payingCustomer: Bool
    public let uptimeLabel: String
    public let uptimeNotes: String
    public let owner: String?
    public let link: String?
    /// The components this party provides, by name, in model order.
    public let provides: [String]
    /// The named assets those components hold, in model order, each named
    /// once.
    public let assetNames: [String]

    public init(
        id: String,
        name: String,
        description: String = "",
        kindLabel: String,
        payingCustomer: Bool = false,
        uptimeLabel: String,
        uptimeNotes: String = "",
        owner: String? = nil,
        link: String? = nil,
        provides: [String] = [],
        assetNames: [String] = []
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.kindLabel = kindLabel
        self.payingCustomer = payingCustomer
        self.uptimeLabel = uptimeLabel
        self.uptimeNotes = uptimeNotes
        self.owner = owner
        self.link = link
        self.provides = provides
        self.assetNames = assetNames
    }
}

/// One named asset, and what a reader must know about it.
public struct ReportAssetRow: Equatable, Sendable {
    public let id: String
    public let name: String
    public let classificationLabel: String
    public let owner: String?
    public let description: String
    /// The components that hold this asset, by name, in model order.
    public let heldBy: [String]
    /// The flows that carry this asset, by name, in model order.
    public let carriedBy: [String]
    /// The worst open threat on anything that holds or carries this asset,
    /// and its score. Nil when nothing open touches it.
    public let worstOpenThreat: String?
    public let worstOpenScore: Int?

    public init(
        id: String,
        name: String,
        classificationLabel: String,
        owner: String? = nil,
        description: String = "",
        heldBy: [String] = [],
        carriedBy: [String] = [],
        worstOpenThreat: String? = nil,
        worstOpenScore: Int? = nil
    ) {
        self.id = id
        self.name = name
        self.classificationLabel = classificationLabel
        self.owner = owner
        self.description = description
        self.heldBy = heldBy
        self.carriedBy = carriedBy
        self.worstOpenThreat = worstOpenThreat
        self.worstOpenScore = worstOpenScore
    }
}

/// One thing a person does with the system, in report form.
public struct ReportUseCase: Equatable, Sendable {
    public let label: String
    public let text: String

    public init(label: String, text: String) {
        self.label = label
        self.text = text
    }
}

/// One human who uses the system, in report form.
public struct ReportUser: Equatable, Sendable {
    public let name: String
    /// What the person does with the system. Empty when the model states none.
    public let role: String
    /// The privilege the user holds: User, Administrator, Root, System or
    /// Kernel.
    public let accessLabel: String
    /// The names of the components the user reaches, in model order.
    public let reaches: [String]
    /// The name of the threat actor this user is, or nil.
    public let threatActorName: String?

    public init(
        name: String,
        role: String = "",
        accessLabel: String,
        reaches: [String] = [],
        threatActorName: String? = nil
    ) {
        self.name = name
        self.role = role
        self.accessLabel = accessLabel
        self.reaches = reaches
        self.threatActorName = threatActorName
    }
}

/// One thing this model does not cover, and why, in report form.
public struct ReportExclusion: Equatable, Sendable {
    public let label: String
    public let text: String
    public let rationale: String

    public init(label: String, text: String, rationale: String) {
        self.label = label
        self.text = text
        self.rationale = rationale
    }
}

public struct ReportAssumption: Equatable, Sendable {
    public let label: String
    public let text: String
    public let owner: String?

    public init(label: String, text: String, owner: String? = nil) {
        self.label = label
        self.text = text
        self.owner = owner
    }
}

/// One `mitigates` edge marked assumed rather than adopted, in report form.
public struct ReportAssumedMitigation: Equatable, Sendable {
    public let protectorName: String
    public let protectedName: String
    /// The threats this edge would answer, by id.
    public let threatIds: [String]
    public let reducesRiskBy: Int

    public init(protectorName: String, protectedName: String, threatIds: [String], reducesRiskBy: Int) {
        self.protectorName = protectorName
        self.protectedName = protectedName
        self.threatIds = threatIds
        self.reducesRiskBy = reducesRiskBy
    }
}

public struct ReportControl: Equatable, Sendable {
    public let description: String
    public let isImplemented: Bool
    /// What the user said about it: Implemented, Not implemented, Not
    /// applicable or Accepted.
    public let statusLabel: String
    /// What proves the control is in place: the tier, the reference and the
    /// date, or `no evidence`. Nil for a control nobody has implemented,
    /// which has nothing to prove.
    public let evidence: String?

    public init(
        description: String,
        isImplemented: Bool,
        statusLabel: String? = nil,
        evidence: String? = nil
    ) {
        self.description = description
        self.isImplemented = isImplemented
        self.statusLabel = statusLabel ?? (isImplemented ? "Implemented" : "Not implemented")
        self.evidence = evidence
    }
}

/// Something a team does that answers a threat the catalogue's controls do not.
public struct ReportCompensatingControl: Equatable, Sendable {
    public let label: String
    public let reducesRiskBy: Int
    public let rationale: String
    /// Where the rationale comes from. Empty when a person names none.
    public let sources: [String]
    /// What proves it is in place, or nil when the file states nothing.
    public let evidence: String?

    public init(
        label: String,
        reducesRiskBy: Int,
        rationale: String,
        sources: [String] = [],
        evidence: String? = nil
    ) {
        self.label = label
        self.reducesRiskBy = reducesRiskBy
        self.rationale = rationale
        self.sources = sources
        self.evidence = evidence
    }
}

/// One action a team could take, and what it would remove.
public struct ReportAction: Equatable, Sendable {
    public let label: String
    public let text: String
    public let note: String?
    public let blockedBy: String?
    public let sources: [String]
    /// Who does it, how big it is, by when and where it stands, or nil when
    /// the governance file states nothing about it.
    public let governance: String?
    public let removes: Int
    public let totalResidual: Int
    public let threatsMoved: Int
    public let worstBefore: Int
    public let worstAfter: Int

    public init(
        label: String,
        text: String,
        note: String? = nil,
        blockedBy: String? = nil,
        sources: [String] = [],
        governance: String? = nil,
        removes: Int = 0,
        totalResidual: Int = 0,
        threatsMoved: Int = 0,
        worstBefore: Int = 0,
        worstAfter: Int = 0
    ) {
        self.label = label
        self.text = text
        self.note = note
        self.blockedBy = blockedBy
        self.sources = sources
        self.governance = governance
        self.removes = removes
        self.totalResidual = totalResidual
        self.threatsMoved = threatsMoved
        self.worstBefore = worstBefore
        self.worstAfter = worstAfter
    }
}
