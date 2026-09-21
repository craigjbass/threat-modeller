public protocol AssessThreatModelUseCase {
    func execute(_ request: AssessThreatModelRequest) -> AssessThreatModelResponse
}

public struct AssessThreatModelRequest: Equatable, Sendable {
    public init() {}
}

/// A severity the user can override a threat to. In taxonomy order, weakest
/// first, which is the order the ranks run in.
public struct AssessedSeverity: Equatable, Sendable {
    public let id: String
    public let label: String

    public init(id: String, label: String) {
        self.id = id
        self.label = label
    }
}

public struct AssessThreatModelResponse: Equatable, Sendable {
    public let threats: [AssessedThreat]
    /// Every severity the override menu offers, in taxonomy order.
    public let severities: [AssessedSeverity]
    /// What each `mitigates` edge rests on. Empty when the model draws none.
    public let protectionDependencies: [ProtectionDependency]
    /// What a reader must know before they trust a reduction.
    public let warnings: [String]
    /// The trees a person wrote, bound to this model and scored.
    public let attackTrees: [BoundAttackTree]

    public init(
        threats: [AssessedThreat],
        severities: [AssessedSeverity] = [],
        protectionDependencies: [ProtectionDependency] = [],
        warnings: [String] = [],
        attackTrees: [BoundAttackTree] = []
    ) {
        self.threats = threats
        self.severities = severities
        self.protectionDependencies = protectionDependencies
        self.warnings = warnings
        self.attackTrees = attackTrees
    }
}

/// What an assessor decided a threat's severity is, and why, in report-ready
/// form: both labels already resolved, so a delivery mechanism looks up
/// nothing else.
/// One compensating control on one threat, as a delivery mechanism reads it.
public struct AssessedCompensatingControl: Hashable, Sendable {
    public let label: String
    /// 0 to 100.
    public let reducesRiskBy: Int
    public let rationale: String
    public let sources: [String]
    /// What proves the control is in place, or nil when nothing does.
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

public struct AssessedSeverityDecision: Hashable, Sendable {
    /// The severity the threat started from.
    public let fromLabel: String
    /// The severity the assessor chose.
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

/// What a person says should be done about this threat, as one
/// `recommendation` block of the controls file states it.
public struct AssessedRecommendation: Hashable, Sendable {
    public let text: String
    public let note: String?
    /// Where the recommendation comes from. Empty when a person names none.
    public let sources: [String]

    public init(text: String, note: String? = nil, sources: [String] = []) {
        self.text = text
        self.note = note
        self.sources = sources
    }
}

public struct AssessedMitreTechnique: Hashable, Sendable {
    public let id: String
    public let name: String
    public let tactic: String

    public init(id: String, name: String, tactic: String) {
        self.id = id
        self.name = name
        self.tactic = tactic
    }
}

public struct AssessedControl: Hashable, Sendable {
    public let description: String
    /// True when the control came from the technology rather than the threat.
    public let isTechnologySpecific: Bool
    /// What the user said about it: implemented, not_implemented,
    /// not_applicable or accepted.
    public let statusId: String
    public let statusLabel: String
    /// The key `RecordControlImplemented` takes. Minted by the core.
    public let key: String
    public let isImplemented: Bool
    /// Who carries this accepted risk, or nil when the control is not
    /// accepted or the governance file names nobody.
    public let acceptedBy: String?
    /// When they read it again, written `YYYY-MM-DD`, or nil.
    public let reviewBy: String?
    /// True when that date has passed.
    public let isReviewOverdue: Bool
    /// The evidence tier the file states for this control, or nil.
    public let evidenceId: String?
    /// Where the proof is, and when somebody last checked.
    public let evidenceReference: String?
    public let verifiedOn: String?
    /// What a person wrote about this control, beside its evidence, or nil.
    public let note: String?
    /// The open trees this control closes a step on, by name, in file order.
    /// Empty for a control that closes no route. The order rule of
    /// `RouteClosing` puts a control with names here before one without.
    public let closesTreeNames: [String]
    /// The `mitigates` edge a person says implements this control, or nil
    /// when nobody has mapped one. Written `<protector>-><protected>`.
    public let mitigatedByEdgeId: String?

    public init(
        description: String,
        isTechnologySpecific: Bool,
        key: String,
        isImplemented: Bool,
        statusId: String? = nil,
        statusLabel: String? = nil,
        acceptedBy: String? = nil,
        reviewBy: String? = nil,
        isReviewOverdue: Bool = false,
        evidenceId: String? = nil,
        evidenceReference: String? = nil,
        verifiedOn: String? = nil,
        note: String? = nil,
        closesTreeNames: [String] = [],
        mitigatedByEdgeId: String? = nil
    ) {
        self.description = description
        self.isTechnologySpecific = isTechnologySpecific
        self.key = key
        self.isImplemented = isImplemented
        self.acceptedBy = acceptedBy
        self.reviewBy = reviewBy
        self.isReviewOverdue = isReviewOverdue
        self.note = note
        self.evidenceId = evidenceId
        self.evidenceReference = evidenceReference
        self.verifiedOn = verifiedOn
        self.closesTreeNames = closesTreeNames
        self.mitigatedByEdgeId = mitigatedByEdgeId
        let status = statusId.flatMap(ControlStatus.init(rawValue:))
            ?? (isImplemented ? ControlStatus.implemented : .notImplemented)
        self.statusId = status.rawValue
        self.statusLabel = statusLabel ?? status.label
    }
}

/// One `mitigates` edge a person may map a control to.
public struct AssessedMitigatesEdge: Hashable, Sendable {
    /// `<protector>-><protected>`, which is what a `.controls` file writes.
    public let id: String
    /// What the protecting component is called on the diagram.
    public let protectorName: String
    public let reducesRiskBy: Int
    /// `adopted` or `assumed`.
    public let statusId: String

    public init(id: String, protectorName: String, reducesRiskBy: Int, statusId: String) {
        self.id = id
        self.protectorName = protectorName
        self.reducesRiskBy = reducesRiskBy
        self.statusId = statusId
    }

    /// `Guard (80%)`, or `Guard (80%, assumed)` for an edge the team plans.
    public var label: String {
        statusId == MitigationStatus.assumed.rawValue
            ? "\(protectorName) (\(reducesRiskBy)%, assumed)"
            : "\(protectorName) (\(reducesRiskBy)%)"
    }
}

/// One CVE the component a threat is raised on carries, as the threat card
/// reads it.
public struct AssessedVulnerability: Hashable, Sendable {
    public let cveId: String
    public let cvss: Double?
    public let epss: Double?
    public let isKnownExploited: Bool
    /// `1+` to `4`, or nil when the lock file does not hold the CVE.
    public let priorityLabel: String?

    public init(
        cveId: String,
        cvss: Double? = nil,
        epss: Double? = nil,
        isKnownExploited: Bool = false,
        priorityLabel: String? = nil
    ) {
        self.cveId = cveId
        self.cvss = cvss
        self.epss = epss
        self.isKnownExploited = isKnownExploited
        self.priorityLabel = priorityLabel
    }

    /// `CVE-2023-44487 (KEV, 1+)`, `CVE-2024-7347 (4)`, or
    /// `CVE-2025-0001 (not synchronised)`.
    public var described: String {
        guard let priorityLabel else { return "\(cveId) (not synchronised)" }
        return isKnownExploited ? "\(cveId) (KEV, \(priorityLabel))" : "\(cveId) (\(priorityLabel))"
    }

    /// The CVEs of one component, each ranked against the lock file.
    public static func of(
        cves: [String],
        held: [String: KnownVulnerability],
        thresholds: VulnerabilityPriority.Thresholds
    ) -> [AssessedVulnerability] {
        cves.map { cveId in
            guard let record = held[cveId] else { return AssessedVulnerability(cveId: cveId) }
            return AssessedVulnerability(
                cveId: cveId,
                cvss: record.cvss,
                epss: record.epss,
                isKnownExploited: record.isKnownExploited,
                priorityLabel: VulnerabilityPriority.priority(of: record, thresholds: thresholds).label
            )
        }
    }
}

/// What raised a threat.
public enum AssessedThreatSource: Hashable, Sendable {
    case component(id: String, name: String, providerId: String)
    case connection(id: String, sourceName: String, targetName: String)
    case zone(id: String, name: String)

    /// The label the user reads on the threat row.
    public var displayName: String {
        switch self {
        case .component(_, let name, _):
            name
        case .connection(_, let sourceName, let targetName):
            "\(sourceName) \u{2192} \(targetName)"
        case .zone(_, let name):
            name
        }
    }

    /// Identifies the source across kinds. Two sources of different kinds never
    /// share one. Used to order rows and to raise a duplicate pair once.
    public var id: String {
        switch self {
        case .component(let id, _, _):
            "component:\(id)"
        case .connection(let id, _, _):
            "connection:\(id)"
        case .zone(let id, _):
            "zone:\(id)"
        }
    }
}

/// One tree a threat is on, and what part the threat plays in it.
///
/// The design
/// `docs/superpowers/specs/2026-09-17-trees-in-the-threat-list-design.md`
/// states what the card prints from this.
public struct AssessedTreeRole: Hashable, Sendable {
    public let treeId: String
    public let treeName: String
    /// True when the threat is the tree's goal, false when it is a step.
    public let isGoal: Bool
    /// True while an attacker can walk the whole route.
    public let isTreeOpen: Bool
    /// True while a step or a sufficient control of the tree does not bind.
    /// A stale tree moves no score.
    public let isTreeStale: Bool
    /// The per cent the file states the tree adds to its goal.
    public let raisesRiskBy: Int
    /// The goal's score before the tree moved it.
    public let scoreBefore: Int
    /// The goal's score after the tree moved it.
    public let score: Int
    /// What this threat is doing as a step: `open`, `closed` or `unbound`.
    /// Nil on the goal.
    public let stepState: String?
    /// The control or the compensating control that closed this step, or nil.
    public let stepClosedBy: String?
    /// Why an open step is still open. Nil on a closed step and on the goal.
    public let stepIsOpenBecause: String?

    public init(
        treeId: String,
        treeName: String,
        isGoal: Bool,
        isTreeOpen: Bool,
        isTreeStale: Bool,
        raisesRiskBy: Int,
        scoreBefore: Int,
        score: Int,
        stepState: String? = nil,
        stepClosedBy: String? = nil,
        stepIsOpenBecause: String? = nil
    ) {
        self.treeId = treeId
        self.treeName = treeName
        self.isGoal = isGoal
        self.isTreeOpen = isTreeOpen
        self.isTreeStale = isTreeStale
        self.raisesRiskBy = raisesRiskBy
        self.scoreBefore = scoreBefore
        self.score = score
        self.stepState = stepState
        self.stepClosedBy = stepClosedBy
        self.stepIsOpenBecause = stepIsOpenBecause
    }
}

public struct AssessedTreeClosure: Hashable, Sendable {
    public let treeName: String
    public let control: String

    public init(treeName: String, control: String) {
        self.treeName = treeName
        self.control = control
    }
}

public struct AssessedThreat: Hashable, Sendable {
    public let threatId: String
    public let name: String
    public let description: String
    public let severityId: String
    public let severityLabel: String
    public let stride: [String]
    /// What this threat harms: `confidentiality`, `integrity`, `availability`.
    public let impacts: [String]
    public let mitreTechniques: [AssessedMitreTechnique]
    public let controls: [AssessedControl]
    public let source: AssessedThreatSource
    public let sensitivityId: String
    public let riskScore: Int
    public let riskLevel: String
    public let context: String?
    /// True when the threat is one TLS mitigates and an endpoint technology
    /// enforces encryption. Display only. It never changes `riskScore`.
    public let isTlsMitigated: Bool
    /// The key `OverrideThreatSeverity` takes. Minted by the core.
    public let overrideKey: String
    /// The key that names this threat on this source. `SetLikelihoodFinding`
    /// and `SetCompensatingControl` both take it. Minted by the core, so no
    /// caller builds the string itself.
    public let threatKey: String
    /// The severity id the user overrode this threat to, or nil.
    public let overriddenSeverityId: String?
    /// The pathway mitigations that answered this threat, by label. Empty when
    /// none did.
    public let pathwayMitigationLabels: [String]
    /// What each pathway mitigation in `pathwayMitigationLabels` does to a
    /// threat it answers, by label: `Remove the threat` or `Lower the
    /// score`.
    public let pathwayMitigationModes: [String: String]
    /// The score before any pathway mitigation. Equal to `riskScore` when none
    /// applied, so a card can show what the mitigation bought.
    public let scoreBeforePathwayMitigation: Int
    /// What compensates this threat, from the controls file, by label.
    public let compensatingLabels: [String]
    /// What compensates this threat, whole, in the order the score read it.
    public let compensating: [AssessedCompensatingControl]
    /// The evidence tier the compensating control states, or nil.
    public let compensatingEvidenceId: String?
    /// Where the compensating control's proof is, or nil.
    public let compensatingEvidenceReference: String?
    /// When somebody last checked the compensating control, or nil.
    public let compensatingVerifiedOn: String?
    /// Where the compensating control comes from, from the controls file.
    /// Empty when the file names none.
    public let compensatingSources: [String]
    /// The score before the compensating control. Equal to `riskScore` when
    /// none applied.
    public let scoreBeforeCompensation: Int
    /// The score before the implemented controls lowered it. Equal to
    /// `riskScore` when nothing was implemented.
    public let inherentScore: Int
    /// The components whose `mitigates` edges lowered this threat, by label.
    /// Empty when none did.
    public let mitigatedByComponentLabels: [String]
    /// The percentage each component in `mitigatedByComponentLabels` takes
    /// off, same order and same count.
    public let mitigatedByComponentReductions: [Int]
    /// Every `mitigates` edge that answers this threat on this element,
    /// adopted and assumed alike, so a person picks the one that implements a
    /// control. Empty for a threat no edge answers.
    public let mitigatesEdgeChoices: [AssessedMitigatesEdge]
    /// The likelihood tier the score used, and what a reader sees.
    public let likelihoodId: String
    public let likelihoodLabel: String
    /// The score before the likelihood stage. Equal to `riskScore` when the
    /// likelihood is `commodity`.
    public let scoreBeforeLikelihood: Int
    /// Why the likelihood is what it is, from the controls file, or nil when
    /// the library's prior stands.
    public let likelihoodRationale: String?
    /// The label a person writes on the likelihood block, beside its
    /// rationale, or nil when the library's prior stands.
    public let likelihoodFindingLabel: String?
    /// Where the likelihood finding comes from. Empty when the library's
    /// prior stands.
    public let likelihoodSources: [String]
    /// What set this likelihood: `from the catalogue`, `set by <actor>`, or
    /// the label of the finding that answered it.
    public let likelihoodReason: String
    /// The faced threat actors that perform this threat, by name. Empty when
    /// the system faces nobody who does.
    public let performedByLabels: [String]
    /// The CVEs the component this threat is raised on carries, in file
    /// order. Empty for a threat on a zone or a flow.
    public let knownVulnerabilities: [AssessedVulnerability]
    /// The score when every assumed mitigation is in place. Equal to
    /// `riskScore` when no assumed edge answers this threat.
    public let scoreIfAssumptionsHold: Int
    /// The components whose assumed `mitigates` edges lowered the target
    /// posture, by label. Empty when none did.
    public let assumedByComponentLabels: [String]
    /// What an assessor decided this threat's severity is, and why, or nil
    /// when no decision names this threat on this source.
    public let severityDecision: AssessedSeverityDecision?
    /// What the controls file says should be done about this threat. Empty
    /// when it holds no `recommendation` block for it.
    public let recommendations: [AssessedRecommendation]
    /// Every tree that names this threat as its goal and is closed as a
    /// whole by a sufficient control, in file order. Empty for every other
    /// threat. The threat card states it.
    public let closedByTrees: [AssessedTreeClosure]
    /// Every tree that names this threat as its goal or as a step, in file
    /// order. Empty for a threat no tree names.
    public let trees: [AssessedTreeRole]
    /// Why the library's matchers raised this threat here, or nil when the
    /// threat carries no matcher that narrows where it applies.
    public let matchReason: String?

    public init(
        threatId: String,
        name: String,
        description: String,
        severityId: String,
        severityLabel: String,
        stride: [String],
        impacts: [String] = [],
        mitreTechniques: [AssessedMitreTechnique],
        controls: [AssessedControl],
        source: AssessedThreatSource,
        sensitivityId: String,
        riskScore: Int,
        riskLevel: String,
        context: String?,
        isTlsMitigated: Bool,
        overrideKey: String,
        threatKey: String = "",
        overriddenSeverityId: String?,
        pathwayMitigationLabels: [String] = [],
        pathwayMitigationModes: [String: String] = [:],
        scoreBeforePathwayMitigation: Int = 0,
        compensatingLabels: [String] = [],
        compensating: [AssessedCompensatingControl] = [],
        compensatingEvidenceId: String? = nil,
        compensatingEvidenceReference: String? = nil,
        compensatingVerifiedOn: String? = nil,
        compensatingSources: [String] = [],
        scoreBeforeCompensation: Int? = nil,
        inherentScore: Int? = nil,
        mitigatedByComponentLabels: [String] = [],
        mitigatedByComponentReductions: [Int] = [],
        mitigatesEdgeChoices: [AssessedMitigatesEdge] = [],
        likelihoodId: String = Likelihood.commodity.id,
        likelihoodLabel: String = Likelihood.commodity.label,
        scoreBeforeLikelihood: Int? = nil,
        likelihoodRationale: String? = nil,
        likelihoodFindingLabel: String? = nil,
        likelihoodSources: [String] = [],
        likelihoodReason: String = LikelihoodSource.catalogue(.commodity).reason,
        performedByLabels: [String] = [],
        knownVulnerabilities: [AssessedVulnerability] = [],
        scoreIfAssumptionsHold: Int? = nil,
        assumedByComponentLabels: [String] = [],
        severityDecision: AssessedSeverityDecision? = nil,
        recommendations: [AssessedRecommendation] = [],
        closedByTrees: [AssessedTreeClosure] = [],
        trees: [AssessedTreeRole] = [],
        matchReason: String? = nil
    ) {
        self.threatId = threatId
        self.name = name
        self.description = description
        self.severityId = severityId
        self.severityLabel = severityLabel
        self.stride = stride
        self.impacts = impacts
        self.mitreTechniques = mitreTechniques
        self.controls = controls
        self.source = source
        self.sensitivityId = sensitivityId
        self.riskScore = riskScore
        self.riskLevel = riskLevel
        self.context = context
        self.isTlsMitigated = isTlsMitigated
        self.overrideKey = overrideKey
        self.threatKey = threatKey
        self.overriddenSeverityId = overriddenSeverityId
        self.pathwayMitigationLabels = pathwayMitigationLabels
        self.pathwayMitigationModes = pathwayMitigationModes
        self.scoreBeforePathwayMitigation = scoreBeforePathwayMitigation
        self.compensatingLabels = compensatingLabels
        self.compensating = compensating
        self.compensatingEvidenceId = compensatingEvidenceId
        self.compensatingEvidenceReference = compensatingEvidenceReference
        self.compensatingVerifiedOn = compensatingVerifiedOn
        self.compensatingSources = compensatingSources
        self.scoreBeforeCompensation = scoreBeforeCompensation ?? riskScore
        self.inherentScore = inherentScore ?? riskScore
        self.mitigatedByComponentLabels = mitigatedByComponentLabels
        self.mitigatedByComponentReductions = mitigatedByComponentReductions
        self.mitigatesEdgeChoices = mitigatesEdgeChoices
        self.likelihoodId = likelihoodId
        self.likelihoodLabel = likelihoodLabel
        self.scoreBeforeLikelihood = scoreBeforeLikelihood ?? riskScore
        self.likelihoodRationale = likelihoodRationale
        self.likelihoodFindingLabel = likelihoodFindingLabel
        self.likelihoodSources = likelihoodSources
        self.likelihoodReason = likelihoodReason
        self.performedByLabels = performedByLabels
        self.knownVulnerabilities = knownVulnerabilities
        self.scoreIfAssumptionsHold = scoreIfAssumptionsHold ?? riskScore
        self.assumedByComponentLabels = assumedByComponentLabels
        self.severityDecision = severityDecision
        self.recommendations = recommendations
        self.closedByTrees = closedByTrees
        self.trees = trees
        self.matchReason = matchReason
    }
}

/// Lists every threat the model raises, as plain values.
public struct AssessThreatModel: AssessThreatModelUseCase {
    /// The CVEs of the component a threat is raised on, ranked. A threat on a
    /// zone or a flow carries none.
    static func vulnerabilities(on source: ResolvedSource, in model: ThreatModel) -> [AssessedVulnerability] {
        guard case .component(let id, _, _) = source,
              let component = model.components.first(where: { $0.id == id }) else {
            return []
        }
        return AssessedVulnerability.of(
            cves: component.cves,
            held: model.vulnerabilities,
            thresholds: VulnerabilityPriority.Thresholds(policy: model.policy)
        )
    }

    /// Why a step that is open is still open, read from the answers its
    /// threat holds. Section 7.5 of the language guide: `accepted` and
    /// `not_applicable` answer a threat and close no step.
    static func openBecause(_ statuses: [ControlStatus]) -> String {
        if statuses.contains(.accepted) { return "an accepted control closes no step" }
        if statuses.contains(.notApplicable) { return "a control that does not apply closes no step" }
        if statuses.isEmpty { return "no control answers it" }
        return "no control is implemented"
    }

    /// Every tree that names one threat as its goal or as a step, in the
    /// order the trees are given.
    static func roles(
        of key: ThreatKey,
        on trees: [BoundAttackTree],
        statuses: [ControlStatus]
    ) -> [AssessedTreeRole] {
        var roles: [AssessedTreeRole] = []
        for tree in trees {
            if tree.goal == key {
                roles.append(
                    AssessedTreeRole(
                        treeId: tree.id,
                        treeName: tree.name,
                        isGoal: true,
                        isTreeOpen: tree.isOpen,
                        isTreeStale: tree.isStale,
                        raisesRiskBy: tree.raisesRiskBy,
                        scoreBefore: tree.scoreBefore,
                        score: tree.score
                    )
                )
            }
            guard let step = tree.steps.first(where: { $0.key == key }) else { continue }
            roles.append(
                AssessedTreeRole(
                    treeId: tree.id,
                    treeName: tree.name,
                    isGoal: false,
                    isTreeOpen: tree.isOpen,
                    isTreeStale: tree.isStale,
                    raisesRiskBy: tree.raisesRiskBy,
                    scoreBefore: tree.scoreBefore,
                    score: tree.score,
                    stepState: step.state.rawValue,
                    stepClosedBy: step.closedBy,
                    stepIsOpenBecause: step.state == .open ? openBecause(statuses) : nil
                )
            )
        }
        return roles
    }

    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue
    /// The day a review date is measured against.
    private let clock: Clock
    /// Where the last resolution is kept, or nil to resolve every time.
    private let cache: ThreatResolutionCache?

    public init(
        models: ThreatModelGateway,
        catalogue: TechnologyCatalogue,
        clock: Clock = SystemClock(),
        cache: ThreatResolutionCache? = nil
    ) {
        self.models = models
        self.catalogue = catalogue
        self.clock = clock
        self.cache = cache
    }

    public func execute(_ request: AssessThreatModelRequest) -> AssessThreatModelResponse {
        let model = models.current()
        let taxonomy = catalogue.taxonomy()
        let today = CheckGovernance.today(clock.now())
        let lookup = TechnologyLookup(model: model, catalogue: catalogue)
        let resolvedByStages = cache?.resolved(models, catalogue)
            ?? ThreatResolver(model: model, catalogue: catalogue).resolve()
        let bound = AttackTreeBinding.bind(
            trees: model.attackTrees,
            to: resolvedByStages,
            context: AttackTreeContext(model: model, catalogue: catalogue)
        )
        let staged = AttackTreeScoring.apply(trees: bound, to: resolvedByStages)
        let resolved = staged.threats
        // The order rule of
        // `docs/superpowers/specs/2026-09-17-trees-in-the-threat-list-design.md`.
        let openStepTrees = RouteClosing.openSteps(on: staged.trees)
        let sufficientTrees = RouteClosing.sufficientControls(on: staged.trees)
        let nameOf: (ComponentId) -> String = { id in
            guard let component = model.components.first(where: { $0.id == id }) else {
                return id.value
            }
            return component.customName
                ?? lookup.findById(component.technologyId)?.name
                ?? component.technologyId.value
        }
        let dependencies = ProtectionDependencies.derive(
            from: resolved,
            edges: model.mitigatesEdges.filter { $0.effectiveStatus == .adopted },
            nameOf: nameOf
        )

        return AssessThreatModelResponse(
            threats: resolved.map { threat in
                AssessedThreat(
                    threatId: threat.threat.id.value,
                    name: threat.threat.name,
                    description: threat.threat.description,
                    severityId: threat.severity.id,
                    severityLabel: threat.severity.label,
                    stride: threat.threat.stride.map(\.value),
                    impacts: threat.impacts.map(\.rawValue),
                    mitreTechniques: threat.threat.mitreTechniques.map {
                        AssessedMitreTechnique(id: $0.id, name: $0.name, tactic: $0.tactic)
                    },
                    controls: Self.ordered(threat.controls.map { control in
                        // An accepted control states who carries the risk and
                        // when they read it again. The governance file writes
                        // both; this only carries them to the reader.
                        let accepted = control.status == .accepted
                            ? model.acceptedRisks[
                                ThreatKey(
                                    threatId: threat.threat.id.value,
                                    sourceId: threat.source.id
                                )
                            ]?.first { $0.control == control.description }
                            : nil
                        return AssessedControl(
                            description: control.description,
                            isTechnologySpecific: control.isTechnologySpecific,
                            key: control.key.value,
                            isImplemented: control.isImplemented,
                            statusId: control.status.rawValue,
                            acceptedBy: accepted?.owner.isEmpty == false ? accepted?.owner : nil,
                            reviewBy: accepted?.reviewBy?.description,
                            isReviewOverdue: accepted?.isOverdue(on: today) ?? false,
                            evidenceId: model.controlProofs[control.key]?.evidence?.rawValue,
                            evidenceReference: model.controlProofs[control.key].map(\.reference)
                                .flatMap { $0.isEmpty ? nil : $0 },
                            verifiedOn: model.controlProofs[control.key]?.verifiedOn?.description,
                            note: model.controlNotes[control.key],
                            closesTreeNames: Self.closes(
                                control.description,
                                onAnOpenStepOf: openStepTrees[
                                    ThreatKey(
                                        threatId: threat.threat.id.value,
                                        sourceId: threat.source.id
                                    )
                                ] ?? [],
                                sufficientFor: sufficientTrees
                            ),
                            mitigatedByEdgeId: control.mitigatedByEdgeId
                        )
                    }),
                    source: Self.source(threat.source),
                    sensitivityId: threat.sensitivity.rawValue,
                    riskScore: threat.score.value,
                    riskLevel: threat.score.level.rawValue,
                    context: threat.context,
                    isTlsMitigated: threat.isTlsMitigated,
                    overrideKey: threat.overrideKey.value,
                    threatKey: ThreatKey(
                        threatId: threat.threat.id.value,
                        sourceId: threat.source.id
                    ).value,
                    overriddenSeverityId: threat.overriddenSeverityId,
                    pathwayMitigationLabels: threat.mitigatedBy.map(\.label),
                    pathwayMitigationModes: Dictionary(
                        uniqueKeysWithValues: threat.mitigatedBy.map {
                            ($0.label, model.pathwayMitigations.config(for: $0).mode.label)
                        }
                    ),
                    scoreBeforePathwayMitigation: threat.scoreBeforePathwayMitigation,
                    compensatingLabels: threat.compensating.map(\.label),
                    compensating: threat.compensating.map {
                        AssessedCompensatingControl(
                            label: $0.label,
                            reducesRiskBy: $0.reducesRiskBy,
                            rationale: $0.rationale,
                            sources: $0.sources,
                            evidence: $0.proof.isEmpty ? nil : $0.proof.says
                        )
                    },
                    compensatingEvidenceId: threat.compensating.first?.proof.evidence?.rawValue,
                    compensatingEvidenceReference: threat.compensating.first.flatMap {
                        $0.proof.reference.isEmpty ? nil : $0.proof.reference
                    },
                    compensatingVerifiedOn: threat.compensating.first?.proof.verifiedOn?.description,
                    compensatingSources: threat.compensating.first?.sources ?? [],
                    scoreBeforeCompensation: threat.scoreBeforeCompensation,
                    inherentScore: threat.scoreBeforeControls,
                    mitigatedByComponentLabels: threat.mitigatedByComponents.map(\.protectorName),
                    mitigatedByComponentReductions: threat.mitigatedByComponents.map(\.reducesRiskBy),
                    mitigatesEdgeChoices: Self.edgeChoices(
                        answering: threat,
                        in: model.mitigatesEdges,
                        nameOf: nameOf
                    ),
                    likelihoodId: threat.likelihood.id,
                    likelihoodLabel: threat.likelihood.label,
                    scoreBeforeLikelihood: threat.scoreBeforeLikelihood,
                    likelihoodRationale: threat.likelihoodFinding?.rationale,
                    likelihoodFindingLabel: threat.likelihoodFinding?.label,
                    likelihoodSources: threat.likelihoodFinding?.sources ?? [],
                    likelihoodReason: threat.likelihoodSource.reason,
                    performedByLabels: threat.performedBy.map(\.name),
                    knownVulnerabilities: Self.vulnerabilities(on: threat.source, in: model),
                    scoreIfAssumptionsHold: threat.scoreIfAssumptionsHold,
                    assumedByComponentLabels: threat.assumedMitigations.map(\.protectorName),
                    severityDecision: threat.severityDecision.map { decision in
                        AssessedSeverityDecision(
                            fromLabel: threat.threat.severity.label,
                            toLabel: taxonomy.severity(id: decision.severityId)?.label ?? decision.severityId,
                            rationale: decision.rationale,
                            sources: decision.sources
                        )
                    },
                    recommendations: model.recommendations[
                        ThreatKey(
                            threatId: threat.threat.id.value,
                            sourceId: threat.source.id
                        )
                    ]?.map {
                        AssessedRecommendation(text: $0.text, note: $0.note, sources: $0.sources)
                    } ?? [],
                    closedByTrees: staged.trees
                        .filter {
                            $0.goal == ThreatKey(threatId: threat.threat.id.value, sourceId: threat.source.id)
                        }
                        .compactMap { tree in
                            tree.closedBy.map { AssessedTreeClosure(treeName: tree.name, control: $0) }
                        },
                    trees: Self.roles(
                        of: ThreatKey(
                            threatId: threat.threat.id.value,
                            sourceId: threat.source.id
                        ),
                        on: staged.trees,
                        statuses: threat.controls.map(\.status)
                    ),
                    matchReason: Self.matchReason(threat.threat, source: threat.source)
                )
            },
            severities: taxonomy.severities.map {
                AssessedSeverity(id: $0.id, label: $0.label)
            },
            protectionDependencies: dependencies,
            warnings: ProtectionDependencies.warnings(for: dependencies),
            attackTrees: staged.trees
        )
    }

    /// The open trees this control closes a step on, by name. A control on an
    /// open step breaks that step; a control a tree names as sufficient breaks
    /// the whole route.
    /// Every `mitigates` edge a person may map a control of this threat to:
    /// the edges that protect the element the threat is raised on and name
    /// the threat. Only a component carries such an edge.
    private static func edgeChoices(
        answering threat: ResolvedThreat,
        in edges: [MitigatesEdge],
        nameOf: (ComponentId) -> String
    ) -> [AssessedMitigatesEdge] {
        guard case .component(let componentId, _, _) = threat.source else { return [] }
        return edges
            .filter { $0.target == componentId && $0.answers(threat.threat.id) }
            .map { edge in
                AssessedMitigatesEdge(
                    id: edge.id,
                    protectorName: nameOf(edge.source),
                    reducesRiskBy: edge.reducesRiskBy,
                    statusId: edge.effectiveStatus.rawValue
                )
            }
    }

    private static func closes(
        _ description: String,
        onAnOpenStepOf stepTrees: [BoundAttackTree],
        sufficientFor sufficientTrees: [String: [BoundAttackTree]]
    ) -> [String] {
        var names = stepTrees.map(\.name)
        let fingerprint = ControlIdentity.fingerprint(of: description)
        for tree in sufficientTrees[fingerprint] ?? [] where names.contains(tree.name) == false {
            names.append(tree.name)
        }
        return names
    }

    /// The order rule: a control that closes a step on an open tree first.
    private static func ordered(_ controls: [AssessedControl]) -> [AssessedControl] {
        RouteClosing.first(controls) { $0.closesTreeNames.isEmpty == false }
    }

    private static func source(_ source: ResolvedSource) -> AssessedThreatSource {
        switch source {
        case .component(let id, let name, let providerId):
            .component(id: id.value, name: name, providerId: providerId.value)
        case .connection(let id, let sourceName, let targetName):
            .connection(id: id.value, sourceName: sourceName, targetName: targetName)
        case .zone(let id, let name):
            .zone(id: id.value, name: name)
        }
    }

    /// Why the library's matchers raised this threat on this element. Nil
    /// when the threat carries no matcher that narrows where it applies, so
    /// the card stays quiet for the common, unrestricted threat.
    public static func matchReason(_ threat: Threat, source: ResolvedSource) -> String? {
        var reasons: [String] = []
        switch source {
        case .component:
            if threat.appliesToPrivilegeLevels.isEmpty == false {
                reasons.append(
                    "Applies only where the component runs as "
                        + Self.joinedWithOr(threat.appliesToPrivilegeLevels.map(\.label)) + "."
                )
            }
        case .connection:
            if threat.boundary == .privilege {
                reasons.append("Applies only where the flow crosses a privilege level.")
            } else if threat.appliesToFlowKinds.isEmpty == false {
                reasons.append(
                    "Applies only to "
                        + Self.joinedWithOr(threat.appliesToFlowKinds.map(\.label)) + " flows."
                )
            }
        case .zone:
            reasons.append("Applies within the \((threat.boundary ?? .network).rawValue) boundary.")
        }
        if threat.isPathwayThreat {
            reasons.append(
                "Its sensitivity considers what this element feeds downstream, not only what it holds."
            )
        }
        return reasons.isEmpty ? nil : reasons.joined(separator: " ")
    }

    /// `"a"`, `"a or b"`, `"a, b or c"`. English list join with no Oxford
    /// comma before the last word, the way a short reason sentence reads.
    private static func joinedWithOr(_ words: [String]) -> String {
        guard let last = words.last else { return "" }
        guard words.count > 1 else { return last }
        return words.dropLast().joined(separator: ", ") + " or " + last
    }
}
