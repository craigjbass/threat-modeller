import Foundation

/// The aggregate a threat model is assessed from.
public struct ThreatModel: Equatable, Sendable {
    public var name: String
    public var components: [Component]
    public var connections: [Connection]
    /// In drawing order. A zone later in this list wins over an earlier one
    /// where they overlap.
    public var zones: [Zone]
    /// A severity the user has overridden, keyed as spec section 5.3 states.
    /// The value is a severity id the taxonomy resolves.
    public var severityOverrides: [SeverityOverrideKey: String]
    /// What the user said about each control. A control nobody has answered
    /// is not in here.
    public var controlStatuses: [ControlKey: ControlStatus]
    /// What compensates a threat the catalogue's own controls do not answer.
    /// Spec section 5: the one thing in a controls file that moves a score.
    public var compensatingControls: [ThreatKey: [CompensatingControl]]
    /// One component answering a named threat on another. `ComponentMitigations`
    /// reads these edges.
    public var mitigatesEdges: [MitigatesEdge]
    /// What a person says should be done about a threat, keyed the way a
    /// compensating control is.
    public var recommendations: [ThreatKey: [Recommendation]]
    /// What a person found out about how often each threat happens, keyed the
    /// way a compensating control is.
    public var likelihoodFindings: [ThreatKey: LikelihoodFinding]
    /// What an assessor decided each threat's severity is, and why, keyed by
    /// threat and source. Wins over `severityOverrides` for the threat it
    /// names.
    public var severityDecisions: [ThreatKey: SeverityDecision]
    /// What a team states a threat harms in this system, by threat and source.
    /// Empty for a threat whose catalogue answer stands.
    public var impactOverrides: [ThreatKey: [ThreatImpact]]
    /// What a person does with this system, in file order.
    public var useCases: [SystemUseCase]
    /// What this model does not cover, in file order.
    public var exclusions: [SystemExclusion]
    /// The named things of value this system holds, in file order.
    public var systemAssets: [SystemAsset]
    /// The parties outside this team the system depends on, in file order.
    public var thirdParties: [ThirdParty]
    /// The pictures the team keeps beside the diagram, in file order.
    public var diagrams: [SystemDiagram]
    /// What the model takes on trust. The report gives them a section.
    public var assumptions: [SystemAssumption]
    /// The routes a person wrote in the `.attacktree` file. Empty when the
    /// project holds no such file.
    public var attackTrees: [SourceAttackTree]
    /// The risk level a likelihood finding may answer up to. Nil means the
    /// file states none, so `effectiveRiskTolerance` is what a check uses.
    public var riskTolerance: RiskLevel?

    /// The risk level a check uses: what the file states, or `.low` when the
    /// file states none.
    public var effectiveRiskTolerance: RiskLevel { riskTolerance ?? .low }

    /// Every control the user has recorded as in place.
    ///
    /// Derived from `controlStatuses`, and written by setting them.
    public var implementedControls: Set<ControlKey> {
        get { Set(controlStatuses.filter { $0.value.isRecorded }.keys) }
        set {
            for key in controlStatuses.keys where controlStatuses[key]?.isRecorded == true {
                controlStatuses[key] = .notImplemented
            }
            for key in newValue {
                controlStatuses[key] = .implemented
            }
        }
    }
    /// How the user has set the pathway mitigations. Starts with the master
    /// toggle off, so nothing is mitigated until they say so.
    public var pathwayMitigations: PathwayMitigationSettings
    /// Technologies this model defines for itself. Spec section 8: they travel
    /// in the document.
    public var customTechnologies: [CustomTechnology]
    /// Who owns this system, from the `.arch` file. Empty when it states
    /// nobody.
    public var owner: String
    /// What this model states about itself: the description, the authors, the
    /// links, the dates and the version. None of it moves a score.
    public var documentFacts: DocumentFacts
    /// The rules the project states for itself, or nil when it holds no
    /// policy file.
    public var policy: PolicySource?
    /// What proves each control is in place, by control key. Sparse: a
    /// control that states none of the three attributes is not in here.
    public var controlProofs: [ControlKey: ControlProof]
    /// What a person wrote about each control, by control key. Sparse: a
    /// control with no note is not in here.
    public var controlNotes: [ControlKey: String]
    /// The `mitigates` edges a person says implement each control, and how
    /// much each one takes off, by control key. Sparse: a control nobody has
    /// mapped to an edge is not in here.
    public var controlMitigatedBy: [ControlKey: [ControlMitigation]]
    /// The risk level at and above which an implemented control must state
    /// evidence, or nil when the project states no such rule.
    public var requiresEvidenceAbove: RiskLevel?
    /// Who carries each accepted risk, keyed the way a compensating control
    /// is. Written by the governance file; it lowers no score.
    public var acceptedRisks: [ThreatKey: [RiskAcceptance]]
    /// Who does each recommendation, keyed the same way.
    public var plannedWork: [ThreatKey: [PlannedWork]]
    /// Who does each action the architecture declares, by the action's label.
    public var actionWork: [String: PlannedWork]
    /// The threat actors this system faces, in the order the `.arch` file
    /// states them. A model that faces nobody scores by the catalogue alone.
    public var facedActorIds: [String]
    /// The threat actors the `.arch` file declares for itself. One of these
    /// beats a library actor of the same id, whole.
    public var localActors: [ThreatActor]
    /// The vetting levels the `.arch` file declares, in file order. A user
    /// names one of these.
    public var clearances: [Clearance]
    /// What the lock file states about each CVE the components name, by id.
    /// Empty when the project holds no lock file. A known exploited one
    /// raises every threat on its component to commodity.
    public var vulnerabilities: [String: KnownVulnerability]
    /// When the model was first created, and when it last changed. A document
    /// carries both. Spec section 8.
    public var createdAt: Date
    public var updatedAt: Date
    /// The catalogue the model was last assessed against, or nil for a model
    /// that has never been saved.
    public var catalogueVersion: CatalogueVersion?

    public init(
        name: String = "Untitled",
        components: [Component] = [],
        connections: [Connection] = [],
        zones: [Zone] = [],
        severityOverrides: [SeverityOverrideKey: String] = [:],
        implementedControls: Set<ControlKey> = [],
        controlStatuses: [ControlKey: ControlStatus] = [:],
        compensatingControls: [ThreatKey: [CompensatingControl]] = [:],
        mitigatesEdges: [MitigatesEdge] = [],
        recommendations: [ThreatKey: [Recommendation]] = [:],
        likelihoodFindings: [ThreatKey: LikelihoodFinding] = [:],
        severityDecisions: [ThreatKey: SeverityDecision] = [:],
        impactOverrides: [ThreatKey: [ThreatImpact]] = [:],
        useCases: [SystemUseCase] = [],
        exclusions: [SystemExclusion] = [],
        systemAssets: [SystemAsset] = [],
        thirdParties: [ThirdParty] = [],
        diagrams: [SystemDiagram] = [],
        assumptions: [SystemAssumption] = [],
        attackTrees: [SourceAttackTree] = [],
        riskTolerance: RiskLevel? = nil,
        pathwayMitigations: PathwayMitigationSettings = PathwayMitigationSettings(),
        customTechnologies: [CustomTechnology] = [],
        owner: String = "",
        documentFacts: DocumentFacts = DocumentFacts(),
        policy: PolicySource? = nil,
        controlProofs: [ControlKey: ControlProof] = [:],
        controlNotes: [ControlKey: String] = [:],
        controlMitigatedBy: [ControlKey: [ControlMitigation]] = [:],
        requiresEvidenceAbove: RiskLevel? = nil,
        acceptedRisks: [ThreatKey: [RiskAcceptance]] = [:],
        plannedWork: [ThreatKey: [PlannedWork]] = [:],
        actionWork: [String: PlannedWork] = [:],
        facedActorIds: [String] = [],
        localActors: [ThreatActor] = [],
        clearances: [Clearance] = [],
        vulnerabilities: [String: KnownVulnerability] = [:],
        createdAt: Date = Date(timeIntervalSince1970: 0),
        updatedAt: Date = Date(timeIntervalSince1970: 0),
        catalogueVersion: CatalogueVersion? = nil
    ) {
        self.name = name
        self.components = components
        self.connections = connections
        self.zones = zones
        self.severityOverrides = severityOverrides
        self.controlStatuses = controlStatuses
        self.compensatingControls = compensatingControls
        self.mitigatesEdges = mitigatesEdges
        self.recommendations = recommendations
        self.likelihoodFindings = likelihoodFindings
        self.severityDecisions = severityDecisions
        self.impactOverrides = impactOverrides
        self.useCases = useCases
        self.exclusions = exclusions
        self.systemAssets = systemAssets
        self.thirdParties = thirdParties
        self.diagrams = diagrams
        self.assumptions = assumptions
        self.attackTrees = attackTrees
        self.riskTolerance = riskTolerance
        // The two ways of saying the same thing meet here: a caller may pass
        // either, and a recorded control is a status.
        for key in implementedControls {
            self.controlStatuses[key] = .implemented
        }
        self.pathwayMitigations = pathwayMitigations
        self.customTechnologies = customTechnologies
        self.owner = owner
        self.documentFacts = documentFacts
        self.policy = policy
        self.controlProofs = controlProofs
        self.controlNotes = controlNotes
        self.controlMitigatedBy = controlMitigatedBy
        self.requiresEvidenceAbove = requiresEvidenceAbove
        self.acceptedRisks = acceptedRisks
        self.plannedWork = plannedWork
        self.actionWork = actionWork
        self.facedActorIds = facedActorIds
        self.localActors = localActors
        self.clearances = clearances
        self.vulnerabilities = vulnerabilities
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.catalogueVersion = catalogueVersion
    }

    /// The component with that identifier, or nil. Every write use case checks
    /// a component exists before it changes anything.
    public func component(_ id: ComponentId) -> Component? {
        components.first { $0.id == id }
    }

    public func zone(_ id: ZoneId) -> Zone? {
        zones.first { $0.id == id }
    }

    public func customTechnology(_ id: TechnologyId) -> CustomTechnology? {
        customTechnologies.first { $0.id == id }
    }

    /// Every user on the diagram, in model order.
    public var users: [Component] { components.filter(\.isUser) }

    /// Every threat actor id this system faces: what `faces` states, then
    /// the actor each user names, in model order, with a repeat dropped. A
    /// user that names an actor is faced whether or not `faces` lists it.
    public var everyFacedActorId: [String] {
        var seen: Set<String> = []
        return (facedActorIds + components.compactMap { $0.user?.threatActorId })
            .filter { seen.insert($0).inserted }
    }
}
