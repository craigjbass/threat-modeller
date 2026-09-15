/// What an architecture file says, as plain values.
///
/// This is the boundary. Text and tokens stay inside the language target; a use
/// case reads this and nothing else.
public struct ArchitectureSource: Equatable, Sendable {
    public let systemName: String
    /// The catalogue tag the file was written against, or nil.
    public let catalogueTag: String?
    public let technologies: [SourceTechnology]
    public let zones: [SourceZone]
    /// Components declared outside every zone.
    public let components: [SourceComponent]
    public let flows: [SourceFlow]
    public let mitigates: [SourceMitigates]
    /// The risk level a likelihood finding may answer up to. Nil means low.
    public let riskTolerance: String?
    public let assumptions: [SourceAssumption]
    /// What a person does with this system, in file order.
    public let useCases: [SourceUseCase]
    /// What this model does not cover, in file order.
    public let exclusions: [SourceExclusion]
    /// The named things of value this system holds, in file order.
    public let systemAssets: [SourceSystemAsset]
    /// The companies, projects and people outside this team the system
    /// depends on, in file order.
    public let thirdParties: [SourceThirdParty]
    /// The pictures the team keeps beside the diagram, in file order.
    public let diagrams: [SourceDiagram]
    /// The risk level at and above which an implemented control must state
    /// evidence, or nil when the file states no such rule.
    public let requiresEvidenceAbove: String?
    /// Who owns this system, or nil when the file states nobody. The policy
    /// rule `system_requires_owner` and the report read it.
    public let owner: String?
    /// The threat actor ids this system faces, in file order.
    public let faces: [String]
    /// The threat actors this file declares for itself.
    public let threatActors: [SourceThreatActor]
    /// What this system is, in the team's own words.
    public let description: String?
    /// Who wrote the model, in file order.
    public let authors: [String]
    /// Where the design, the ticket or the runbook is.
    public let links: [String]
    /// The repositories this system's code sits in.
    public let repositories: [String]
    /// When the model was written and when it was last read again, each
    /// `YYYY-MM-DD`.
    public let created: String?
    public let reviewed: String?
    /// What the team calls this version of the model.
    public let version: String?
    /// What the language does not name, stated by the team.
    public let attributes: [SourceSystemAttribute]

    public init(
        systemName: String,
        catalogueTag: String? = nil,
        technologies: [SourceTechnology] = [],
        zones: [SourceZone] = [],
        components: [SourceComponent] = [],
        flows: [SourceFlow] = [],
        mitigates: [SourceMitigates] = [],
        riskTolerance: String? = nil,
        assumptions: [SourceAssumption] = [],
        useCases: [SourceUseCase] = [],
        exclusions: [SourceExclusion] = [],
        systemAssets: [SourceSystemAsset] = [],
        thirdParties: [SourceThirdParty] = [],
        diagrams: [SourceDiagram] = [],
        requiresEvidenceAbove: String? = nil,
        owner: String? = nil,
        faces: [String] = [],
        threatActors: [SourceThreatActor] = [],
        description: String? = nil,
        authors: [String] = [],
        links: [String] = [],
        repositories: [String] = [],
        created: String? = nil,
        reviewed: String? = nil,
        version: String? = nil,
        attributes: [SourceSystemAttribute] = []
    ) {
        self.description = description
        self.authors = authors
        self.links = links
        self.repositories = repositories
        self.created = created
        self.reviewed = reviewed
        self.version = version
        self.attributes = attributes
        self.systemName = systemName
        self.catalogueTag = catalogueTag
        self.technologies = technologies
        self.zones = zones
        self.components = components
        self.flows = flows
        self.mitigates = mitigates
        self.riskTolerance = riskTolerance
        self.assumptions = assumptions
        self.useCases = useCases
        self.exclusions = exclusions
        self.systemAssets = systemAssets
        self.thirdParties = thirdParties
        self.diagrams = diagrams
        self.requiresEvidenceAbove = requiresEvidenceAbove
        self.owner = owner
        self.faces = faces
        self.threatActors = threatActors
    }

    /// Every component the file declares, wherever it declared it.
    public var everyComponent: [SourceComponent] {
        components + zones.flatMap(\.components)
    }
}

public struct SourceTechnology: Equatable, Sendable {
    public let id: String
    public let name: String
    public let category: String
    public let description: String
    public let threatIds: [String]
    public let encrypts: Bool
    /// The controls this technology brings, in the team's own words. They
    /// answer every threat it carries.
    public let controlDescriptions: [String]

    public init(
        id: String,
        name: String,
        category: String,
        description: String = "",
        threatIds: [String] = [],
        encrypts: Bool = false,
        controlDescriptions: [String] = []
    ) {
        self.id = id
        self.name = name
        self.category = category
        self.description = description
        self.threatIds = threatIds
        self.encrypts = encrypts
        self.controlDescriptions = controlDescriptions
    }
}

public struct SourceZone: Equatable, Sendable {
    public let id: String
    public let kind: String
    public let network: String
    public let name: String?
    public let reducesRisk: Bool
    /// nil means the application's default.
    public let reducesRiskBy: Int?
    public let components: [SourceComponent]
    public let boundary: String
    public let description: String?

    public init(
        id: String,
        kind: String = "private",
        network: String = "generic",
        name: String? = nil,
        reducesRisk: Bool = true,
        reducesRiskBy: Int? = nil,
        components: [SourceComponent] = [],
        boundary: String = "network",
        description: String? = nil
    ) {
        self.id = id
        self.kind = kind
        self.network = network
        self.name = name
        self.reducesRisk = reducesRisk
        self.reducesRiskBy = reducesRiskBy
        self.components = components
        self.boundary = boundary
        self.description = description
    }
}

public struct SourceComponent: Equatable, Sendable {
    public let id: String
    public let technologyId: String
    public let name: String?
    public let data: String
    public let raisesThreats: Bool
    public let runsAs: String
    public let assets: [SourceAsset]
    /// The system asset ids this component holds, in file order.
    public let holds: [String]
    /// The third party that provides this component, or nil.
    public let providedBy: String?
    /// What the file stated for `data`, or nil when it stated none. A
    /// component that states none takes the highest classification it holds.
    public let declaredData: String?
    /// The diagram shape the file forces, or nil to let the derivation decide.
    public let shape: String?

    public init(
        id: String,
        technologyId: String,
        name: String? = nil,
        data: String = "internal",
        raisesThreats: Bool = true,
        runsAs: String = "user",
        assets: [SourceAsset] = [],
        holds: [String] = [],
        providedBy: String? = nil,
        declaredData: String? = nil,
        shape: String? = nil
    ) {
        self.id = id
        self.technologyId = technologyId
        self.name = name
        self.data = data
        self.raisesThreats = raisesThreats
        self.runsAs = runsAs
        self.assets = assets
        self.holds = holds
        self.providedBy = providedBy
        self.declaredData = declaredData
        self.shape = shape
    }
}

public struct SourceAsset: Equatable, Sendable {
    public let name: String
    public let data: String

    public init(name: String, data: String = "internal") {
        self.name = name
        self.data = data
    }
}

public struct SourceFlow: Equatable, Sendable {
    public let sourceId: String
    public let targetId: String
    public let kind: String
    public let description: String?
    /// The system asset ids this flow carries, in file order.
    public let carries: [String]

    public init(
        sourceId: String,
        targetId: String,
        kind: String = "network",
        description: String? = nil,
        carries: [String] = []
    ) {
        self.carries = carries
        self.sourceId = sourceId
        self.targetId = targetId
        self.kind = kind
        self.description = description
    }

    /// The identifier a connection takes, and the identifier the controls file
    /// keys a flow's answers on.
    public var id: String { "\(sourceId)->\(targetId)" }
}

/// A recommendation written on one assumed `mitigates` edge.
public struct SourceEdgeAction: Equatable, Sendable {
    public let label: String
    public let text: String?
    public let note: String?
    public let blockedBy: String?
    public let sources: [String]

    public init(
        label: String,
        text: String? = nil,
        note: String? = nil,
        blockedBy: String? = nil,
        sources: [String] = []
    ) {
        self.label = label
        self.text = text
        self.note = note
        self.blockedBy = blockedBy
        self.sources = sources
    }
}

public struct SourceMitigates: Equatable, Sendable {
    public var sourceId: String
    public var targetId: String
    public var threatIds: [String]
    public var reducesRiskBy: Int
    /// "adopted" or "assumed". Nil means the file states none.
    public var status: String?
    /// What a team would do to adopt this edge, or nil when it names none.
    public var action: SourceEdgeAction?

    public init(
        sourceId: String,
        targetId: String,
        threatIds: [String],
        reducesRiskBy: Int,
        status: String? = nil,
        action: SourceEdgeAction? = nil
    ) {
        self.sourceId = sourceId
        self.targetId = targetId
        self.threatIds = threatIds
        self.reducesRiskBy = reducesRiskBy
        self.status = status
        self.action = action
    }

    /// The identifier, minted the way a flow's is.
    public var id: String { "\(sourceId)->\(targetId)" }

    /// The same edge with its action dropped, for a file that states one this
    /// language cannot mean.
    public func withoutAction() -> SourceMitigates {
        var edge = self
        edge.action = nil
        return edge
    }
}

/// One thing a team states about a system that the language does not name.
public struct SourceSystemAttribute: Equatable, Sendable {
    public let name: String
    public let value: String

    public init(name: String, value: String) {
        self.name = name
        self.value = value
    }
}

/// Something the file takes on trust, and who owns it.
public struct SourceAssumption: Equatable, Sendable {
    public let label: String
    public let text: String
    public let owner: String?

    public init(label: String, text: String, owner: String? = nil) {
        self.label = label
        self.text = text
        self.owner = owner
    }
}

/// One picture a team keeps beside the diagram the canvas draws.
public struct SourceDiagram: Equatable, Sendable {
    public let label: String
    /// `mermaid`, the one kind this application draws.
    public let kind: String
    /// The picture's source, byte for byte as the file states it.
    public let text: String

    public init(label: String, kind: String = "mermaid", text: String) {
        self.label = label
        self.kind = kind
        self.text = text
    }
}

/// One party outside this team the system depends on.
public struct SourceThirdParty: Equatable, Sendable {
    public let id: String
    public let name: String
    public let description: String
    /// `saas`, `open_source`, `infrastructure` or `contractor`.
    public let kind: String
    /// Whether the team pays this party for the thing it provides.
    public let payingCustomer: Bool
    /// What happens to this system when the party stops: `none`, `degraded`,
    /// `hard` or `operational`.
    public let uptime: String
    public let uptimeNotes: String
    public let owner: String?
    public let link: String?

    public init(
        id: String,
        name: String,
        description: String = "",
        kind: String = "saas",
        payingCustomer: Bool = false,
        uptime: String,
        uptimeNotes: String = "",
        owner: String? = nil,
        link: String? = nil
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.kind = kind
        self.payingCustomer = payingCustomer
        self.uptime = uptime
        self.uptimeNotes = uptimeNotes
        self.owner = owner
        self.link = link
    }
}

/// One named thing of value the system holds. The label is its identifier,
/// and a component states which of these it holds.
public struct SourceSystemAsset: Equatable, Sendable {
    public let id: String
    public let name: String
    /// A classification id, taking the words `data` takes.
    public let classification: String
    public let description: String
    public let owner: String?

    public init(
        id: String,
        name: String,
        classification: String = "internal",
        description: String = "",
        owner: String? = nil
    ) {
        self.id = id
        self.name = name
        self.classification = classification
        self.description = description
        self.owner = owner
    }
}

/// One thing a person does with the system.
public struct SourceUseCase: Equatable, Sendable {
    public let label: String
    public let text: String

    public init(label: String, text: String) {
        self.label = label
        self.text = text
    }
}

/// One thing this model does not cover, and why.
public struct SourceExclusion: Equatable, Sendable {
    public let label: String
    public let text: String
    public let rationale: String

    public init(label: String, text: String, rationale: String) {
        self.label = label
        self.text = text
        self.rationale = rationale
    }
}

/// What a read produced: a source when it could, and every fault it found.
public struct ArchitectureRead: Equatable, Sendable {
    public let source: ArchitectureSource?
    public let diagnostics: [Diagnostic]

    public init(source: ArchitectureSource?, diagnostics: [Diagnostic]) {
        self.source = source
        self.diagnostics = diagnostics
    }

    public var hasErrors: Bool {
        diagnostics.contains { $0.severity == .error }
    }

    public var warnings: [Diagnostic] {
        diagnostics.filter { $0.severity == .warning }
    }
}
