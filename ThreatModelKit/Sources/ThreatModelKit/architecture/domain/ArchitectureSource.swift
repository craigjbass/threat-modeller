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

    public init(
        systemName: String,
        catalogueTag: String? = nil,
        technologies: [SourceTechnology] = [],
        zones: [SourceZone] = [],
        components: [SourceComponent] = [],
        flows: [SourceFlow] = [],
        mitigates: [SourceMitigates] = [],
        riskTolerance: String? = nil,
        assumptions: [SourceAssumption] = []
    ) {
        self.systemName = systemName
        self.catalogueTag = catalogueTag
        self.technologies = technologies
        self.zones = zones
        self.components = components
        self.flows = flows
        self.mitigates = mitigates
        self.riskTolerance = riskTolerance
        self.assumptions = assumptions
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

    public init(
        id: String,
        name: String,
        category: String,
        description: String = "",
        threatIds: [String] = [],
        encrypts: Bool = false
    ) {
        self.id = id
        self.name = name
        self.category = category
        self.description = description
        self.threatIds = threatIds
        self.encrypts = encrypts
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
        shape: String? = nil
    ) {
        self.id = id
        self.technologyId = technologyId
        self.name = name
        self.data = data
        self.raisesThreats = raisesThreats
        self.runsAs = runsAs
        self.assets = assets
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

    public init(
        sourceId: String,
        targetId: String,
        kind: String = "network",
        description: String? = nil
    ) {
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
