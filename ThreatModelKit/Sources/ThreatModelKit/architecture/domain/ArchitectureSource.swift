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

    public init(
        systemName: String,
        catalogueTag: String? = nil,
        technologies: [SourceTechnology] = [],
        zones: [SourceZone] = [],
        components: [SourceComponent] = [],
        flows: [SourceFlow] = []
    ) {
        self.systemName = systemName
        self.catalogueTag = catalogueTag
        self.technologies = technologies
        self.zones = zones
        self.components = components
        self.flows = flows
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

    public init(
        id: String,
        kind: String = "private",
        network: String = "generic",
        name: String? = nil,
        reducesRisk: Bool = true,
        reducesRiskBy: Int? = nil,
        components: [SourceComponent] = []
    ) {
        self.id = id
        self.kind = kind
        self.network = network
        self.name = name
        self.reducesRisk = reducesRisk
        self.reducesRiskBy = reducesRiskBy
        self.components = components
    }
}

public struct SourceComponent: Equatable, Sendable {
    public let id: String
    public let technologyId: String
    public let name: String?
    public let data: String
    public let raisesThreats: Bool

    public init(
        id: String,
        technologyId: String,
        name: String? = nil,
        data: String = "internal",
        raisesThreats: Bool = true
    ) {
        self.id = id
        self.technologyId = technologyId
        self.name = name
        self.data = data
        self.raisesThreats = raisesThreats
    }
}

public struct SourceFlow: Equatable, Sendable {
    public let sourceId: String
    public let targetId: String

    public init(sourceId: String, targetId: String) {
        self.sourceId = sourceId
        self.targetId = targetId
    }

    /// The identifier a connection takes, and the identifier the controls file
    /// keys a flow's answers on.
    public var id: String { "\(sourceId)->\(targetId)" }
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
