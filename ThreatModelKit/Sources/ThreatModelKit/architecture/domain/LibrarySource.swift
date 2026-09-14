/// What a library file says, as plain values.
///
/// This is the boundary, the way `ArchitectureSource` is. Ids here are
/// unprefixed: `Library.build` mints the prefixed ones.
public struct LibrarySource: Equatable, Sendable {
    /// The label of the `library` block, which is the provider id.
    public let label: String
    /// What the palette calls the group. Nil means the label.
    public let displayName: String?
    /// The catalogue tag the file was written against, or nil.
    public let catalogueTag: String?
    public let technologies: [SourceTechnology]
    public let threats: [SourceLibraryThreat]
    public let mitigations: [SourceLibraryMitigation]
    public let threatActors: [SourceThreatActor]

    public init(
        label: String,
        displayName: String? = nil,
        catalogueTag: String? = nil,
        technologies: [SourceTechnology] = [],
        threats: [SourceLibraryThreat] = [],
        mitigations: [SourceLibraryMitigation] = [],
        threatActors: [SourceThreatActor] = []
    ) {
        self.label = label
        self.displayName = displayName
        self.catalogueTag = catalogueTag
        self.technologies = technologies
        self.threats = threats
        self.mitigations = mitigations
        self.threatActors = threatActors
    }
}

/// A threat actor a library or an architecture file declares.
///
/// The words are the file's words. `Library.build` and `ImportArchitecture`
/// turn them into a `ThreatActor`, and the parser has already refused a tier
/// word outside the three.
public struct SourceThreatActor: Equatable, Sendable {
    public let id: String
    public let name: String
    public let description: String
    public let aliases: [String]
    /// A tier id: `commodity`, `targeted` or `research`. Nil means the
    /// application's own default, `targeted`.
    public let capability: String?
    public let intent: String
    public let performs: [String]
    public let techniques: [String]
    /// A tier id, or nil. An actor that states one performs every threat the
    /// catalogue marks at that tier.
    public let performsCatalogueTier: String?

    public init(
        id: String,
        name: String,
        description: String = "",
        aliases: [String] = [],
        capability: String? = nil,
        intent: String = "",
        performs: [String] = [],
        techniques: [String] = [],
        performsCatalogueTier: String? = nil
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.aliases = aliases
        self.capability = capability
        self.intent = intent
        self.performs = performs
        self.techniques = techniques
        self.performsCatalogueTier = performsCatalogueTier
    }
}

/// A threat a library defines.
public struct SourceLibraryThreat: Equatable, Sendable {
    public let id: String
    public let name: String
    public let description: String
    /// A severity id. The taxonomy says which ids exist, so the build checks it.
    public let severityLabel: String
    public let strideIds: [String]
    public let isConnectionThreat: Bool
    public let isZoneThreat: Bool
    public let zoneContext: String?
    public let mitre: [SourceMitreTechnique]
    /// A control is its description, which is what a controls file keys on.
    public let controlDescriptions: [String]
    /// The flow kinds this threat applies to. Empty means every flow kind.
    public let appliesTo: [String]
    /// The zone boundary a zone threat belongs to, or nil for every boundary.
    public let boundary: String?
    /// The privilege levels this threat applies to. Empty means every level.
    public let runsAs: [String]
    /// Whether this threat is a pathway threat.
    public let isPathwayThreat: Bool
    /// The tier id or the whole number a threat states, or nil for none.
    public let likelihood: String?

    public init(
        id: String,
        name: String,
        description: String = "",
        severityLabel: String,
        strideIds: [String] = [],
        isConnectionThreat: Bool = false,
        isZoneThreat: Bool = false,
        zoneContext: String? = nil,
        mitre: [SourceMitreTechnique] = [],
        controlDescriptions: [String] = [],
        appliesTo: [String] = [],
        boundary: String? = nil,
        runsAs: [String] = [],
        isPathwayThreat: Bool = false,
        likelihood: String? = nil
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.severityLabel = severityLabel
        self.strideIds = strideIds
        self.isConnectionThreat = isConnectionThreat
        self.isZoneThreat = isZoneThreat
        self.zoneContext = zoneContext
        self.mitre = mitre
        self.controlDescriptions = controlDescriptions
        self.appliesTo = appliesTo
        self.boundary = boundary
        self.runsAs = runsAs
        self.isPathwayThreat = isPathwayThreat
        self.likelihood = likelihood
    }
}

/// A pathway mitigation a library defines.
public struct SourceLibraryMitigation: Equatable, Sendable {
    public let id: String
    public let name: String
    public let description: String
    public let mitigatesThreatIds: [String]
    public let technologyIds: [String]
    public let reducesRiskBy: Int
    /// What the mitigation does to a threat it answers: `remove` or `reduce`.
    /// Nil when the file states none, and the application's own default mode
    /// stands.
    public let mode: String?

    public init(
        id: String,
        name: String,
        description: String = "",
        mitigatesThreatIds: [String] = [],
        technologyIds: [String] = [],
        reducesRiskBy: Int = 0,
        mode: String? = nil
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.mitigatesThreatIds = mitigatesThreatIds
        self.technologyIds = technologyIds
        self.reducesRiskBy = reducesRiskBy
        self.mode = mode
    }
}

public struct SourceMitreTechnique: Equatable, Sendable {
    public let id: String
    public let name: String
    public let tactic: String

    public init(id: String, name: String, tactic: String) {
        self.id = id
        self.name = name
        self.tactic = tactic
    }
}

/// What a read produced: a source when it could, and every fault it found.
public struct LibraryRead: Equatable, Sendable {
    public let source: LibrarySource?
    public let diagnostics: [Diagnostic]

    public init(source: LibrarySource?, diagnostics: [Diagnostic]) {
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
