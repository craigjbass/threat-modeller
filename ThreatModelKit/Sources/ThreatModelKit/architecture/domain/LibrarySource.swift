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

    public init(
        label: String,
        displayName: String? = nil,
        catalogueTag: String? = nil,
        technologies: [SourceTechnology] = [],
        threats: [SourceLibraryThreat] = []
    ) {
        self.label = label
        self.displayName = displayName
        self.catalogueTag = catalogueTag
        self.technologies = technologies
        self.threats = threats
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
        controlDescriptions: [String] = []
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
