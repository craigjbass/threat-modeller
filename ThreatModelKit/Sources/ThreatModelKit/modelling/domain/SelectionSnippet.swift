/// What a copy holds.
///
/// The identifiers inside are the ones the copy was taken from. They are unique
/// within one document only, and a snippet crosses documents, so
/// `PasteSelection` always mints fresh ones and rewrites the links between them.
///
/// A copy carries the user's answers about what it holds, so a pasted element
/// scores what the copied one scored: the controls they ticked, the severities
/// they overrode and the likelihood they found. Every key in those three is
/// scoped to an element in this snippet, or is one of the keys consolidated
/// across every link and every zone.
public struct SelectionSnippet: Equatable, Sendable {
    public let components: [Component]
    /// Only the links whose both ends are in `components`. A link to something
    /// that was not copied has nothing to attach to.
    public let connections: [Connection]
    public let zones: [Zone]
    /// What the user said about each control of the copied elements.
    public let controlStatuses: [ControlKey: ControlStatus]
    /// The severities the user overrode on the copied elements.
    public let severityOverrides: [SeverityOverrideKey: String]
    /// What the user found out about how often each threat on the copied
    /// elements happens.
    public let likelihoodFindings: [ThreatKey: LikelihoodFinding]

    public init(
        components: [Component],
        connections: [Connection],
        zones: [Zone],
        controlStatuses: [ControlKey: ControlStatus] = [:],
        severityOverrides: [SeverityOverrideKey: String] = [:],
        likelihoodFindings: [ThreatKey: LikelihoodFinding] = [:]
    ) {
        self.components = components
        self.connections = connections
        self.zones = zones
        self.controlStatuses = controlStatuses
        self.severityOverrides = severityOverrides
        self.likelihoodFindings = likelihoodFindings
    }

    public var isEmpty: Bool {
        components.isEmpty && connections.isEmpty && zones.isEmpty
    }
}
