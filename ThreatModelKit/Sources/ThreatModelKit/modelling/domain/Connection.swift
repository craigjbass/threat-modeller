/// A directed link from one component to another.
///
/// The canvas draws an arrowhead at `target`. A component never links to
/// itself, and one source and target pair carries at most one connection.
/// A link in the opposite direction is a separate connection.
/// `ConnectComponents` enforces all three rules.
public struct Connection: Equatable, Sendable {
    public let id: ConnectionId
    public let source: ComponentId
    public let target: ComponentId
    public var kind: FlowKind
    public var description: String?

    public init(
        id: ConnectionId,
        source: ComponentId,
        target: ComponentId,
        kind: FlowKind = .default,
        description: String? = nil
    ) {
        self.id = id
        self.source = source
        self.target = target
        self.kind = kind
        self.description = description
    }

    /// True when the component is either end of this connection.
    /// `RemoveComponents` uses it to cascade, `AssessThreatModel` to find the
    /// endpoints of a link.
    public func touches(_ componentId: ComponentId) -> Bool {
        source == componentId || target == componentId
    }
}
