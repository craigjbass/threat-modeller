/// The aggregate a threat model is assessed from. Zones, overrides and
/// implemented controls join it in later milestones.
public struct ThreatModel: Equatable, Sendable {
    public var name: String
    public var components: [Component]
    public var connections: [Connection]

    public init(
        name: String = "Untitled",
        components: [Component] = [],
        connections: [Connection] = []
    ) {
        self.name = name
        self.components = components
        self.connections = connections
    }

    /// The component with that identifier, or nil. Every write use case checks
    /// a component exists before it changes anything.
    public func component(_ id: ComponentId) -> Component? {
        components.first { $0.id == id }
    }
}
