/// The aggregate a threat model is assessed from. Overrides and implemented
/// controls join it in later milestones.
public struct ThreatModel: Equatable, Sendable {
    public var name: String
    public var components: [Component]
    public var connections: [Connection]
    /// In drawing order. A zone later in this list wins over an earlier one
    /// where they overlap.
    public var zones: [Zone]

    public init(
        name: String = "Untitled",
        components: [Component] = [],
        connections: [Connection] = [],
        zones: [Zone] = []
    ) {
        self.name = name
        self.components = components
        self.connections = connections
        self.zones = zones
    }

    /// The component with that identifier, or nil. Every write use case checks
    /// a component exists before it changes anything.
    public func component(_ id: ComponentId) -> Component? {
        components.first { $0.id == id }
    }

    public func zone(_ id: ZoneId) -> Zone? {
        zones.first { $0.id == id }
    }
}
