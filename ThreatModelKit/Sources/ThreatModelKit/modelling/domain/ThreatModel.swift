/// The aggregate a threat model is assessed from. Overrides and implemented
/// controls join it in later milestones.
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
    /// Every control the user has recorded as in place.
    public var implementedControls: Set<ControlKey>

    public init(
        name: String = "Untitled",
        components: [Component] = [],
        connections: [Connection] = [],
        zones: [Zone] = [],
        severityOverrides: [SeverityOverrideKey: String] = [:],
        implementedControls: Set<ControlKey> = []
    ) {
        self.name = name
        self.components = components
        self.connections = connections
        self.zones = zones
        self.severityOverrides = severityOverrides
        self.implementedControls = implementedControls
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
