import Foundation

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
    /// How the user has set the pathway mitigations. Starts with the master
    /// toggle off, so nothing is mitigated until they say so.
    public var pathwayMitigations: PathwayMitigationSettings
    /// When the model was first created, and when it last changed. A document
    /// carries both. Spec section 8.
    public var createdAt: Date
    public var updatedAt: Date
    /// The catalogue the model was last assessed against, or nil for a model
    /// that has never been saved.
    public var catalogueVersion: CatalogueVersion?

    public init(
        name: String = "Untitled",
        components: [Component] = [],
        connections: [Connection] = [],
        zones: [Zone] = [],
        severityOverrides: [SeverityOverrideKey: String] = [:],
        implementedControls: Set<ControlKey> = [],
        pathwayMitigations: PathwayMitigationSettings = PathwayMitigationSettings(),
        createdAt: Date = Date(timeIntervalSince1970: 0),
        updatedAt: Date = Date(timeIntervalSince1970: 0),
        catalogueVersion: CatalogueVersion? = nil
    ) {
        self.name = name
        self.components = components
        self.connections = connections
        self.zones = zones
        self.severityOverrides = severityOverrides
        self.implementedControls = implementedControls
        self.pathwayMitigations = pathwayMitigations
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.catalogueVersion = catalogueVersion
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
