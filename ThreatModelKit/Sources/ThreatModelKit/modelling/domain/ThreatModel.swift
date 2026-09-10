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
    /// What the user said about each control. A control nobody has answered
    /// is not in here.
    public var controlStatuses: [ControlKey: ControlStatus]
    /// What compensates a threat the catalogue's own controls do not answer.
    /// Spec section 5: the one thing in a controls file that moves a score.
    public var compensatingControls: [ThreatKey: [CompensatingControl]]
    /// One component answering a named threat on another. Task 9 reads these;
    /// until then the resolver carries them without acting on them.
    public var mitigatesEdges: [MitigatesEdge]
    /// What a person says should be done about a threat, keyed the way a
    /// compensating control is.
    public var recommendations: [ThreatKey: [Recommendation]]
    /// What a person found out about how often each threat happens, keyed the
    /// way a compensating control is.
    public var likelihoodFindings: [ThreatKey: LikelihoodFinding]
    /// What an assessor decided each threat's severity is, and why, keyed by
    /// threat and source. Wins over `severityOverrides` for the threat it
    /// names.
    public var severityDecisions: [ThreatKey: SeverityDecision]

    /// Every control the user has recorded as in place.
    ///
    /// Derived from the statuses, and written by setting them, so everything
    /// that read this before Milestone 10B still reads it.
    public var implementedControls: Set<ControlKey> {
        get { Set(controlStatuses.filter { $0.value.isRecorded }.keys) }
        set {
            for key in controlStatuses.keys where controlStatuses[key]?.isRecorded == true {
                controlStatuses[key] = .notImplemented
            }
            for key in newValue {
                controlStatuses[key] = .implemented
            }
        }
    }
    /// How the user has set the pathway mitigations. Starts with the master
    /// toggle off, so nothing is mitigated until they say so.
    public var pathwayMitigations: PathwayMitigationSettings
    /// Technologies this model defines for itself. Spec section 8: they travel
    /// in the document.
    public var customTechnologies: [CustomTechnology]
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
        controlStatuses: [ControlKey: ControlStatus] = [:],
        compensatingControls: [ThreatKey: [CompensatingControl]] = [:],
        mitigatesEdges: [MitigatesEdge] = [],
        recommendations: [ThreatKey: [Recommendation]] = [:],
        likelihoodFindings: [ThreatKey: LikelihoodFinding] = [:],
        severityDecisions: [ThreatKey: SeverityDecision] = [:],
        pathwayMitigations: PathwayMitigationSettings = PathwayMitigationSettings(),
        customTechnologies: [CustomTechnology] = [],
        createdAt: Date = Date(timeIntervalSince1970: 0),
        updatedAt: Date = Date(timeIntervalSince1970: 0),
        catalogueVersion: CatalogueVersion? = nil
    ) {
        self.name = name
        self.components = components
        self.connections = connections
        self.zones = zones
        self.severityOverrides = severityOverrides
        self.controlStatuses = controlStatuses
        self.compensatingControls = compensatingControls
        self.mitigatesEdges = mitigatesEdges
        self.recommendations = recommendations
        self.likelihoodFindings = likelihoodFindings
        self.severityDecisions = severityDecisions
        // The two ways of saying the same thing meet here: a caller may pass
        // either, and a recorded control is a status.
        for key in implementedControls {
            self.controlStatuses[key] = .implemented
        }
        self.pathwayMitigations = pathwayMitigations
        self.customTechnologies = customTechnologies
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

    public func customTechnology(_ id: TechnologyId) -> CustomTechnology? {
        customTechnologies.first { $0.id == id }
    }
}
