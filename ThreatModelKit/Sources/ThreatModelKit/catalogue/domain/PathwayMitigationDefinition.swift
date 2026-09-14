public struct PathwayMitigationId: Hashable, Sendable, CustomStringConvertible {
    public let value: String
    public init(_ value: String) { self.value = value }
    public var description: String { value }
}

/// A control that answers a threat for everything downstream of it.
///
/// The catalogue says what a mitigation is called, which threats it answers and
/// which technologies provide it. Whether it is switched on, and what it does
/// to a score, are the user's settings and live on the model.
public struct PathwayMitigationDefinition: Equatable, Sendable {
    public let id: PathwayMitigationId
    public let label: String
    public let description: String
    public let mitigatesThreatIds: [ThreatId]
    /// The technologies that provide this mitigation.
    public let technologyIds: [TechnologyId]
    /// The percentage the catalogue states this mitigation reduces risk by, or
    /// nil when the catalogue states none. The user's settings start from this
    /// value until the user sets their own.
    public let reducesRiskBy: Int?
    /// What the catalogue states this mitigation does to a threat it answers,
    /// or nil when the catalogue states nothing. The user's settings start
    /// from this mode until the user sets their own.
    public let defaultMode: PathwayMitigationMode?

    public init(
        id: PathwayMitigationId,
        label: String,
        description: String,
        mitigatesThreatIds: [ThreatId],
        technologyIds: [TechnologyId],
        reducesRiskBy: Int? = nil,
        defaultMode: PathwayMitigationMode? = nil
    ) {
        self.id = id
        self.label = label
        self.description = description
        self.mitigatesThreatIds = mitigatesThreatIds
        self.technologyIds = technologyIds
        self.reducesRiskBy = reducesRiskBy
        self.defaultMode = defaultMode
    }

    public func mitigates(_ threatId: ThreatId) -> Bool {
        mitigatesThreatIds.contains(threatId)
    }

    public func isProvidedBy(_ technologyId: TechnologyId) -> Bool {
        technologyIds.contains(technologyId)
    }
}
