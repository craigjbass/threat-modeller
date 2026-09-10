/// What a `mitigates` edge takes off a threat.
public struct ComponentMitigation: Equatable, Sendable {
    public let protectorId: ComponentId
    public let protectorName: String
    public let reducesRiskBy: Int

    public init(protectorId: ComponentId, protectorName: String, reducesRiskBy: Int) {
        self.protectorId = protectorId
        self.protectorName = protectorName
        self.reducesRiskBy = reducesRiskBy
    }
}

/// The stage between the pathway mitigation and the compensating control.
///
/// Task 9 fills this in. Until then it returns the score it was given, so the
/// hook in `ThreatResolver` changes nothing.
public enum ComponentMitigations {
    public static func apply(
        score: Int,
        threatId: ThreatId,
        target: ComponentId,
        edges: [MitigatesEdge],
        nameOf: (ComponentId) -> String
    ) -> (score: Int, by: [ComponentMitigation]) {
        (score, [])
    }
}
