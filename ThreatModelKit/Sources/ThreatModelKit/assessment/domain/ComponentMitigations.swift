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
/// Spec section 6.2. Two edges that both answer one threat give the stronger
/// reduction, not the sum, which is the rule the pathway mitigations and the
/// compensating controls already follow.
public enum ComponentMitigations {
    public static func apply(
        score: Int,
        threatId: ThreatId,
        target: ComponentId,
        edges: [MitigatesEdge],
        statuses: Set<MitigationStatus> = [.adopted],
        nameOf: (ComponentId) -> String
    ) -> (score: Int, by: [ComponentMitigation]) {
        let answering = edges.filter {
            $0.target == target && $0.answers(threatId) && statuses.contains($0.status)
        }
        guard answering.isEmpty == false else { return (score, []) }

        let strongest = answering.map(\.reducesRiskBy).max() ?? 0
        let reduced = max(1, Int((Double(score) * (1 - Double(strongest) / 100)).rounded()))

        return (
            reduced,
            answering.map {
                ComponentMitigation(
                    protectorId: $0.source,
                    protectorName: nameOf($0.source),
                    reducesRiskBy: $0.reducesRiskBy
                )
            }
        )
    }
}
