/// What one `mitigates` edge took off a threat, through the control that
/// names it.
public struct ComponentMitigation: Equatable, Sendable {
    public let protectorId: ComponentId
    public let protectorName: String
    public let reducesRiskBy: Int
    /// Whether the edge this mitigation came from is live or proposed.
    public let status: ComponentStatus

    public init(
        protectorId: ComponentId,
        protectorName: String,
        reducesRiskBy: Int,
        status: ComponentStatus = .live
    ) {
        self.protectorId = protectorId
        self.protectorName = protectorName
        self.reducesRiskBy = reducesRiskBy
        self.status = status
    }
}

/// The stage between the pathway mitigation and the compensating control.
///
/// Spec section 6.2. An edge lowers nothing on its own: a person says that an
/// edge implements one control and states how much it takes off, and this
/// reads those answers. Two mappings that answer one threat give the stronger
/// reduction, not the sum, which is the rule the pathway mitigations and the
/// compensating controls already follow.
public enum ComponentMitigations {
    public static func apply(
        score: Int,
        target: ComponentId,
        controls: [ResolvedControl],
        edges: [MitigatesEdge],
        statuses: Set<ComponentStatus> = [.live],
        nameOf: (ComponentId) -> String
    ) -> (score: Int, by: [ComponentMitigation]) {
        var answering: [ComponentMitigation] = []

        for control in controls {
            for mitigation in control.mitigations {
                guard let edge = edges.first(where: { $0.id == mitigation.edgeId }),
                      edge.target == target,
                      statuses.contains(edge.effectiveStatus) else { continue }
                // A live edge takes its reduction off only while the person
                // says the control is in place. A proposed edge states what
                // the score would be, so the control's answer does not gate
                // it: the pass that asks for proposed edges is asking what
                // putting them in place would buy.
                guard edge.effectiveStatus == .proposed || control.status == .implemented else {
                    continue
                }
                answering.append(
                    ComponentMitigation(
                        protectorId: edge.source,
                        protectorName: nameOf(edge.source),
                        reducesRiskBy: mitigation.reducesRiskBy,
                        status: edge.effectiveStatus
                    )
                )
            }
        }

        guard answering.isEmpty == false else { return (score, []) }

        let strongest = answering.map(\.reducesRiskBy).max() ?? 0
        let reduced = max(1, Int((Double(score) * (1 - Double(strongest) / 100)).rounded()))

        return (reduced, answering)
    }
}

