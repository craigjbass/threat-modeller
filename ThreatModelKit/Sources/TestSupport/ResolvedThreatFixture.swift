import ThreatModelKit

/// Builds a `ResolvedThreat` with the fields a binding test cares about and a
/// plain default for the rest.
public enum ResolvedThreatFixture {
    public static func make(
        threatId: String,
        componentId: String,
        score: Int,
        statuses: [ControlStatus],
        compensating: [CompensatingControl],
        likelihood: Likelihood
    ) -> ResolvedThreat {
        let threat = Threat(
            id: ThreatId(threatId),
            name: threatId,
            description: "",
            severity: CatalogueFixture.high,
            stride: [],
            controls: []
        )
        let controls = statuses.enumerated().map { index, status in
            ResolvedControl(
                description: "control \(index)",
                isTechnologySpecific: false,
                key: ControlKey("\(threatId)-\(index)"),
                isImplemented: status == .implemented,
                status: status
            )
        }
        return ResolvedThreat(
            threat: threat,
            severity: CatalogueFixture.high,
            source: .component(id: ComponentId(componentId), name: componentId, providerId: ProviderId("aws")),
            sensitivity: .confidential,
            score: RiskScore(value: score),
            controls: controls,
            context: nil,
            isTlsMitigated: false,
            overrideKey: SeverityOverrideKey("\(componentId)/\(threatId)"),
            overriddenSeverityId: nil,
            mitigatedBy: [],
            scoreBeforePathwayMitigation: score,
            scoreBeforeControls: score,
            compensating: compensating,
            scoreBeforeCompensation: score,
            mitigatedByComponents: [],
            likelihood: likelihood,
            scoreBeforeLikelihood: score,
            likelihoodFinding: nil,
            severityDecision: nil,
            scoreIfAssumptionsHold: score,
            assumedMitigations: []
        )
    }
}
