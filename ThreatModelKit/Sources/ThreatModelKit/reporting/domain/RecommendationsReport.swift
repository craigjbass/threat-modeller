/// Turns the recommendations on the model into the report's section.
///
/// Spec section 8.2: worst first, so the reader starts with the work that
/// matters. `RouteClosing` then lifts the work that breaks an open route
/// above the rest, so the report and the Controls stage read the same way. A recommendation whose threat the model no longer raises is left
/// out, the way an answer to a threat nobody raises is left out.
public enum RecommendationsReport {
    public static func build(
        threats: [ReportThreat],
        recommendations: [ThreatKey: [Recommendation]],
        governance: [ThreatKey: [PlannedWork]] = [:],
        routeClosingThreats: Set<ThreatKey> = []
    ) -> [ReportRecommendation] {
        var built: [ReportRecommendation] = []

        for threat in threats {
            let key = ThreatKey(threatId: threat.threatId, sourceId: threat.sourceId)
            for recommendation in recommendations[key] ?? [] {
                let plan = governance[key]?.first { $0.label == recommendation.text }
                built.append(
                    ReportRecommendation(
                        text: recommendation.text,
                        note: recommendation.note,
                        threatName: threat.name,
                        sourceName: threat.sourceName,
                        riskScore: threat.riskScore,
                        sources: recommendation.sources,
                        threatId: threat.threatId,
                        sourceId: threat.sourceId,
                        governance: plan?.says,
                        planAcceptance: plan?.acceptance.isEmpty == false ? plan?.acceptance : nil,
                        planNote: plan?.note.isEmpty == false ? plan?.note : nil,
                        planSources: plan?.sources ?? []
                    )
                )
            }
        }

        let sorted = built.sorted { left, right in
            if left.riskScore != right.riskScore { return left.riskScore > right.riskScore }
            return left.text < right.text
        }

        // The order rule of
        // `docs/superpowers/specs/2026-09-17-trees-in-the-threat-list-design.md`,
        // which the Controls stage reads too: a recommendation on an open
        // step of an open tree comes before one that closes no route.
        return RouteClosing.first(sorted) {
            routeClosingThreats.contains(
                ThreatKey(threatId: $0.threatId, sourceId: $0.sourceId)
            )
        }
    }
}
