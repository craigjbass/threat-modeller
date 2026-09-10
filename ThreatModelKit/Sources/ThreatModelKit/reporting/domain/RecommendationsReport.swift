/// Turns the recommendations on the model into the report's section.
///
/// Spec section 8.2: worst first, so the reader starts with the work that
/// matters. A recommendation whose threat the model no longer raises is left
/// out, the way an answer to a threat nobody raises is left out.
public enum RecommendationsReport {
    public static func build(
        threats: [ReportThreat],
        recommendations: [ThreatKey: [Recommendation]]
    ) -> [ReportRecommendation] {
        var built: [ReportRecommendation] = []

        for threat in threats {
            let key = ThreatKey(threatId: threat.threatId, sourceId: threat.sourceId)
            for recommendation in recommendations[key] ?? [] {
                built.append(
                    ReportRecommendation(
                        text: recommendation.text,
                        note: recommendation.note,
                        threatName: threat.name,
                        sourceName: threat.sourceName,
                        riskScore: threat.riskScore
                    )
                )
            }
        }

        return built.sorted { left, right in
            if left.riskScore != right.riskScore { return left.riskScore > right.riskScore }
            return left.text < right.text
        }
    }
}
