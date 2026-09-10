/// The report's Recommendations section.
///
/// Spec section 8.2. This is the most actionable page of the report, so it
/// sits above the threat list and states the risk beside each line.
public enum MarkdownRecommendations {
    public static func lines(_ recommendations: [ReportRecommendation]) -> [String] {
        guard recommendations.isEmpty == false else { return [] }

        var lines = ["## Recommendations", ""]
        for recommendation in recommendations {
            lines.append("- \(recommendation.text)")
            lines.append(
                "  - \(recommendation.threatName) on \(recommendation.sourceName),"
                    + " risk \(recommendation.riskScore)"
            )
            if let note = recommendation.note {
                lines.append("  - \(note)")
            }
        }
        lines.append("")
        return lines
    }
}
