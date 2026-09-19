/// The report's Recommendations section.
///
/// This is the most actionable page of the report, so it sits above the
/// threat register and reads worst risk first, whatever raised it.
///
/// `RecommendationsReport` decides the order. This writer prints the list it
/// is given, in that order, and does not sort it again.
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
            if let governance = recommendation.governance {
                lines.append("  - \(governance)")
            }
            if let acceptance = recommendation.planAcceptance {
                lines.append("  - Acceptance: \(acceptance)")
            }
            if let planNote = recommendation.planNote {
                lines.append("  - \(planNote)")
            }
            lines += Markdown.sourceLines(recommendation.sources)
            lines += Markdown.sourceLines(recommendation.planSources)
        }
        lines.append("")
        return lines
    }
}
