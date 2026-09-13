/// The report's Recommendations section.
///
/// This is the most actionable page of the report, so it sits above the
/// threat register and reads worst risk first, whatever raised it.
public enum MarkdownRecommendations {
    public static func lines(_ recommendations: [ReportRecommendation]) -> [String] {
        guard recommendations.isEmpty == false else { return [] }

        var lines = ["## Recommendations", ""]

        // A reader works down this list, so the worst risk is first. Grouping
        // by element hid the order a team should work in.
        let recommendations = recommendations.sorted { $0.riskScore > $1.riskScore }

        for recommendation in recommendations {
            lines.append("- \(recommendation.text)")
            lines.append(
                "  - \(recommendation.threatName) on \(recommendation.sourceName),"
                    + " risk \(recommendation.riskScore)"
            )
            if let note = recommendation.note {
                lines.append("  - \(note)")
            }
            lines += Markdown.sourceLines(recommendation.sources)
        }
        return lines
    }
}
