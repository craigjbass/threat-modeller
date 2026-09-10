/// The report's Recommendations section.
///
/// Spec section 8.2. This is the most actionable page of the report, so it
/// sits above the threat list and states the risk beside each line, grouped
/// by the source that raised the threat, worst source first.
public enum MarkdownRecommendations {
    public static func lines(_ recommendations: [ReportRecommendation]) -> [String] {
        guard recommendations.isEmpty == false else { return [] }

        var lines = ["## Recommendations", ""]
        for group in groupedBySource(recommendations) {
            lines.append("### \(group.sourceName)")
            lines.append("")
            for recommendation in group.recommendations {
                lines.append("- \(recommendation.text)")
                lines.append("  - \(recommendation.threatName), risk \(recommendation.riskScore)")
                if let note = recommendation.note {
                    lines.append("  - \(note)")
                }
                for source in recommendation.sources {
                    lines.append("  - Source: \(source)")
                }
            }
            lines.append("")
        }
        return lines
    }

    /// One group per source, worst group first. Inside a group the worst
    /// recommendation comes first, whatever order the caller passed them in.
    private static func groupedBySource(
        _ recommendations: [ReportRecommendation]
    ) -> [(sourceName: String, recommendations: [ReportRecommendation])] {
        var order: [String] = []
        var bucket: [String: [ReportRecommendation]] = [:]
        for recommendation in recommendations {
            if bucket[recommendation.sourceName] == nil { order.append(recommendation.sourceName) }
            bucket[recommendation.sourceName, default: []].append(recommendation)
        }

        return order
            .map { sourceName in
                (
                    sourceName: sourceName,
                    recommendations: (bucket[sourceName] ?? []).sorted { left, right in
                        if left.riskScore != right.riskScore { return left.riskScore > right.riskScore }
                        return left.text < right.text
                    }
                )
            }
            .sorted { left, right in
                (left.recommendations.map(\.riskScore).max() ?? 0)
                    > (right.recommendations.map(\.riskScore).max() ?? 0)
            }
    }
}
