/// The report's Executive summary section.
///
/// This section writes for a reader who reads one page and no more, so its
/// sentences read as a deliverable rather than in the tool's plain register.
/// Every number in it comes from `ReportExecutiveSummary`; this writer counts
/// nothing itself.
public enum MarkdownExecutiveSummary {
    public static func lines(
        _ summary: ReportExecutiveSummary,
        components: [ReportComponent]
    ) -> [String] {
        var lines = ["## Executive summary", "", summary.verdict, ""]

        if summary.topRisks.isEmpty == false {
            lines.append("**Highest residual risk**")
            lines.append("")
            for (index, threat) in summary.topRisks.enumerated() {
                let level = RiskLevel(rawValue: threat.riskLevel)?.label ?? threat.riskLevel
                lines.append(
                    "\(index + 1). \(threat.name) \u{2014} \(threat.sourceName)"
                        + " \u{2014} \(level) (\(threat.riskScore) of 16)."
                )
                if let element = components.first(where: { $0.name == threat.sourceName }) {
                    lines.append(
                        "   The element holds \(element.sensitivityLabel) data"
                            + " and runs as \(element.privilegeLabel)."
                    )
                }
            }
            lines.append("")
        }

        if summary.topActions.isEmpty == false {
            lines.append("**Do first**")
            lines.append("")
            for (index, action) in summary.topActions.enumerated() {
                lines.append(
                    "\(index + 1). \(action.text) \u{2014} answers \(action.threatName)"
                        + " on \(action.sourceName) (\(action.riskScore) of 16)."
                )
            }
            lines.append("")
        }

        lines.append(
            "\(summary.unansweredCount) of \(summary.totalThreats) threats hold"
                + " no answered control and no compensating control."
        )
        lines.append("")
        return lines
    }
}
