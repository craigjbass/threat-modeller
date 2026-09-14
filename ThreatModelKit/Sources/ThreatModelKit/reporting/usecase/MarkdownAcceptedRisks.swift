/// The report's Accepted risks section.
///
/// It sits after `## Recommendations` and before `## Assumptions`, because a
/// risk somebody decided to carry is a decision, not a thing still to do. A
/// model that accepts nothing writes no section.
public enum MarkdownAcceptedRisks {
    public static func lines(_ risks: [ReportAcceptedRisk]) -> [String] {
        guard risks.isEmpty == false else { return [] }

        var lines = ["## Accepted risks", ""]
        lines.append(
            "Each row is a risk the organisation decided to carry. The score is the full "
                + "score: accepting a risk lowers nothing."
        )
        lines.append("")
        lines.append("| Threat | Element | Score | Owner | Accepted | Review by | Rationale |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")

        for risk in risks {
            let reviewBy = risk.reviewBy.map { risk.isOverdue ? "\($0) **overdue**" : $0 }
            lines.append(
                "| \(Markdown.cell(risk.threatName)) | \(Markdown.cell(risk.sourceName))"
                    + " | \(risk.riskScore) | \(cell(risk.owner)) | \(cell(risk.acceptedOn))"
                    + " | \(cell(reviewBy)) | \(cell(risk.rationale)) |"
            )
        }
        lines.append("")
        return lines
    }

    /// How many of these a person has not read again by the date they set.
    public static func overdueCount(_ risks: [ReportAcceptedRisk]) -> Int {
        risks.filter(\.isOverdue).count
    }

    /// An empty field reads as a dash, so an ungoverned row is a row of
    /// dashes rather than a row of blanks.
    private static func cell(_ text: String?) -> String {
        guard let text, text.isEmpty == false else { return "\u{2014}" }
        return Markdown.cell(text)
    }
}
