/// The report's Data inventory section.
///
/// A reader asks what a system holds before asking what threatens it. One row
/// per named asset says what it is, who owns it, what holds it, what carries
/// it and the worst threat nobody has answered on any of them. A system that
/// declares no asset writes no section.
public enum MarkdownDataInventory {
    public static func lines(_ rows: [ReportAssetRow]) -> [String] {
        guard rows.isEmpty == false else { return [] }

        var lines = ["## Data inventory", ""]
        lines.append("| Asset | Classification | Owner | Held by | Carried by | Worst open threat |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for row in rows {
            let worst = row.worstOpenThreat.map { name in
                row.worstOpenScore.map { "\(name) (\($0))" } ?? name
            }
            lines.append(
                "| \(Markdown.cell(row.name))"
                    + " | \(Markdown.cell(row.classificationLabel))"
                    + " | \(Markdown.cell(row.owner ?? "\u{2014}"))"
                    + " | \(Markdown.cell(list(row.heldBy)))"
                    + " | \(Markdown.cell(list(row.carriedBy)))"
                    + " | \(Markdown.cell(worst ?? "None"))"
                    + " |"
            )
        }
        lines.append("")

        for row in rows where row.description.isEmpty == false {
            lines.append("- \(row.name): \(row.description)")
        }
        if rows.contains(where: { $0.description.isEmpty == false }) {
            lines.append("")
        }

        return lines
    }

    private static func list(_ names: [String]) -> String {
        names.isEmpty ? "\u{2014}" : names.joined(separator: ", ")
    }
}
