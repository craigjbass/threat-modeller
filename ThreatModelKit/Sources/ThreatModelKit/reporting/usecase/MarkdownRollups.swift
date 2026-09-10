/// The report's rollup tables, above the component list.
public enum MarkdownRollups {
    /// `showsAssumed` is the model's own flag, not the table's: spec section
    /// 6 says the column appears only when the model draws at least one
    /// assumed edge, not only when the rows this table happens to show
    /// differ under it. A threat whose residual is low because it is
    /// unlikely can drop out of the top-20 prefix while an assumed edge
    /// still stands elsewhere in the model, and the column must still show.
    public static func lines(_ tables: ReportRollupTables, showsAssumed: Bool) -> [String] {
        var lines: [String] = []

        if tables.bySourceKind.isEmpty == false {
            lines.append("## Where the risk sits")
            lines.append("")
            for count in tables.bySourceKind {
                lines.append("- \(count.label): \(count.count)")
            }
            lines.append("")
        }

        if tables.byZone.isEmpty == false {
            lines.append("## By zone")
            lines.append("")
            lines.append(
                showsAssumed
                    ? "| Zone | Components | Worst | If assumed hold | Levels |"
                    : "| Zone | Components | Worst | Levels |"
            )
            lines.append(
                showsAssumed
                    ? "| --- | --- | --- | --- | --- |"
                    : "| --- | --- | --- | --- |"
            )
            for rollup in tables.byZone {
                let levels = rollup.byLevel.map { "\($0.label) \($0.count)" }.joined(separator: ", ")
                let cells = showsAssumed
                    ? "| \(Markdown.cell(rollup.zoneName)) | \(rollup.componentCount)"
                        + " | \(rollup.worstScore) | \(rollup.worstScoreIfAssumptionsHold)"
                        + " | \(levels.isEmpty ? "none" : levels) |"
                    : "| \(Markdown.cell(rollup.zoneName)) | \(rollup.componentCount)"
                        + " | \(rollup.worstScore) | \(levels.isEmpty ? "none" : levels) |"
                lines.append(cells)
            }
            lines.append("")
        }

        if tables.topResidual.isEmpty == false {
            lines.append("## Top residual risk")
            lines.append("")
            lines.append(
                showsAssumed
                    ? "| Threat | Raised by | Residual | If assumed hold | Before controls | Level |"
                    : "| Threat | Raised by | Residual | Before controls | Level |"
            )
            lines.append(
                showsAssumed
                    ? "| --- | --- | --- | --- | --- | --- |"
                    : "| --- | --- | --- | --- | --- |"
            )
            for threat in tables.topResidual {
                let cells = showsAssumed
                    ? "| \(Markdown.cell(threat.name)) | \(Markdown.cell(threat.sourceName))"
                        + " | \(threat.riskScore) | \(threat.scoreIfAssumptionsHold)"
                        + " | \(threat.inherentScore) | \(threat.riskLevel) |"
                    : "| \(Markdown.cell(threat.name)) | \(Markdown.cell(threat.sourceName))"
                        + " | \(threat.riskScore) | \(threat.inherentScore) | \(threat.riskLevel) |"
                lines.append(cells)
            }
            lines.append("")
        }

        return lines
    }
}
