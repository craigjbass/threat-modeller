/// The report's rollup tables, above the component list.
public enum MarkdownRollups {
    public static func lines(_ tables: ReportRollupTables) -> [String] {
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
            lines.append("| Zone | Components | Worst | Levels |")
            lines.append("| --- | --- | --- | --- |")
            for rollup in tables.byZone {
                let levels = rollup.byLevel.map { "\($0.label) \($0.count)" }.joined(separator: ", ")
                lines.append(
                    "| \(Markdown.cell(rollup.zoneName)) | \(rollup.componentCount)"
                        + " | \(rollup.worstScore) | \(levels.isEmpty ? "none" : levels) |"
                )
            }
            lines.append("")
        }

        if tables.topResidual.isEmpty == false {
            lines.append("## Top residual risk")
            lines.append("")
            // The "If assumed hold" column only earns its place when at
            // least one threat's target posture differs from its residual
            // score; a table with a column that never varies wastes a
            // reader's eye.
            let showsAssumed = tables.topResidual.contains { $0.scoreIfAssumptionsHold != $0.riskScore }
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
