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
            lines.append("| Threat | Raised by | Residual | Before controls | Level |")
            lines.append("| --- | --- | --- | --- | --- |")
            for threat in tables.topResidual {
                lines.append(
                    "| \(Markdown.cell(threat.name)) | \(Markdown.cell(threat.sourceName))"
                        + " | \(threat.riskScore) | \(threat.inherentScore) | \(threat.riskLevel) |"
                )
            }
            lines.append("")
        }

        return lines
    }
}
