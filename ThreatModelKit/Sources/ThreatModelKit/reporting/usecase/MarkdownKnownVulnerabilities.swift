/// The report's Known vulnerabilities section.
///
/// One row per CVE per component, ordered by priority and then by CVE id,
/// with the thresholds the rows were ranked by stated above the table. A
/// system whose components state no CVE writes no section.
public enum MarkdownKnownVulnerabilities {
    public static func lines(
        _ rows: [ReportKnownVulnerability],
        thresholds: VulnerabilityPriority.Thresholds
    ) -> [String] {
        guard rows.isEmpty == false else { return [] }

        var lines = ["## Known vulnerabilities", ""]
        lines.append(
            "The CVEs this system's components state, ranked by the CVE_Prioritizer rule with "
                + "\(thresholds.described). A known exploited vulnerability raises every threat "
                + "on its component to Commodity."
        )
        lines.append("")
        lines.append("| CVE | Component | Version | CVSS | EPSS | KEV | Priority |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for row in ordered(rows) {
            lines.append(
                "| [\(row.cveId)](\(CveId.address(of: row.cveId)))"
                    + " | \(Markdown.cell(row.componentName))"
                    + " | \(Markdown.cell(row.version.isEmpty ? "\u{2014}" : row.version))"
                    + " | \(number(row.cvss, digits: 1, held: row.isSynchronised))"
                    + " | \(number(row.epss, digits: 2, held: row.isSynchronised))"
                    + " | \(row.isSynchronised ? (row.isKnownExploited ? "Yes" : "No") : "\u{2014}")"
                    + " | \(row.priorityLabel ?? "not synchronised")"
                    + " |"
            )
        }
        lines.append("")
        return lines
    }

    /// By priority, `1+` first and an unsynchronised CVE last, then by id.
    public static func ordered(_ rows: [ReportKnownVulnerability]) -> [ReportKnownVulnerability] {
        rows.sorted { left, right in
            let leftRank = rank(left.priorityLabel)
            let rightRank = rank(right.priorityLabel)
            if leftRank != rightRank { return leftRank < rightRank }
            if left.cveId != right.cveId { return left.cveId < right.cveId }
            return left.componentName < right.componentName
        }
    }

    private static func rank(_ label: String?) -> Int {
        switch label {
        case "1+": 0
        case "1": 1
        case "2": 2
        case "3": 3
        case "4": 4
        default: 5
        }
    }

    private static func number(_ value: Double?, digits: Int, held: Bool) -> String {
        guard held, let value else { return "\u{2014}" }
        return String(format: "%.\(digits)f", value)
    }
}
