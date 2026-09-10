/// The report's Assumptions section.
///
/// A model that takes nothing on trust writes no section, so a reader never
/// meets an empty heading.
public enum MarkdownAssumptions {
    public static func lines(_ assumptions: [ReportAssumption]) -> [String] {
        guard assumptions.isEmpty == false else { return [] }

        var lines = ["## Assumptions", ""]
        for assumption in assumptions {
            var line = "- \(assumption.label): \(assumption.text)"
            if let owner = assumption.owner { line += " (\(owner))" }
            lines.append(line)
            for edge in assumption.edges {
                lines.append("  - \(edge)")
            }
        }
        lines.append("")
        return lines
    }
}
