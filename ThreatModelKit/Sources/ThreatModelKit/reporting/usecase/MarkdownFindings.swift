/// The report's Findings section: what a reader must act on.
///
/// WARNING: the cut is bounded. When it drops a qualifying threat the section
/// says so and names where the rest are, because a silent truncation reads as
/// full coverage.
public enum MarkdownFindings {
    public static func lines(_ cut: ReportFindingsCut, toleranceLabel: String) -> [String] {
        var lines = ["## Findings", ""]

        guard cut.above.isEmpty == false else {
            lines.append("No threat sits above the project's \(toleranceLabel) risk tolerance.")
            lines.append("")
            return lines
        }

        var opening = "Every threat above the project's \(toleranceLabel) risk tolerance."
        if cut.notShown > 0 {
            opening += " \(cut.notShown) more qualify and are in Appendix A."
        }
        lines.append(opening)
        lines.append("")

        for threat in cut.above {
            lines += MarkdownThreatStanza.lines(threat)
        }
        return lines
    }
}
