/// The report's Diagrams section.
///
/// A team keeps pictures the data-flow diagram cannot draw: a sequence of a
/// login, a deployment. Each is written as a fenced block under its own
/// heading, so GitHub draws it and the HTML page shows the source of one it
/// cannot draw. A system that states none writes no section.
public enum MarkdownDiagrams {
    public static func lines(_ diagrams: [ReportDiagram]) -> [String] {
        guard diagrams.isEmpty == false else { return [] }

        var lines = ["## Diagrams", ""]
        for diagram in diagrams {
            lines.append("### \(diagram.label)")
            lines.append("")
            lines.append("```\(diagram.kind)")
            lines += diagram.text
                .split(separator: "\n", omittingEmptySubsequences: false)
                .map(String.init)
            if diagram.text.hasSuffix("\n") { lines.removeLast() }
            lines.append("```")
            lines.append("")
        }
        return lines
    }
}
