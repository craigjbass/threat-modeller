/// The report's Threat actors section.
///
/// A model that faces nobody writes no section, because a heading with an
/// empty table says less than no heading at all.
public enum MarkdownThreatActors {
    public static func lines(_ actors: [ReportThreatActor]) -> [String] {
        guard actors.isEmpty == false else { return [] }

        var lines = ["## Threat actors", ""]
        lines.append(
            "This assessment is written against these threat actors. A threat no actor here "
                + "performs keeps the catalogue's own likelihood."
        )
        lines.append("")
        lines.append("| Actor | Capability | Intent | Threats performed |")
        lines.append("| --- | --- | --- | --- |")
        for actor in actors {
            lines.append(
                "| \(Markdown.cell(actor.name)) | \(actor.capabilityLabel)"
                    + " | \(Markdown.cell(capitalised(actor.intent)))"
                    + " | \(actor.threatsPerformed) |"
            )
        }
        lines.append("")
        return lines
    }

    /// The intent as a file states it, with the first letter in upper case, so
    /// a table column reads as a label rather than as a keyword.
    private static func capitalised(_ text: String) -> String {
        guard let first = text.first else { return text }
        return first.uppercased() + text.dropFirst()
    }
}
