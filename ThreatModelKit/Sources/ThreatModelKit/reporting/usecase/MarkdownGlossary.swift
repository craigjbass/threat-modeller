/// The report's Glossary section.
///
/// Every word here is one the tool uses for itself. A reader who has never
/// used the tool needs them to read the rest of the report.
public enum MarkdownGlossary {
    public static func lines() -> [String] {
        var lines = ["## Glossary", "", "| Word | What it means |", "| --- | --- |"]
        for entry in entries {
            lines.append("| \(entry.word) | \(entry.meaning) |")
        }
        lines.append("")
        return lines
    }

    /// Every word the glossary states. The Report stage draws the same
    /// list as rows, so the two cannot drift.
    public static let entries: [(word: String, meaning: String)] = [
        ("Answered", "a person has said something about the threat: a control is implemented, not applicable or accepted, or a compensating control stands"),
        ("Implemented", "the control is in place, and it lowers the score"),
        ("Not applicable", "the control does not apply here, and it leaves the share the other controls divide"),
        ("Accepted", "the team takes the risk. The threat counts as answered and the score stays where it is"),
        ("Not implemented", "nobody has answered the control. This is what a control starts as"),
        ("Compensating control", "something the team does that answers a threat the catalogue's own controls do not"),
        ("Pathway mitigation", "a reduction a component upstream gives to everything downstream of it"),
        ("Mitigates edge", "one element stated to lower a named threat on another element"),
        ("Adopted", "the mitigation is in place today"),
        ("Assumed", "the team plans the mitigation and has not put it in place. It never lowers the residual score"),
        ("Inherent score", "the score before any control lowered it"),
        ("Residual score", "the score left after every stage has run. This is the number a reader acts on"),
        ("If the assumptions hold", "the residual score with every assumed mitigation counted as in place"),
        ("Risk tolerance", "the risk level the project accepts. A likelihood finding answers a threat only at or below it"),
        ("Prior", "the likelihood the threat catalogue states before anybody finds evidence about this system"),
        ("Raised by", "what put the threat in the model: a component, a connection or a zone")
    ]
}
