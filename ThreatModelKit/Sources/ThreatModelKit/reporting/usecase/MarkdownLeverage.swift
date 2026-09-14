/// The report's "What removes the most risk" section.
///
/// WARNING: the numbers here do not add. Each action is measured alone against
/// today's posture, and the section says so beside them, because a reader who
/// totals the top rows plans against a number the model never produced.
public enum MarkdownLeverage {
    public static func lines(_ actions: [ReportAction]) -> [String] {
        guard actions.isEmpty == false else { return [] }

        var lines = ["## What removes the most risk", ""]
        lines.append(
            "Each action is measured on its own against today's posture. Two"
                + " actions that answer one threat do not remove the sum of"
                + " their leverage: the stronger reduction wins, never the sum."
        )
        lines.append("")
        lines.append("| Action | Removes | Threats moved | Worst | Blocked by |")
        lines.append("| --- | --- | --- | --- | --- |")
        for action in actions {
            let removes = action.removes == 0
                ? "removes nothing at today's posture"
                : "\(action.removes) of \(action.totalResidual)"
            lines.append(
                "| \(Markdown.cell(action.text))"
                    + " | \(removes)"
                    + " | \(action.threatsMoved)"
                    + " | \(action.worstBefore) → \(action.worstAfter)"
                    + " | \(Markdown.cell(action.blockedBy ?? "—"))"
                    + " |"
            )
        }
        lines.append("")

        let annotated = actions.filter {
            $0.note != nil || $0.sources.isEmpty == false || $0.governance != nil
        }
        if annotated.isEmpty == false {
            for action in annotated {
                lines.append("- \(action.text)")
                if let note = action.note {
                    lines.append("  - \(note)")
                }
                if let governance = action.governance {
                    lines.append("  - \(governance)")
                }
                lines += Markdown.sourceLines(action.sources)
            }
            lines.append("")
        }
        return lines
    }
}
