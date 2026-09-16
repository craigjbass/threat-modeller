/// The report's Policy section.
///
/// It sits after the executive summary, because a reader who reads one page
/// should see what the team enforces, not only what it failed. A project with
/// no policy file writes no section.
public enum MarkdownPolicy {
    public static func lines(_ rules: [ReportPolicyRule]) -> [String] {
        guard rules.isEmpty == false else { return [] }

        var lines = ["## Policy", ""]
        lines.append("The rules this project enforces, and whether this system keeps them.")
        lines.append("")
        lines.append("| Rule | Asks | Holds |")
        lines.append("| --- | --- | --- |")
        for rule in rules {
            lines.append(
                "| \(Markdown.cell(rule.name)) | \(Markdown.cell(rule.asks))"
                    + " | \(holds(rule)) |"
            )
        }
        lines.append("")
        return lines
    }

    private static func holds(_ rule: ReportPolicyRule) -> String {
        guard rule.breaches.isEmpty == false else { return "yes" }
        return rule.breaches.count == 1
            ? "no \u{2014} 1 breach"
            : "no \u{2014} \(rule.breaches.count) breaches"
    }
}
