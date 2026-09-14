/// The attack tree section of the report.
///
/// It sits after the attack paths, because the walk proposes the routes and a
/// tree states the one a person confirmed.
public enum MarkdownAttackTrees {
    /// `routes` is how many routes the attack path walk found, which the
    /// section states so a reader sees how much of the graph one tree covers.
    public static func lines(_ trees: [BoundAttackTree], routes: Int) -> [String] {
        guard trees.isEmpty == false else { return [] }

        var lines: [String] = ["## Attack trees", ""]

        for tree in trees.sorted(by: { $0.score > $1.score }) {
            lines.append(heading(tree))
            lines.append("")
            if let description = tree.description {
                lines.append(description)
                lines.append("")
            }
            lines.append("Goal: \(tree.goalName) on \(tree.goalSourceName).")
            lines.append("")
            lines.append("| Step | Raised on | State | Closed by |")
            lines.append("| --- | --- | --- | --- |")
            for step in tree.steps {
                lines.append(
                    "| \(Markdown.cell(step.threatName)) | \(Markdown.cell(step.sourceName))"
                        + " | \(step.state.rawValue)"
                        + " | \(Markdown.cell(step.closedBy ?? "\u{2014}")) |"
                )
            }
            lines.append("")
        }

        lines.append(
            "This model states \(count(trees.count, "tree"))."
                + " The walk found \(count(routes, "route"))."
        )
        lines.append("")
        return lines
    }

    /// What the heading states depends on what the tree is doing.
    ///
    /// A tree whose every route is closed states so rather than a pair of
    /// scores: `BoundAttackTree.score` is the goal's score after every tree
    /// that raises it, so a closed tree sharing a goal with an open one reads
    /// the open one's number and never raised it itself.
    private static func heading(_ tree: BoundAttackTree) -> String {
        guard tree.isStale == false else {
            return "### \(tree.name) \u{2014} no longer binds"
        }
        guard tree.isOpen else {
            return "### \(tree.name) \u{2014} every route is closed"
        }
        return "### \(tree.name) \u{2014} \(tree.scoreBefore) \u{2192} \(tree.score),"
            + " chain \(tree.chainPercentage)%"
    }

    private static func count(_ number: Int, _ word: String) -> String {
        "\(number) \(word)\(number == 1 ? "" : "s")"
    }
}
