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
            lines += sufficientControls(of: tree)
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
            lines += chains(of: tree)
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
        if let closedBy = tree.closedBy {
            return "### \(tree.name) \u{2014} closed by \(closedBy)"
        }
        guard tree.isOpen else {
            return "### \(tree.name) \u{2014} every route is closed"
        }
        return "### \(tree.name) \u{2014} \(tree.scoreBefore) \u{2192} \(tree.score),"
            + " chain \(tree.chainPercentage)%"
    }

    /// Every chain of the tree as an ordered route, one line per link with
    /// its position. A tree of branches alone prints nothing here: the table
    /// above already holds it.
    private static func chains(of tree: BoundAttackTree) -> [String] {
        let numbers = Array(Set(tree.steps.compactMap(\.chain))).sorted()
        guard numbers.isEmpty == false else { return [] }

        var lines: [String] = []
        for number in numbers {
            let links = tree.steps.filter { $0.chain == number }
            lines.append(numbers.count == 1 ? "The chain, in order:" : "Chain \(number), in order:")
            lines.append("")
            let positions = Array(Set(links.compactMap(\.position))).sorted()
            for position in positions {
                // The steps of a branch that is one link share its position
                // and print on one line.
                let said = links
                    .filter { $0.position == position }
                    .map { link -> String in
                        var line = "\(link.threatName) on \(link.sourceName), \(link.state.rawValue)"
                        if let closedBy = link.closedBy { line += " by \(closedBy)" }
                        return line
                    }
                    .joined(separator: "; ")
                lines.append("\(position). \(said)")
            }
            lines.append("")
        }
        return lines
    }

    /// The controls the file names as each sufficient to close the whole
    /// route, one per line with what each is doing. Nothing for a tree that
    /// names none.
    private static func sufficientControls(of tree: BoundAttackTree) -> [String] {
        guard tree.sufficientControls.isEmpty == false else { return [] }
        var lines = ["Sufficient controls:", ""]
        for control in tree.sufficientControls {
            lines.append("- \(control.description): \(said(control.state))")
        }
        lines.append("")
        return lines
    }

    /// What each state of a sufficient control reads as in the report.
    public static func said(_ state: SufficientControlState) -> String {
        switch state {
        case .closes: "closes the tree"
        case .open: "not implemented"
        case .unevidenced: "implemented with no evidence"
        case .unknown: "not a control the catalogue or the libraries hold"
        }
    }

    private static func count(_ number: Int, _ word: String) -> String {
        "\(number) \(word)\(number == 1 ? "" : "s")"
    }
}
