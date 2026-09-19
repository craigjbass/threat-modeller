/// The report's Attack paths section.
///
/// WARNING: the walk is bounded and the narrative is curated. When it drops a
/// path the report says so and names the appendix that lists it, because a
/// silent truncation reads as full coverage.
public enum MarkdownAttackPaths {
    public static func lines(
        _ paths: [ReportAttackPath],
        prefix: [ReportAttackPathHop]
    ) -> [String] {
        guard paths.isEmpty == false else { return [] }

        var lines = ["## Attack paths", ""]

        if prefix.isEmpty == false {
            lines.append(
                "Every path below starts at "
                    + prefix.map(\.componentName).joined(separator: " \u{2192} ")
                    + "."
            )
            lines.append("")
            lines += table(of: prefix)
        }

        for (index, path) in paths.enumerated() {
            var heading = "### \(index + 1). \(route(of: path.hops))"
                + " \u{2014} worst \(path.worstScore)"
            if path.likelihoodLabel.isEmpty == false {
                heading += ", \(path.likelihoodLabel)"
            }
            lines.append(heading)
            lines.append("")
            lines += table(of: path.hops)
        }
        return lines
    }

    /// A path's name: every hop it visits after the shared prefix, in order.
    /// Two paths that share a start, an end and a worst score still read
    /// apart when their middle hops differ.
    private static func route(of hops: [ReportAttackPathHop]) -> String {
        hops.map(\.componentName).joined(separator: " \u{2192} ")
    }

    /// The five-column table a path and the shared prefix both use, so a
    /// score a heading names always has a row that shows it.
    private static func table(of hops: [ReportAttackPathHop]) -> [String] {
        var lines = ["| Hop | Flow | Worst threat | Score | Reduced by |", "| --- | --- | --- | --- | --- |"]
        for hop in hops {
            lines.append(
                "| \(Markdown.cell(hop.componentName))"
                    + " | \(Markdown.cell(hop.flowKindLabel ?? "\u{2014}"))"
                    + " | \(Markdown.cell(hop.worstThreatName ?? "none"))"
                    + " | \(hop.riskScore)"
                    + " | \(hop.reducedBy.isEmpty ? "nothing reduces this hop" : Markdown.cell(hop.reducedBy.joined(separator: ", ")))"
                    + " |"
            )
        }
        lines.append("")
        return lines
    }

    /// Appendix C: one line per path the narrative did not carry, and the
    /// count of what even this appendix does not name.
    public static func appendixLines(
        _ notListed: [ReportAttackPathSummary],
        beyond: Int
    ) -> [String] {
        guard notListed.isEmpty == false || beyond > 0 else { return [] }

        var lines = ["## Appendix C \u{2014} Attack paths not listed", ""]
        if notListed.isEmpty == false {
            lines.append(
                "The trace found \(notListed.count) further paths. Each one scores"
                    + " at or below the paths above."
            )
            lines.append("")
            for path in notListed {
                lines.append("- \(path.startName) \u{2192} \(path.endName), worst \(path.worstScore)")
            }
            lines.append("")
        }
        if beyond > 0 {
            lines.append("The trace found \(beyond) further paths this report names nowhere.")
            lines.append("")
        }
        return lines
    }
}
