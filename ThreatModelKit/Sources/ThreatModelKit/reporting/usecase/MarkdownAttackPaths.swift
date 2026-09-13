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
        var lines = ["## Attack paths", ""]

        guard paths.isEmpty == false else {
            return lines + ["None.", ""]
        }

        if prefix.isEmpty == false {
            lines.append(
                "Every path below starts at "
                    + prefix.map(\.componentName).joined(separator: " \u{2192} ")
                    + "."
            )
            lines.append("")
        }

        for (index, path) in paths.enumerated() {
            var heading = "### \(index + 1). \(path.startName) \u{2192} \(path.endName)"
                + " \u{2014} worst \(path.worstScore)"
            if path.likelihoodLabel.isEmpty == false {
                heading += ", \(path.likelihoodLabel)"
            }
            lines.append(heading)
            lines.append("")
            lines.append("| Hop | Flow | Worst threat | Score | Reduced by |")
            lines.append("| --- | --- | --- | --- | --- |")
            for hop in path.hops {
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
        }
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
