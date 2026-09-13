/// The report's Methodology section, and the legend for its pictures.
///
/// The stages are written in the order `ThreatResolver` runs them, so a reader
/// can follow one threat through the arithmetic from end to end.
public enum MarkdownMethodology {
    public static func lines(_ methodology: ReportMethodology) -> [String] {
        var lines = ["## Methodology", ""]

        lines.append(
            "A threat's base score is its severity rank multiplied by the data"
                + " sensitivity rank of what it puts at risk, from 1 to"
                + " \(ReportMethodology.highestScore)."
        )
        lines.append("")

        lines.append("| Level | Lowest score | Highest score |")
        lines.append("| --- | --- | --- |")
        for threshold in methodology.levelThresholds {
            lines.append("| \(threshold.label) | \(threshold.lowest) | \(threshold.highest) |")
        }
        lines.append("")

        lines.append("The stages run in this order, and each one takes the score the one before it left.")
        lines.append("")

        for zone in methodology.zoneReductions {
            lines.append("1. \(Markdown.cell(zone.label)) reduces the risk of what it holds by \(zone.count)%.")
        }
        if methodology.zoneReductions.isEmpty == false {
            lines.append(
                "   A flow between two private zones takes the smaller of the two reductions."
            )
        }

        lines.append(
            "1. The implemented controls take off their share of the score,"
                + " capped at \(methodology.controlCapPercent)%. The share is the"
                + " implemented controls divided by the applicable ones, and a"
                + " control marked not applicable leaves the divisor. A control"
                + " marked accepted stays in the divisor and lowers nothing."
        )
        lines.append(
            "1. A pathway mitigation and a `mitigates` edge each take off the"
                + " percentage they state. Two that answer one threat give the"
                + " stronger reduction, never the sum."
        )
        if methodology.likelihoodTiers.isEmpty == false {
            let tiers = methodology.likelihoodTiers
                .map { "\($0.label) \($0.count)%" }
                .joined(separator: ", ")
            lines.append(
                "1. The likelihood multiplies the score: \(tiers), or the"
                    + " percentage a finding states."
            )
        }
        lines.append(
            "1. A compensating control multiplies the score by the reduction it"
                + " states. Two give the stronger reduction, never the sum."
        )
        lines.append("1. A score never falls below 1.")
        lines.append("")

        lines.append(
            "The project's risk tolerance is \(methodology.toleranceLabel)."
                + " A likelihood finding answers a threat only when the threat"
                + " sits at or below that level."
        )
        lines.append(
            "\"If the assumptions hold\" is the same arithmetic with every"
                + " assumed `mitigates` edge counted as in place."
        )
        lines.append("")

        lines += legend()
        return lines
    }

    /// Fixed text. Every row states what the drawing code does, not what a
    /// reader might expect it to do.
    private static func legend() -> [String] {
        [
            "### Diagram legend",
            "",
            "| Mark | Meaning |",
            "| --- | --- |",
            "| Red, orange, yellow, green | Critical, High, Medium, Low |",
            "| Dashed tinted box | a zone, green if private, orange otherwise |",
            "| Purple dashed line | a control protecting an element; it carries no data |",
            "| Purple badge on that line | how many threats the control answers on the component at the other end |",
            "| Grey chip | a boundary crossing with no guard, and a threat still open there |",
            "| Dashed guard marker | a guard the model assumes rather than adopts |",
            "| Thicker stroke | the element the picture is about |",
            "| Badge on a component | how many threats are still open on that component |",
            "| Arrowhead | the direction the data flows |",
            ""
        ]
    }
}
