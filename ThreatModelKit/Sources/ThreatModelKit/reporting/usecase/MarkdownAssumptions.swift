/// The report's Assumptions section.
///
/// A model that takes nothing on trust and assumes no mitigation writes no
/// section, so a reader never meets an empty heading. An assumed `mitigates`
/// edge names no assumption, so the section lists assumptions and assumed
/// edges as two separate parts rather than nesting one inside the other.
public enum MarkdownAssumptions {
    public static func lines(
        assumptions: [ReportAssumption],
        assumedMitigations: [ReportAssumedMitigation]
    ) -> [String] {
        guard assumptions.isEmpty == false || assumedMitigations.isEmpty == false else {
            return []
        }

        var lines = ["## Assumptions", ""]
        for assumption in assumptions {
            var line = "- \(assumption.label): \(assumption.text)"
            if let owner = assumption.owner { line += " (\(owner))" }
            lines.append(line)
        }

        if assumedMitigations.isEmpty == false {
            if assumptions.isEmpty == false { lines.append("") }
            lines.append("### Assumed mitigations")
            lines.append("")
            for mitigation in assumedMitigations {
                lines.append(
                    "- \(mitigation.protectorName) \u{2192} \(mitigation.protectedName),"
                        + " mitigates \(mitigation.threatIds.joined(separator: ", ")),"
                        + " \u{2212}\(mitigation.reducesRiskBy)%"
                )
            }
        }

        lines.append("")
        return lines
    }
}
