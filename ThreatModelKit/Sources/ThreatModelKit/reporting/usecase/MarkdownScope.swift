/// The report's Scope section.
///
/// A reader must be able to tell a flow that was modelled and found safe from
/// a flow nobody modelled. The use cases say what the model covers, and the
/// exclusions say what it leaves out and why. A system that states neither
/// writes no section, so a reader never meets an empty heading.
public enum MarkdownScope {
    public static func lines(
        useCases: [ReportUseCase],
        exclusions: [ReportExclusion]
    ) -> [String] {
        guard useCases.isEmpty == false || exclusions.isEmpty == false else { return [] }

        var lines = ["## Scope", ""]

        if useCases.isEmpty == false {
            lines.append("### Use cases")
            lines.append("")
            for useCase in useCases {
                lines.append("- \(useCase.label): \(useCase.text)")
            }
            lines.append("")
        }

        if exclusions.isEmpty == false {
            lines.append("### Exclusions")
            lines.append("")
            for exclusion in exclusions {
                lines.append("- \(exclusion.label): \(exclusion.text)")
                lines.append("  - Rationale: \(exclusion.rationale)")
            }
            lines.append("")
        }

        return lines
    }
}
