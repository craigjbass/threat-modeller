/// The report's Protection dependencies section.
///
/// Spec section 6.3: what each reduction rests on. A protector carrying an
/// unanswered threat is where the whole reduction fails, and this section
/// says so rather than folding a guess into the score.
public enum MarkdownProtectionDependencies {
    public static func lines(
        _ dependencies: [ReportProtectionDependency],
        pictures: [String: String] = [:]
    ) -> [String] {
        guard dependencies.isEmpty == false else { return [] }

        var lines = ["## Protection dependencies", ""]
        for dependency in dependencies {
            lines.append("### \(dependency.protectorName)")
            lines.append("")
            if let fileName = pictures[dependency.protectorId] {
                lines.append("![What \(dependency.protectorName) protects](\(fileName))")
                lines.append("")
            }
            lines += protects(dependency)
            lines.append("")
            if dependency.unanswered.isEmpty {
                lines.append("- Nothing on this component is unanswered.")
            } else {
                for threat in dependency.unanswered {
                    lines.append(
                        "- Unanswered on this component: \(threat.name)"
                            + " (\(threat.riskLevel), \(threat.riskScore))"
                    )
                }
            }
            lines.append("")
        }
        return lines
    }

    /// What the control answers, named for a reader.
    ///
    /// The table states the element, the zone that holds it and every threat
    /// the control answers there, with the risk that is left after it. A
    /// caller that built no names gets the `protects` lines instead, which
    /// name a threat and a component by id.
    static func protects(_ dependency: ReportProtectionDependency) -> [String] {
        guard dependency.protectsElements.isEmpty == false else {
            return dependency.protects.map { "- Answers: \($0)" }
        }

        let threats = dependency.protectsElements.reduce(0) { $0 + $1.threats.count }
        let elements = dependency.protectsElements.count
        var lines = [
            "Answers \(threats) \(threats == 1 ? "threat" : "threats")"
                + " on \(elements) \(elements == 1 ? "element" : "elements")."
                + " Every risk below is what is left after this control.",
            "",
            "| Element | Zone | Threats answered, with the risk left |",
            "| --- | --- | --- |"
        ]

        for element in dependency.protectsElements {
            lines.append(
                "| \(Markdown.cell(element.elementName))"
                    + " | \(Markdown.cell(element.zoneName ?? "\u{2014}"))"
                    + " | \(Markdown.cell(risks(element.threats)))"
                    + " |"
            )
        }

        return lines
    }

    /// Each answered threat with the risk left on it. The risk sits beside
    /// the name it belongs to, because a second column of levels leaves the
    /// reader pairing two lists by position.
    static func risks(_ threats: [ReportAnsweredThreat]) -> String {
        threats
            .map { "\($0.name) (\($0.riskLevel) \($0.riskScore))" }
            .joined(separator: ", ")
    }
}
