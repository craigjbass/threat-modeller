/// The report's Protection dependencies section.
///
/// Spec section 6.3: what each reduction rests on. A protector carrying an
/// unanswered threat is where the whole reduction fails, and this section
/// says so rather than folding a guess into the score.
public enum MarkdownProtectionDependencies {
    public static func lines(_ dependencies: [ReportProtectionDependency]) -> [String] {
        guard dependencies.isEmpty == false else { return [] }

        var lines = ["## Protection dependencies", ""]
        for dependency in dependencies {
            lines.append("### \(dependency.protectorName)")
            lines.append("")
            for answered in dependency.protects {
                lines.append("- Answers: \(answered)")
            }
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
}
