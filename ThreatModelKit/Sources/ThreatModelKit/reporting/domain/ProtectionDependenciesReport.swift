/// Turns the assessment's protection dependencies into the report's section.
public enum ProtectionDependenciesReport {
    public static func build(_ dependencies: [ProtectionDependency]) -> [ReportProtectionDependency] {
        dependencies.map { dependency in
            ReportProtectionDependency(
                protectorName: dependency.protectorName,
                protects: dependency.protects,
                unanswered: dependency.unanswered.map {
                    ReportUnansweredThreat(
                        name: $0.name,
                        riskScore: $0.residualScore,
                        riskLevel: $0.levelLabel.lowercased()
                    )
                }
            )
        }
    }
}
