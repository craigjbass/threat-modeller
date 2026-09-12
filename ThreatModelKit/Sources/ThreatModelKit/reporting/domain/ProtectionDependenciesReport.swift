import Foundation

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
                },
                protectorId: dependency.protectorId,
                answeredByElementId: countByElement(dependency.protects)
            )
        }
    }

    /// How many reductions each component gets, read from the
    /// "<threat id> on <component id>" lines the assessment states.
    static func countByElement(_ protects: [String]) -> [String: Int] {
        var counted: [String: Int] = [:]
        for line in protects {
            guard let at = line.range(of: " on ", options: .backwards) else { continue }
            let id = String(line[at.upperBound...])
            counted[id, default: 0] += 1
        }
        return counted
    }
}
