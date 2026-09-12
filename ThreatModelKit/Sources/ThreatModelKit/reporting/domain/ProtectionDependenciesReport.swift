import Foundation

/// Turns the assessment's protection dependencies into the report's section.
public enum ProtectionDependenciesReport {
    public static func build(
        _ dependencies: [ProtectionDependency],
        threats: [ReportThreat] = [],
        zones: [ReportZone] = [],
        nameOfComponent: (String) -> String = { $0 }
    ) -> [ReportProtectionDependency] {
        let zoneOf = Dictionary(
            zones.flatMap { zone in zone.componentIds.map { ($0, zone.name) } },
            uniquingKeysWith: { first, _ in first }
        )
        let byKey = Dictionary(
            threats.map { (("\($0.threatId)@\($0.sourceId)"), $0) },
            uniquingKeysWith: { first, _ in first }
        )

        return dependencies.map { dependency in
            let named = elements(
                of: dependency.protects,
                zoneOf: zoneOf,
                byKey: byKey,
                nameOfComponent: nameOfComponent
            )
            return ReportProtectionDependency(
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
                // The count comes from what the table states, so a picture
                // and the table beneath it never state different totals. A
                // reduction naming a threat the report does not carry is in
                // neither.
                answeredByElementId: named.isEmpty
                    ? countByElement(dependency.protects)
                    : Dictionary(
                        uniqueKeysWithValues: named.map { ($0.elementId, $0.threats.count) }
                    ),
                protectsElements: named
            )
        }
    }

    /// What the protector answers, grouped by the component it answers it on,
    /// in the order the reductions are stated.
    ///
    /// A reduction whose threat the report does not carry is left out: the
    /// assessment states edges that name a threat never raised on the target,
    /// and a table row naming a threat nobody can look up says nothing.
    static func elements(
        of protects: [String],
        zoneOf: [String: String],
        byKey: [String: ReportThreat],
        nameOfComponent: (String) -> String
    ) -> [ReportProtectedElement] {
        var order: [String] = []
        var answered: [String: [ReportAnsweredThreat]] = [:]

        for line in protects {
            guard let at = line.range(of: " on ", options: .backwards) else { continue }
            let threatId = String(line[line.startIndex ..< at.lowerBound])
            let elementId = String(line[at.upperBound...])
            guard let threat = byKey["\(threatId)@component:\(elementId)"] else { continue }

            if answered[elementId] == nil {
                order.append(elementId)
                answered[elementId] = []
            }
            answered[elementId]?.append(
                ReportAnsweredThreat(
                    threatId: threatId,
                    name: threat.name,
                    riskScore: threat.riskScore,
                    riskLevel: threat.riskLevel
                )
            )
        }

        return order.map { elementId in
            ReportProtectedElement(
                elementId: elementId,
                elementName: nameOfComponent(elementId),
                zoneName: zoneOf[elementId],
                threats: answered[elementId] ?? []
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
