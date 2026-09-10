/// A threat on a protector that nobody has answered.
public struct UnansweredProtectorThreat: Equatable, Sendable {
    public let threatId: String
    public let name: String
    public let residualScore: Int
    public let levelLabel: String

    public init(threatId: String, name: String, residualScore: Int, levelLabel: String) {
        self.threatId = threatId
        self.name = name
        self.residualScore = residualScore
        self.levelLabel = levelLabel
    }
}

/// What one protector's reductions rest on.
public struct ProtectionDependency: Equatable, Sendable {
    public let protectorId: String
    public let protectorName: String
    /// The reductions this protector gives, as "<threat id> on <component id>".
    public let protects: [String]
    public let unanswered: [UnansweredProtectorThreat]

    public init(
        protectorId: String,
        protectorName: String,
        protects: [String],
        unanswered: [UnansweredProtectorThreat]
    ) {
        self.protectorId = protectorId
        self.protectorName = protectorName
        self.protects = protects
        self.unanswered = unanswered
    }
}

/// Derives the tamper surface of every `mitigates` edge.
///
/// Spec section 6.3: the surface is reported, never scored. Scaling a
/// reduction by the protector's own residual score would invent arithmetic
/// nobody can defend in a review.
public enum ProtectionDependencies {
    /// One entry per protector, in the order the edges are declared.
    public static func derive(
        from resolved: [ResolvedThreat],
        edges: [MitigatesEdge],
        nameOf: (ComponentId) -> String
    ) -> [ProtectionDependency] {
        var order: [ComponentId] = []
        var protects: [ComponentId: [String]] = [:]

        for edge in edges {
            if protects[edge.source] == nil { order.append(edge.source) }
            protects[edge.source, default: []] += edge.threatIds.map {
                "\($0.value) on \(edge.target.value)"
            }
        }

        return order.map { protector in
            ProtectionDependency(
                protectorId: protector.value,
                protectorName: nameOf(protector),
                protects: protects[protector] ?? [],
                unanswered: unanswered(on: protector, in: resolved)
            )
        }
    }

    /// The threats raised on the protector that no control and no compensating
    /// control answers.
    private static func unanswered(
        on protector: ComponentId,
        in resolved: [ResolvedThreat]
    ) -> [UnansweredProtectorThreat] {
        resolved
            .filter { $0.source.id == "component:\(protector.value)" }
            .filter { threat in
                threat.compensating.isEmpty
                    && threat.controls.contains { $0.status.isAnswered } == false
            }
            .map {
                UnansweredProtectorThreat(
                    threatId: $0.threat.id.value,
                    name: $0.threat.name,
                    residualScore: $0.score.value,
                    levelLabel: $0.score.level.label
                )
            }
    }

    /// The sentence the assessment states for a protector carrying an
    /// unanswered threat at high or critical.
    public static func warnings(for dependencies: [ProtectionDependency]) -> [String] {
        dependencies.compactMap { dependency in
            let serious = dependency.unanswered.filter {
                $0.levelLabel == "High" || $0.levelLabel == "Critical"
            }
            guard serious.isEmpty == false else { return nil }
            return "\(dependency.protects.count) risk reductions depend on "
                + "\"\(dependency.protectorName)\", which has \(serious.count) "
                + "unanswered threats"
        }
    }
}
