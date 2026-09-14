/// Stage 8: a tree raises the score of the threat it names as its goal.
///
/// The seven stages of `ThreatResolver` run one threat at a time. This stage
/// cannot: whether a step is open depends on another threat's answers, so it
/// reads the whole resolved set and runs after `ThreatResolver.resolve()`.
///
/// The goal's own likelihood is not in the chain. Stage 6 already applies it
/// to the goal's own score, and counting it again would apply it twice.
public enum AttackTreeScoring {
    public static func apply(
        trees: [BoundAttackTree],
        to resolved: [ResolvedThreat]
    ) -> (threats: [ResolvedThreat], trees: [BoundAttackTree]) {
        guard trees.isEmpty == false else { return (resolved, trees) }

        // Two trees naming one goal give the stronger boost, not the sum.
        // Every other stage in this package follows the same rule for two
        // mitigations at one stage.
        var boostByGoal: [ThreatKey: Double] = [:]
        for tree in trees where tree.isStale == false && tree.isOpen {
            let boost = Double(tree.raisesRiskBy) / 100 * tree.chainFactor
            boostByGoal[tree.goal] = max(boostByGoal[tree.goal] ?? 0, boost)
        }

        var scoreByGoal: [ThreatKey: Int] = [:]
        let threats = resolved.map { threat -> ResolvedThreat in
            let key = ThreatKey(threatId: threat.threat.id.value, sourceId: threat.source.id)
            guard let boost = boostByGoal[key], boost > 0 else { return threat }
            let raised = raise(threat.score.value, by: boost)
            scoreByGoal[key] = raised
            return threat.withScore(RiskScore(value: raised))
        }

        let scored = trees.map { tree in
            tree.withScore(scoreByGoal[tree.goal] ?? tree.scoreBefore)
        }

        return (threats, scored)
    }

    /// The score a boost leaves, never above the top of the scale.
    static func raise(_ score: Int, by boost: Double) -> Int {
        min(RiskScore.maximum, Int((Double(score) * (1 + boost)).rounded()))
    }
}
