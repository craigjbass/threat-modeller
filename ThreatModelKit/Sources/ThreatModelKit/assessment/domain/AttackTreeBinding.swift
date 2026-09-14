/// Matches the trees a person wrote against the threats the model raises.
///
/// A step binds when the resolved model raises that threat on that source. One
/// step that does not bind makes the whole tree stale, because a route with a
/// step missing is a claim about a system that is no longer there.
public enum AttackTreeBinding {
    /// What a node is doing: whether an attacker can still walk it, and the
    /// factor the node rules give it.
    private struct NodeState {
        let isOpen: Bool
        let factor: Double
    }

    public static func bind(
        trees: [SourceAttackTree],
        to resolved: [ResolvedThreat]
    ) -> [BoundAttackTree] {
        var byKey: [ThreatKey: ResolvedThreat] = [:]
        for threat in resolved {
            byKey[ThreatKey(threatId: threat.threat.id.value, sourceId: threat.source.id)] = threat
        }

        return trees.map { tree in
            let steps = tree.steps.map { self.step($0, in: byKey) }
            let goal = byKey[tree.goal.key]
            let isStale = goal == nil || steps.contains { $0.state == .unbound }

            let root = isStale
                ? NodeState(isOpen: false, factor: 0)
                : state(of: tree.root, in: byKey)

            let scoreBefore = goal?.score.value ?? 0

            return BoundAttackTree(
                id: tree.id,
                name: tree.displayName,
                description: tree.description,
                raisesRiskBy: tree.raisesRiskBy,
                goal: tree.goal.key,
                goalName: goal?.threat.name ?? tree.goal.threatId,
                goalSourceName: goal?.source.displayName ?? tree.goal.sourceId,
                steps: steps,
                chainFactor: root.isOpen ? root.factor : 0,
                isOpen: root.isOpen,
                isStale: isStale,
                scoreBefore: scoreBefore,
                score: scoreBefore
            )
        }
    }

    private static func step(
        _ step: SourceTreeStep,
        in byKey: [ThreatKey: ResolvedThreat]
    ) -> BoundStep {
        let key = step.target.key
        guard let threat = byKey[key] else {
            return BoundStep(
                key: key,
                threatName: step.target.threatId,
                sourceName: step.target.sourceId,
                state: .unbound,
                factor: 0,
                note: step.note
            )
        }

        // An implemented control or a compensating control closes a step.
        // `not_applicable` and `accepted` answer the threat and close nothing:
        // a control that does not apply stops nobody, and a team that accepts
        // a risk still lets an attacker take the step.
        let closingControl = threat.controls.first { $0.status == .implemented }
        let isClosed = closingControl != nil || threat.compensating.isEmpty == false

        return BoundStep(
            key: key,
            threatName: threat.threat.name,
            sourceName: threat.source.displayName,
            state: isClosed ? .closed : .open,
            closedBy: closingControl?.description ?? threat.compensating.first?.label,
            factor: threat.likelihood.factor,
            note: step.note
        )
    }

    private static func state(
        of node: SourceTreeNode,
        in byKey: [ThreatKey: ResolvedThreat]
    ) -> NodeState {
        switch node {
        case .step(let step):
            let bound = self.step(step, in: byKey)
            return NodeState(isOpen: bound.state == .open, factor: bound.factor)

        case .all(let children):
            let states = children.map { state(of: $0, in: byKey) }
            // Every child is needed, so the chain is as likely as its weakest
            // one, and one closed child closes the branch.
            return NodeState(
                isOpen: states.allSatisfy(\.isOpen),
                factor: states.map(\.factor).min() ?? 0
            )

        case .any(let children):
            let states = children.map { state(of: $0, in: byKey) }
            let open = states.filter(\.isOpen)
            // An attacker takes the easiest branch that is still open.
            return NodeState(
                isOpen: open.isEmpty == false,
                factor: open.map(\.factor).max() ?? 0
            )
        }
    }
}
