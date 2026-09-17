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

    /// `known` is every control description the catalogue and the libraries
    /// hold; nil reads the descriptions the resolved threats offer. A
    /// description is compared by its fingerprint, the identity the
    /// `.controls` file already uses. `proofs` and `evidenceDemandedAbove` are what the sufficient
    /// control rule reads for evidence.
    public static func bind(
        trees: [SourceAttackTree],
        to resolved: [ResolvedThreat],
        known: Set<String>? = nil,
        proofs: [ControlKey: ControlProof] = [:],
        evidenceDemandedAbove: RiskLevel? = nil
    ) -> [BoundAttackTree] {
        var byKey: [ThreatKey: ResolvedThreat] = [:]
        for threat in resolved {
            byKey[ThreatKey(threatId: threat.threat.id.value, sourceId: threat.source.id)] = threat
        }
        let knownDescriptions = known.map(Array.init) ?? resolved.flatMap(\.controls).map(\.description)
        let knownControls = Set(knownDescriptions.map { ControlIdentity.fingerprint(of: $0) })

        return trees.map { tree in
            var chains = 0
            let steps = links(of: tree.root, in: byKey, chain: nil, counting: &chains)
            let goal = byKey[tree.goal.key]
            let sufficient = tree.closedBy.map { description in
                sufficientControl(
                    description,
                    goal: goal,
                    in: resolved,
                    known: knownControls,
                    proofs: proofs,
                    evidenceDemandedAbove: evidenceDemandedAbove
                )
            }
            let isStale = goal == nil
                || steps.contains { $0.state == .unbound }
                || sufficient.contains { $0.state == .unknown }
            let closedBy = isStale ? nil : sufficient.first { $0.state == .closes }?.description

            // A sufficient control that closes the tree closes it as a whole:
            // the steps keep their own states, and the root gives nothing.
            let root = isStale || closedBy != nil
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
                score: scoreBefore,
                sufficientControls: sufficient,
                closedBy: closedBy
            )
        }
    }

    /// One control the tree names as sufficient, read against every answer
    /// the model holds for that description.
    ///
    /// The control is implemented for the tree when at least one answer
    /// remains after the `not_applicable` answers are set aside, and every
    /// answer that remains is `implemented`: a control in place on one
    /// element and not on another is not in place. The evidence demand is
    /// judged at the goal's level before its controls, because the goal is
    /// what the tree closes.
    private static func sufficientControl(
        _ description: String,
        goal: ResolvedThreat?,
        in resolved: [ResolvedThreat],
        known: Set<String>,
        proofs: [ControlKey: ControlProof],
        evidenceDemandedAbove: RiskLevel?
    ) -> BoundSufficientControl {
        let fingerprint = ControlIdentity.fingerprint(of: description)
        guard known.contains(fingerprint) else {
            return BoundSufficientControl(description: description, state: .unknown)
        }

        let answers = resolved
            .flatMap(\.controls)
            .filter { ControlIdentity.fingerprint(of: $0.description) == fingerprint }
            .filter { $0.status != .notApplicable }
        guard answers.isEmpty == false, answers.allSatisfy({ $0.status == .implemented }) else {
            return BoundSufficientControl(description: description, state: .open)
        }

        if let level = evidenceDemandedAbove, let goal,
           RiskScore(value: goal.scoreBeforeControls).level.rank >= level.rank,
           answers.contains(where: { proofs[$0.key]?.evidence == nil }) {
            return BoundSufficientControl(description: description, state: .unevidenced)
        }
        return BoundSufficientControl(description: description, state: .closes)
    }

    /// Every step of a node in file order, each one told which chain it is
    /// a link of and where. A `then` numbers a new chain and hands each link
    /// its position; a branch hands its children the link it sits in, so a
    /// nested chain wins over the one around it.
    private static func links(
        of node: SourceTreeNode,
        in byKey: [ThreatKey: ResolvedThreat],
        chain: (number: Int, position: Int)?,
        counting chains: inout Int
    ) -> [BoundStep] {
        switch node {
        case .step(let step):
            return [self.step(step, in: byKey, chain: chain?.number, position: chain?.position)]
        case .all(let children), .any(let children):
            return children.flatMap { links(of: $0, in: byKey, chain: chain, counting: &chains) }
        case .then(let chainLinks):
            chains += 1
            let number = chains
            var steps: [BoundStep] = []
            for (index, link) in chainLinks.enumerated() {
                steps += links(
                    of: link,
                    in: byKey,
                    chain: (number: number, position: index + 1),
                    counting: &chains
                )
            }
            return steps
        }
    }

    private static func step(
        _ step: SourceTreeStep,
        in byKey: [ThreatKey: ResolvedThreat],
        chain: Int? = nil,
        position: Int? = nil
    ) -> BoundStep {
        let key = step.target.key
        guard let threat = byKey[key] else {
            return BoundStep(
                key: key,
                threatName: step.target.threatId,
                sourceName: step.target.sourceId,
                state: .unbound,
                factor: 0,
                note: step.note,
                chain: chain,
                position: position
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
            note: step.note,
            chain: chain,
            position: position
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

        case .all(let children), .then(let children):
            let states = children.map { state(of: $0, in: byKey) }
            // Every child is needed, so the branch is as likely as its weakest
            // one, and one closed child closes it. A chain reads the same
            // way: a closed link stops the attacker before the next one, and
            // the order changes no number.
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
