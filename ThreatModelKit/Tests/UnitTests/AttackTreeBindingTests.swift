import Testing
import ThreatModelKit
import TestSupport

@Suite("Binding an attack tree to a resolved model")
struct AttackTreeBindingTests {
    private func resolved(
        _ threatId: String,
        _ componentId: String,
        score: Int = 8,
        statuses: [ControlStatus] = [.notImplemented],
        compensating: [CompensatingControl] = [],
        likelihood: Likelihood = .commodity
    ) -> ResolvedThreat {
        ResolvedThreatFixture.make(
            threatId: threatId,
            componentId: componentId,
            score: score,
            statuses: statuses,
            compensating: compensating,
            likelihood: likelihood
        )
    }

    private func target(_ threatId: String, _ componentId: String) -> SourceTreeTarget {
        SourceTreeTarget(threatId: threatId, sourceKind: "component", sourceId: componentId)
    }

    private func tree(
        raises: Int = 40,
        goal: SourceTreeTarget,
        root: SourceTreeNode
    ) -> SourceAttackTree {
        SourceAttackTree(id: "t", raisesRiskBy: raises, goal: goal, root: root)
    }

    private func step(_ threatId: String, _ componentId: String) -> SourceTreeNode {
        .step(SourceTreeStep(target: target(threatId, componentId)))
    }

    @Test func bindsAStepTheModelRaises() throws {
        let bound = AttackTreeBinding.bind(
            trees: [tree(goal: target("g", "db"), root: step("a", "api"))],
            to: [resolved("g", "db"), resolved("a", "api")]
        )

        let first = try #require(bound.first)
        #expect(first.isStale == false)
        #expect(first.steps.map(\.state) == [.open])
    }

    @Test func makesTheWholeTreeStaleWhenOneStepDoesNotBind() throws {
        let bound = AttackTreeBinding.bind(
            trees: [tree(goal: target("g", "db"), root: .all([step("a", "api"), step("b", "gone")]))],
            to: [resolved("g", "db"), resolved("a", "api")]
        )

        let first = try #require(bound.first)
        #expect(first.isStale)
        #expect(first.steps.map(\.state) == [.open, .unbound])
        #expect(first.chainFactor == 0)
        #expect(first.isOpen == false)
        #expect(first.scoreBefore == 8)
        #expect(first.score == first.scoreBefore)
    }

    @Test func makesTheWholeTreeStaleWhenTheGoalDoesNotBind() throws {
        let bound = AttackTreeBinding.bind(
            trees: [tree(goal: target("g", "gone"), root: step("a", "api"))],
            to: [resolved("a", "api")]
        )

        #expect(try #require(bound.first).isStale)
    }

    @Test(arguments: [
        (ControlStatus.implemented, StepState.closed),
        (ControlStatus.notApplicable, StepState.open),
        (ControlStatus.accepted, StepState.open),
        (ControlStatus.notImplemented, StepState.open),
    ])
    func readsAStatusAsAState(status: ControlStatus, state: StepState) throws {
        let bound = AttackTreeBinding.bind(
            trees: [tree(goal: target("g", "db"), root: step("a", "api"))],
            to: [resolved("g", "db"), resolved("a", "api", statuses: [status])]
        )

        #expect(try #require(bound.first).steps.map(\.state) == [state])
    }

    @Test func closesAStepACompensatingControlAnswers() throws {
        let bound = AttackTreeBinding.bind(
            trees: [tree(goal: target("g", "db"), root: step("a", "api"))],
            to: [
                resolved("g", "db"),
                resolved("a", "api", compensating: [
                    CompensatingControl(label: "A break-glass account", reducesRiskBy: 40, rationale: "It alerts."),
                ]),
            ]
        )

        #expect(try #require(bound.first).steps.map(\.state) == [.closed])
    }

    @Test func closesAnAllOfWhenOneChildIsClosed() throws {
        let bound = AttackTreeBinding.bind(
            trees: [tree(goal: target("g", "db"), root: .all([step("a", "api"), step("b", "api")]))],
            to: [
                resolved("g", "db"),
                resolved("a", "api"),
                resolved("b", "api", statuses: [.implemented]),
            ]
        )

        #expect(try #require(bound.first).isOpen == false)
    }

    @Test func keepsAnAnyOfOpenWhileOneChildIsOpen() throws {
        let bound = AttackTreeBinding.bind(
            trees: [tree(goal: target("g", "db"), root: .any([step("a", "api"), step("b", "api")]))],
            to: [
                resolved("g", "db"),
                resolved("a", "api"),
                resolved("b", "api", statuses: [.implemented]),
            ]
        )

        #expect(try #require(bound.first).isOpen)
    }

    @Test func takesTheWeakestChildOfAnAllOf() throws {
        let bound = AttackTreeBinding.bind(
            trees: [tree(goal: target("g", "db"), root: .all([step("a", "api"), step("b", "api")]))],
            to: [
                resolved("g", "db"),
                resolved("a", "api", likelihood: .commodity),
                resolved("b", "api", likelihood: .research),
            ]
        )

        #expect(try #require(bound.first).chainFactor == 0.25)
    }

    @Test func takesTheStrongestOpenChildOfAnAnyOf() throws {
        let bound = AttackTreeBinding.bind(
            trees: [tree(goal: target("g", "db"), root: .any([step("a", "api"), step("b", "api")]))],
            to: [
                resolved("g", "db"),
                resolved("a", "api", likelihood: .targeted),
                resolved("b", "api", likelihood: .research),
            ]
        )

        #expect(try #require(bound.first).chainFactor == 0.6)
    }

    @Test func ignoresAClosedChildsFactorInAnAnyOf() throws {
        let bound = AttackTreeBinding.bind(
            trees: [tree(goal: target("g", "db"), root: .any([step("a", "api"), step("b", "api")]))],
            to: [
                resolved("g", "db"),
                resolved("a", "api", statuses: [.implemented], likelihood: .commodity),
                resolved("b", "api", likelihood: .research),
            ]
        )

        #expect(try #require(bound.first).chainFactor == 0.25)
    }
    // MARK: the controls that are sufficient to close the whole route

    private func closed(
        by controls: [String],
        answers: [(threat: String, status: ControlStatus)],
        known: Set<String>? = nil,
        proofs: [ControlKey: ControlProof] = [:],
        evidenceDemandedAbove: RiskLevel? = nil
    ) throws -> BoundAttackTree {
        let tree = SourceAttackTree(
            id: "t",
            raisesRiskBy: 40,
            closedBy: controls,
            goal: target("g", "db"),
            root: step("a", "api")
        )
        var threats = [resolved("g", "db"), resolved("a", "api")]
        threats += answers.enumerated().map { index, answer in
            ResolvedThreatFixture.make(
                threatId: answer.threat, componentId: "n\(index)", score: 4,
                statuses: [answer.status], compensating: [], likelihood: .commodity,
                descriptions: ["Segment the network"]
            )
        }
        return try #require(AttackTreeBinding.bind(
            trees: [tree],
            to: threats,
            known: known,
            proofs: proofs,
            evidenceDemandedAbove: evidenceDemandedAbove
        ).first)
    }

    @Test func closesTheWholeTreeWhenEveryAnswerForTheControlIsImplemented() throws {
        let bound = try closed(
            by: ["Segment the network"],
            answers: [("x", .implemented), ("y", .implemented)]
        )

        #expect(bound.closedBy == "Segment the network")
        #expect(bound.isOpen == false)
        #expect(bound.chainFactor == 0)
        #expect(bound.sufficientControls.map(\.state) == [.closes])
    }

    @Test func leavesTheTreeOpenWhenOneAnswerForTheControlIsNotImplemented() throws {
        let bound = try closed(
            by: ["Segment the network"],
            answers: [("x", .implemented), ("y", .notImplemented)]
        )

        #expect(bound.closedBy == nil)
        #expect(bound.isOpen)
        #expect(bound.sufficientControls.map(\.state) == [.open])
    }

    @Test func setsANotApplicableAnswerAside() throws {
        let bound = try closed(
            by: ["Segment the network"],
            answers: [("x", .implemented), ("y", .notApplicable)]
        )

        #expect(bound.closedBy == "Segment the network")
    }

    @Test func leavesTheTreeOpenWhenEveryAnswerIsNotApplicable() throws {
        let bound = try closed(by: ["Segment the network"], answers: [("x", .notApplicable)])

        #expect(bound.closedBy == nil)
        #expect(bound.sufficientControls.map(\.state) == [.open])
    }

    @Test func leavesTheTreeOpenWhenNothingAnswersTheControl() throws {
        let bound = try closed(by: ["Segment the network"], answers: [], known: ["Segment the network"])

        #expect(bound.isStale == false)
        #expect(bound.closedBy == nil)
        #expect(bound.sufficientControls.map(\.state) == [.open])
    }

    @Test func namesTheFirstControlThatClosesTheTree() throws {
        let bound = try closed(
            by: ["Alert on the route", "Segment the network"],
            answers: [("x", .implemented)],
            known: ["Alert on the route", "Segment the network"]
        )

        #expect(bound.closedBy == "Segment the network")
        #expect(bound.sufficientControls.map(\.state) == [.open, .closes])
    }

    /// The goal scores 8, which is high. A demand at high with no tier on
    /// the answer leaves the tree open.
    @Test func leavesTheTreeOpenWhenTheDemandedEvidenceIsMissing() throws {
        let bound = try closed(
            by: ["Segment the network"],
            answers: [("x", .implemented)],
            evidenceDemandedAbove: .high
        )

        #expect(bound.closedBy == nil)
        #expect(bound.sufficientControls.map(\.state) == [.unevidenced])
    }

    @Test func closesTheTreeWhenTheDemandedEvidenceIsStated() throws {
        let bound = try closed(
            by: ["Segment the network"],
            answers: [("x", .implemented)],
            proofs: [ControlKey("x-0"): ControlProof(evidence: .tested)],
            evidenceDemandedAbove: .high
        )

        #expect(bound.closedBy == "Segment the network")
    }

    @Test func closesTheTreeWithNoEvidenceBelowTheDemand() throws {
        let bound = try closed(
            by: ["Segment the network"],
            answers: [("x", .implemented)],
            evidenceDemandedAbove: .critical
        )

        #expect(bound.closedBy == "Segment the network")
    }

    @Test func makesTheTreeStaleWhenNoCatalogueOrLibraryControlHasTheDescription() throws {
        let bound = try closed(by: ["Segmnet the network"], answers: [("x", .implemented)])

        #expect(bound.isStale)
        #expect(bound.closedBy == nil)
        #expect(bound.sufficientControls.map(\.state) == [.unknown])
        #expect(bound.chainFactor == 0)
    }

    @Test func readsADescriptionTheWayTheControlsIdentityDoes() throws {
        let bound = try closed(
            by: ["Segment  the network "],
            answers: [("x", .implemented)]
        )

        #expect(bound.closedBy == "Segment  the network ")
    }

    // MARK: the tree's shape, for the report

    @Test func theRootNodeKeepsTheGateKindAndTheNesting() throws {
        let bound = try #require(AttackTreeBinding.bind(
            trees: [tree(
                goal: target("g", "db"),
                root: .all([step("a", "api"), .any([step("b", "api"), step("c", "api")])])
            )],
            to: [resolved("g", "db"), resolved("a", "api"), resolved("b", "api"), resolved("c", "api")]
        ).first)

        guard case .all(let children) = try #require(bound.rootNode) else {
            Issue.record("the root is not an all_of")
            return
        }
        #expect(children.count == 2)
        guard case .any(let nested) = children[1] else {
            Issue.record("the nested child is not an any_of")
            return
        }
        #expect(nested.count == 2)
    }

    @Test func theRootNodeNumbersAChainTheSameWayTheFlatStepsDo() throws {
        let bound = try #require(AttackTreeBinding.bind(
            trees: [tree(goal: target("g", "db"), root: .then([step("a", "api"), step("b", "api")]))],
            to: [resolved("g", "db"), resolved("a", "api"), resolved("b", "api")]
        ).first)

        #expect(bound.steps.map(\.chain) == [1, 1])
        #expect(bound.steps.map(\.position) == [1, 2])

        guard case .then(let children) = try #require(bound.rootNode) else {
            Issue.record("the root is not a then")
            return
        }
        let chained: [(chain: Int?, position: Int?)] = children.map { child in
            guard case .step(let step) = child else { return (nil, nil) }
            return (step.chain, step.position)
        }
        #expect(chained.map(\.chain) == [1, 1])
        #expect(chained.map(\.position) == [1, 2])
    }
}
