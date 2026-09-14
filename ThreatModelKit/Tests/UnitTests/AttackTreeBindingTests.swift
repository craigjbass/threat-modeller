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
}
