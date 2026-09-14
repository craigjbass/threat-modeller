import Testing
import ThreatModelKit
import TestSupport

@Suite("Stage 8: an attack tree raises its goal")
struct AttackTreeScoreTests {
    private func target(_ threatId: String, _ componentId: String) -> SourceTreeTarget {
        SourceTreeTarget(threatId: threatId, sourceKind: "component", sourceId: componentId)
    }

    private func run(
        raises: Int,
        goalScore: Int,
        goalScoreIfAssumptionsHold: Int? = nil,
        steps: [(String, ControlStatus, Likelihood)]
    ) -> (threats: [ResolvedThreat], trees: [BoundAttackTree]) {
        let tree = SourceAttackTree(
            id: "t",
            raisesRiskBy: raises,
            goal: target("g", "db"),
            root: .all(steps.map { .step(SourceTreeStep(target: target($0.0, "api"))) })
        )
        var resolved = [
            ResolvedThreatFixture.make(
                threatId: "g", componentId: "db", score: goalScore,
                statuses: [.notImplemented], compensating: [], likelihood: .commodity,
                scoreIfAssumptionsHold: goalScoreIfAssumptionsHold
            ),
        ]
        resolved += steps.map {
            ResolvedThreatFixture.make(
                threatId: $0.0, componentId: "api", score: 4,
                statuses: [$0.1], compensating: [], likelihood: $0.2
            )
        }
        let bound = AttackTreeBinding.bind(trees: [tree], to: resolved)
        return AttackTreeScoring.apply(trees: bound, to: resolved)
    }

    private func goal(_ result: (threats: [ResolvedThreat], trees: [BoundAttackTree])) -> ResolvedThreat? {
        result.threats.first { $0.threat.id.value == "g" }
    }

    private func goalScore(_ result: (threats: [ResolvedThreat], trees: [BoundAttackTree])) -> Int {
        goal(result)?.score.value ?? 0
    }

    @Test func reachesSevenOnTheWorkedExample() {
        let result = run(raises: 40, goalScore: 5, steps: [
            ("a", .notImplemented, .commodity),
            ("b", .notImplemented, .commodity),
        ])

        #expect(goalScore(result) == 7)
        #expect(result.trees[0].score == 7)
        #expect(result.trees[0].scoreBefore == 5)
        #expect(result.trees[0].chainPercentage == 100)
    }

    @Test func raisesNothingWhenTheRootIsClosed() {
        let result = run(raises: 40, goalScore: 5, steps: [
            ("a", .implemented, .commodity),
            ("b", .notImplemented, .commodity),
        ])

        #expect(goalScore(result) == 5)
        #expect(result.trees[0].chainFactor == 0)
    }

    @Test func raisesNothingWhenTheTreeStatesZero() {
        let result = run(raises: 0, goalScore: 5, steps: [("a", .notImplemented, .commodity)])

        #expect(goalScore(result) == 5)
    }

    @Test(arguments: [
        (Likelihood.commodity, 7),
        (Likelihood.targeted, 6),
        (Likelihood.research, 6),
    ])
    func boundsTheBoostByTheWeakestStep(weakest: Likelihood, expected: Int) {
        let result = run(raises: 40, goalScore: 5, steps: [
            ("a", .notImplemented, .commodity),
            ("b", .notImplemented, weakest),
        ])

        #expect(goalScore(result) == expected)
    }

    @Test func neverCarriesAScoreAboveSixteen() {
        let result = run(raises: 100, goalScore: 15, steps: [("a", .notImplemented, .commodity)])

        #expect(goalScore(result) == 16)
    }

    @Test func leavesAThreatNoTreeNamesWhereItIs() {
        let result = run(raises: 40, goalScore: 5, steps: [("a", .notImplemented, .commodity)])

        #expect(result.threats.first { $0.threat.id.value == "a" }?.score.value == 4)
    }

    @Test func raisesTheTargetScoreTooWhenItStartsBelowTheResidualScore() {
        let result = run(
            raises: 40, goalScore: 5, goalScoreIfAssumptionsHold: 3,
            steps: [("a", .notImplemented, .commodity)]
        )

        #expect(goalScore(result) == 7)
        #expect(goal(result)?.scoreIfAssumptionsHold == 4)
    }

    @Test func keepsTheResidualAndTargetScoreEqualWhenTheyStartEqual() {
        let result = run(raises: 40, goalScore: 5, steps: [
            ("a", .notImplemented, .commodity),
            ("b", .notImplemented, .commodity),
        ])

        let raised = goal(result)
        #expect(raised?.score.value == 7)
        #expect(raised?.scoreIfAssumptionsHold == raised?.score.value)
    }

    @Test func twoTreesOnOneGoalGiveTheStrongerBoostNotTheSum() {
        let strongTree = SourceAttackTree(
            id: "strong",
            raisesRiskBy: 40,
            goal: target("g", "db"),
            root: .step(SourceTreeStep(target: target("a", "api")))
        )
        let weakTree = SourceAttackTree(
            id: "weak",
            raisesRiskBy: 10,
            goal: target("g", "db"),
            root: .step(SourceTreeStep(target: target("a", "api")))
        )
        let resolved = [
            ResolvedThreatFixture.make(
                threatId: "g", componentId: "db", score: 5,
                statuses: [.notImplemented], compensating: [], likelihood: .commodity
            ),
            ResolvedThreatFixture.make(
                threatId: "a", componentId: "api", score: 4,
                statuses: [.notImplemented], compensating: [], likelihood: .commodity
            ),
        ]
        let bound = AttackTreeBinding.bind(trees: [strongTree, weakTree], to: resolved)
        let result = AttackTreeScoring.apply(trees: bound, to: resolved)

        // The stronger boost (0.4) gives round(5 x 1.4) = 7. Summing the two
        // boosts (0.4 + 0.1 = 0.5) would give round(5 x 1.5) = 8.
        #expect(result.threats.first { $0.threat.id.value == "g" }?.score.value == 7)
    }

    @Test func raisesNothingWhenTheTreeIsStale() {
        let tree = SourceAttackTree(
            id: "t",
            raisesRiskBy: 40,
            goal: target("g", "db"),
            root: .step(SourceTreeStep(target: target("missing", "api")))
        )
        let resolved = [
            ResolvedThreatFixture.make(
                threatId: "g", componentId: "db", score: 5,
                statuses: [.notImplemented], compensating: [], likelihood: .commodity
            ),
        ]
        let bound = AttackTreeBinding.bind(trees: [tree], to: resolved)
        let result = AttackTreeScoring.apply(trees: bound, to: resolved)

        #expect(result.threats.first { $0.threat.id.value == "g" }?.score.value == 5)
    }
}
