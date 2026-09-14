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
                statuses: [.notImplemented], compensating: [], likelihood: .commodity
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

    private func goalScore(_ result: (threats: [ResolvedThreat], trees: [BoundAttackTree])) -> Int {
        result.threats.first { $0.threat.id.value == "g" }?.score.value ?? 0
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
}
