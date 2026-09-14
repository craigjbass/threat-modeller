import Testing
import ThreatModelKit

@Suite("The bound attack tree")
struct AttackTreeTests {
    // 0.375 gives 37.5, which rounds to 38 and would truncate to 37, so this
    // case tells a rounding from a truncating cast. The other four multiply to
    // whole numbers and cannot.
    @Test(arguments: [(1.0, 100), (0.6, 60), (0.25, 25), (0.0, 0), (0.375, 38)])
    func statesTheChainFactorAsAWholePercentage(factor: Double, percentage: Int) {
        let tree = BoundAttackTree(
            id: "t",
            name: "T",
            description: nil,
            raisesRiskBy: 40,
            goal: ThreatKey(threatId: "g", sourceId: "component:db"),
            goalName: "G",
            goalSourceName: "db",
            steps: [],
            chainFactor: factor,
            isOpen: factor > 0,
            isStale: false,
            scoreBefore: 5,
            score: 7
        )

        #expect(tree.chainPercentage == percentage)
    }
}
