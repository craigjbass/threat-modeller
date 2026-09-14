import Testing
import ThreatModelKit

@Suite("The bound attack tree")
struct AttackTreeTests {
    private func step(_ id: String, _ state: StepState, _ factor: Double) -> BoundStep {
        BoundStep(
            key: ThreatKey(threatId: id, sourceId: "component:c"),
            threatName: id,
            sourceName: "c",
            state: state,
            closedBy: state == .closed ? "a control" : nil,
            factor: factor,
            note: nil
        )
    }

    @Test func aTreeIsStaleWhenAnyStepIsUnbound() {
        let tree = BoundAttackTree(
            id: "t",
            name: "T",
            description: nil,
            raisesRiskBy: 40,
            goal: ThreatKey(threatId: "g", sourceId: "component:db"),
            goalName: "G",
            goalSourceName: "db",
            steps: [step("a", .open, 1.0), step("b", .unbound, 1.0)],
            chainFactor: 0,
            isOpen: false,
            isStale: true,
            scoreBefore: 5,
            score: 5
        )

        #expect(tree.isStale)
        #expect(tree.score == tree.scoreBefore)
    }

    @Test func aTreeNamesItselfByIdWhenItStatesNoName() {
        #expect(SourceAttackTree(
            id: "t",
            goal: SourceTreeTarget(threatId: "g", sourceKind: "component", sourceId: "db"),
            root: .step(SourceTreeStep(target: SourceTreeTarget(
                threatId: "s", sourceKind: "component", sourceId: "c"
            )))
        ).displayName == "t")
    }
}
