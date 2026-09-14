import Testing
import ThreatModelKit

@Suite("The attack tree value tree")
struct AttackTreeSourceTests {
    @Test func mintsTheThreatKeyAFlowStepNames() {
        let target = SourceTreeTarget(threatId: "connection-mitm", sourceKind: "flow", sourceId: "cdn->api")

        #expect(target.key == ThreatKey(threatId: "connection-mitm", sourceId: "connection:cdn->api"))
    }

    @Test func mintsTheThreatKeyAComponentStepNames() {
        let target = SourceTreeTarget(threatId: "ssrf-attack", sourceKind: "component", sourceId: "appserver")

        #expect(target.key == ThreatKey(threatId: "ssrf-attack", sourceId: "component:appserver"))
    }

    @Test func listsEveryStepInATree() {
        let tree = SourceAttackTree(
            id: "steal-the-credential",
            goal: SourceTreeTarget(threatId: "data-exfiltration", sourceKind: "component", sourceId: "db"),
            root: .all([
                .step(SourceTreeStep(target: SourceTreeTarget(
                    threatId: "ssrf-attack", sourceKind: "component", sourceId: "appserver"
                ))),
                .any([
                    .step(SourceTreeStep(target: SourceTreeTarget(
                        threatId: "credential-theft", sourceKind: "component", sourceId: "appserver"
                    ))),
                ]),
            ])
        )

        #expect(tree.steps.map(\.target.threatId) == ["ssrf-attack", "credential-theft"])
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
