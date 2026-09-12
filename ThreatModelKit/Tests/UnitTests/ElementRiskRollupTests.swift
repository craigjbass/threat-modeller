import Testing
import ThreatModelKit

@Suite("What risk one element on the diagram carries")
struct ElementRiskRollupTests {
    private let levelOrder = ["low", "medium", "high", "critical"]

    private func control(_ status: ControlStatus) -> AssessedControl {
        AssessedControl(
            description: "a control",
            isTechnologySpecific: false,
            key: "k-\(status.rawValue)",
            isImplemented: status == .implemented,
            statusId: status.rawValue,
            statusLabel: status.label
        )
    }

    private func threat(
        _ threatId: String,
        source: AssessedThreatSource,
        level: String,
        controls: [AssessedControl]
    ) -> AssessedThreat {
        AssessedThreat(
            threatId: threatId,
            name: threatId,
            description: "",
            severityId: level,
            severityLabel: level,
            stride: [],
            mitreTechniques: [],
            controls: controls,
            source: source,
            sensitivityId: "internal",
            riskScore: 10,
            riskLevel: level,
            context: nil,
            isTlsMitigated: false,
            overrideKey: "o-\(threatId)",
            overriddenSeverityId: nil
        )
    }

    private let node = AssessedThreatSource.component(
        id: "c1", name: "EC2", providerId: "aws"
    )

    @Test func statesNothingForAnElementThatRaisesNoThreat() {
        let risks = ElementRiskRollup.byElement([], levelOrder: levelOrder)

        #expect(risks.isEmpty)
    }

    @Test func countsAThreatWithNoControlAsOpen() {
        let risks = ElementRiskRollup.byElement(
            [threat("t1", source: node, level: "high", controls: [])],
            levelOrder: levelOrder
        )

        #expect(risks["component:c1"]?.openCount == 1)
        #expect(risks["component:c1"]?.totalCount == 1)
        #expect(risks["component:c1"]?.highestLevelId == "high")
    }

    @Test func countsAThreatWithAnImplementedControlAsAnswered() {
        let risks = ElementRiskRollup.byElement(
            [
                threat(
                    "t1",
                    source: node,
                    level: "medium",
                    controls: [control(.notImplemented), control(.implemented)]
                )
            ],
            levelOrder: levelOrder
        )

        #expect(risks["component:c1"]?.openCount == 0)
        #expect(risks["component:c1"]?.totalCount == 1)
        #expect(risks["component:c1"]?.highestLevelId == "medium")
    }

    @Test func countsAThreatEveryControlOfWhichIsSetAsideAsAnswered() {
        let risks = ElementRiskRollup.byElement(
            [
                threat(
                    "t1",
                    source: node,
                    level: "low",
                    controls: [control(.notApplicable), control(.accepted)]
                )
            ],
            levelOrder: levelOrder
        )

        #expect(risks["component:c1"]?.openCount == 0)
    }

    @Test func countsAThreatWithOneUnansweredControlAsOpen() {
        let risks = ElementRiskRollup.byElement(
            [
                threat(
                    "t1",
                    source: node,
                    level: "low",
                    controls: [control(.notApplicable), control(.notImplemented)]
                )
            ],
            levelOrder: levelOrder
        )

        #expect(risks["component:c1"]?.openCount == 1)
    }

    @Test func takesTheHighestLevelOfEveryThreatOnTheElement() {
        let risks = ElementRiskRollup.byElement(
            [
                threat("t1", source: node, level: "low", controls: []),
                threat("t2", source: node, level: "critical", controls: [control(.implemented)]),
                threat("t3", source: node, level: "medium", controls: [])
            ],
            levelOrder: levelOrder
        )

        #expect(risks["component:c1"]?.highestLevelId == "critical")
        #expect(risks["component:c1"]?.openCount == 2)
        #expect(risks["component:c1"]?.totalCount == 3)
    }

    @Test func keepsAConnectionAndAZoneApartFromAComponent() {
        let risks = ElementRiskRollup.byElement(
            [
                threat("t1", source: node, level: "low", controls: []),
                threat(
                    "t2",
                    source: .connection(id: "f1", sourceName: "A", targetName: "B"),
                    level: "high",
                    controls: []
                ),
                threat(
                    "t3",
                    source: .zone(id: "z1", name: "Private"),
                    level: "medium",
                    controls: []
                )
            ],
            levelOrder: levelOrder
        )

        #expect(risks.count == 3)
        #expect(risks["connection:f1"]?.highestLevelId == "high")
        #expect(risks["zone:z1"]?.highestLevelId == "medium")
    }

    @Test func keepsALevelTheOrderDoesNotNameRatherThanDroppingIt() {
        let risks = ElementRiskRollup.byElement(
            [threat("t1", source: node, level: "unrated", controls: [])],
            levelOrder: levelOrder
        )

        #expect(risks["component:c1"]?.highestLevelId == "unrated")
    }

    @Test func prefersALevelTheOrderNamesOverOneItDoesNot() {
        let risks = ElementRiskRollup.byElement(
            [
                threat("t1", source: node, level: "unrated", controls: []),
                threat("t2", source: node, level: "low", controls: [])
            ],
            levelOrder: levelOrder
        )

        #expect(risks["component:c1"]?.highestLevelId == "low")
    }
}
