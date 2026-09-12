import Testing
import ThreatModelKit

@Suite("What guards one element on the diagram")
struct EdgeGuardsTests {
    private func threat(
        _ threatId: String,
        source: AssessedThreatSource,
        mitigatedBy: [String] = [],
        assumedBy: [String] = []
    ) -> AssessedThreat {
        AssessedThreat(
            threatId: threatId,
            name: threatId,
            description: "",
            severityId: "high",
            severityLabel: "High",
            stride: [],
            mitreTechniques: [],
            controls: [],
            source: source,
            sensitivityId: "internal",
            riskScore: 10,
            riskLevel: "high",
            context: nil,
            isTlsMitigated: false,
            overrideKey: "o-\(threatId)",
            overriddenSeverityId: nil,
            mitigatedByComponentLabels: mitigatedBy,
            assumedByComponentLabels: assumedBy
        )
    }

    private let flow = AssessedThreatSource.connection(
        id: "f1", sourceName: "End User", targetName: "EC2"
    )

    @Test func statesNothingForAFlowNoEdgeGuards() {
        let guards = EdgeGuards.byElement([threat("t1", source: flow)])

        #expect(guards["connection:f1"] == nil)
    }

    @Test func namesTheComponentWhoseAdoptedEdgeAnsweredAThreat() {
        let guards = EdgeGuards.byElement(
            [threat("t1", source: flow, mitigatedBy: ["WAF"])]
        )

        #expect(guards["connection:f1"] == [EdgeGuard(label: "WAF", isAssumed: false)])
    }

    @Test func marksAnAssumedEdgeAsAssumed() {
        let guards = EdgeGuards.byElement(
            [threat("t1", source: flow, assumedBy: ["API Gateway"])]
        )

        #expect(guards["connection:f1"] == [EdgeGuard(label: "API Gateway", isAssumed: true)])
    }

    @Test func keepsTheAdoptedFormWhenOneComponentIsBoth() {
        let guards = EdgeGuards.byElement(
            [
                threat("t1", source: flow, mitigatedBy: ["WAF"]),
                threat("t2", source: flow, assumedBy: ["WAF"])
            ]
        )

        #expect(guards["connection:f1"] == [EdgeGuard(label: "WAF", isAssumed: false)])
    }

    @Test func namesEachComponentOnceHoweverManyThreatsItAnswered() {
        let guards = EdgeGuards.byElement(
            [
                threat("t1", source: flow, mitigatedBy: ["WAF"]),
                threat("t2", source: flow, mitigatedBy: ["WAF"]),
                threat("t3", source: flow, mitigatedBy: ["WAF", "API Gateway"])
            ]
        )

        #expect(
            guards["connection:f1"] == [
                EdgeGuard(label: "API Gateway", isAssumed: false),
                EdgeGuard(label: "WAF", isAssumed: false)
            ]
        )
    }

    @Test func keepsTheGuardsOfTwoFlowsApart() {
        let other = AssessedThreatSource.connection(
            id: "f2", sourceName: "EC2", targetName: "RDS"
        )
        let guards = EdgeGuards.byElement(
            [
                threat("t1", source: flow, mitigatedBy: ["WAF"]),
                threat("t2", source: other, mitigatedBy: ["Bastion"])
            ]
        )

        #expect(guards["connection:f1"]?.map(\.label) == ["WAF"])
        #expect(guards["connection:f2"]?.map(\.label) == ["Bastion"])
    }

    @Test func namesTheGuardsOfAComponentAndAZoneToo() {
        let node = AssessedThreatSource.component(id: "c1", name: "EC2", providerId: "aws")
        let zone = AssessedThreatSource.zone(id: "z1", name: "Core VPC")
        let guards = EdgeGuards.byElement(
            [
                threat("t1", source: node, mitigatedBy: ["EDR"]),
                threat("t2", source: zone, assumedBy: ["Firewall"])
            ]
        )

        #expect(guards["component:c1"]?.map(\.label) == ["EDR"])
        #expect(guards["zone:z1"] == [EdgeGuard(label: "Firewall", isAssumed: true)])
    }
}
