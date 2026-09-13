import Testing
import ThreatModelKit
import TestSupport

/// What one action would remove, measured by running the assessment again
/// with that action's edges in place.
struct AssessLeverageTests {
    private let app = TestDependencies()

    /// Builds a model whose `store` carries threats worth measuring, and
    /// returns the ids of the components.
    private func aModelWorthMeasuring() -> (guardId: String, storeId: String, queueId: String) {
        // The guard is a WAF: it raises no threats of its own, so it never
        // sits at the top of the model and masks what an action removes. The
        // queue holds public data, well below the store's own worst threat,
        // for the same reason.
        guard case .added(let guardId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-waf", x: 0, y: 0, sensitivity: "restricted")
        ), case .added(let storeId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 400, y: 0, sensitivity: "restricted")
        ), case .added(let queueId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 800, y: 0, sensitivity: "public")
        ) else {
            Issue.record("the components were not added")
            return ("", "", "")
        }
        return (guardId, storeId, queueId)
    }

    private func setEdges(_ edges: [MitigatesEdge]) {
        var model = app.modelStore.current()
        model.mitigatesEdges = edges
        app.modelStore.save(model)
    }

    private func threatIdsOn(_ componentId: String) -> [ThreatId] {
        let assessment = app.assessThreatModel().execute(AssessThreatModelRequest())
        return assessment.threats
            .filter { $0.source.id == "component:\(componentId)" }
            .map { ThreatId($0.threatId) }
    }

    @Test func measuresWhatOneActionRemoves() {
        let ids = aModelWorthMeasuring()
        let threats = threatIdsOn(ids.storeId)
        setEdges([
            MitigatesEdge(
                source: ComponentId(ids.guardId),
                target: ComponentId(ids.storeId),
                threatIds: threats,
                reducesRiskBy: 50,
                status: .assumed,
                action: EdgeAction(label: "adopt", text: "Adopt the guard")
            )
        ])

        let response = app.assessLeverage().execute(AssessLeverageRequest())

        #expect(response.leverage.count == 1)
        let only = response.leverage[0]
        #expect(only.action.label == "adopt")
        #expect(only.removes > 0)
        #expect(only.threatsMoved == threats.count)
        #expect(only.worstAfter < only.worstBefore)
        #expect(only.totalResidual == response.totalResidual)
    }

    @Test func totalsEveryEdgeOfOneAction() {
        let ids = aModelWorthMeasuring()
        let onStore = threatIdsOn(ids.storeId)
        let onQueue = threatIdsOn(ids.queueId)
        setEdges([
            MitigatesEdge(
                source: ComponentId(ids.guardId),
                target: ComponentId(ids.storeId),
                threatIds: onStore,
                reducesRiskBy: 50,
                status: .assumed,
                action: EdgeAction(label: "adopt", text: "Adopt the guard")
            ),
            MitigatesEdge(
                source: ComponentId(ids.guardId),
                target: ComponentId(ids.queueId),
                threatIds: onQueue,
                reducesRiskBy: 50,
                status: .assumed,
                action: EdgeAction(label: "adopt")
            )
        ])

        let both = app.assessLeverage().execute(AssessLeverageRequest()).leverage

        #expect(both.count == 1)
        #expect(both[0].threatsMoved == onStore.count + onQueue.count)
    }

    @Test func measuresEachOfTwoOverlappingActionsAlone() {
        let ids = aModelWorthMeasuring()
        let threats = threatIdsOn(ids.storeId)
        let weaker = MitigatesEdge(
            source: ComponentId(ids.guardId),
            target: ComponentId(ids.storeId),
            threatIds: threats,
            reducesRiskBy: 50,
            status: .assumed,
            action: EdgeAction(label: "weaker", text: "The weaker guard")
        )
        let stronger = MitigatesEdge(
            source: ComponentId(ids.queueId),
            target: ComponentId(ids.storeId),
            threatIds: threats,
            reducesRiskBy: 80,
            status: .assumed,
            action: EdgeAction(label: "stronger", text: "The stronger guard")
        )
        setEdges([weaker, stronger])

        let measured = app.assessLeverage().execute(AssessLeverageRequest()).leverage

        // Each is measured alone against today's posture. Baseline totals 10
        // (store's one threat scores 8, queue's scores 2). Adopting only the
        // 80% edge leaves store at 2, for a total of 4: removes = 10 - 4 = 6.
        // Adopting only the 50% edge leaves store at 4, for a total of 6:
        // removes = 10 - 6 = 4.
        #expect(measured.count == 2)
        #expect(measured[0].action.label == "stronger")
        #expect(measured[0].removes == 6)
        #expect(measured[1].action.label == "weaker")
        #expect(measured[1].removes == 4)

        // Adopting both together still gives store's one threat the stronger
        // reduction alone, not the sum of the two: ComponentMitigations takes
        // the strongest answering edge. So the sum of the two rows overstates
        // what doing both actually removes.
        var bothWeakerAdopted = weaker
        bothWeakerAdopted.status = .adopted
        var bothStrongerAdopted = stronger
        bothStrongerAdopted.status = .adopted
        setEdges([bothWeakerAdopted, bothStrongerAdopted])
        let totalWithBothAdopted = app.assessThreatModel().execute(AssessThreatModelRequest())
            .threats.map(\.riskScore).reduce(0, +)
        let removedByBoth = 10 - totalWithBothAdopted

        #expect(measured[0].removes + measured[1].removes > removedByBoth)
    }

    @Test func reportsAnActionThatRemovesNothing() {
        let ids = aModelWorthMeasuring()
        setEdges([
            MitigatesEdge(
                source: ComponentId(ids.guardId),
                target: ComponentId(ids.storeId),
                threatIds: [ThreatId("a-threat-this-model-does-not-raise")],
                reducesRiskBy: 90,
                status: .assumed,
                action: EdgeAction(label: "pointless", text: "Buy the wrong thing")
            )
        ])

        let measured = app.assessLeverage().execute(AssessLeverageRequest()).leverage

        #expect(measured.count == 1)
        #expect(measured[0].removes == 0)
        #expect(measured[0].threatsMoved == 0)
        #expect(measured[0].worstAfter == measured[0].worstBefore)
    }

    @Test func measuresNothingForAModelWithNoActions() {
        _ = aModelWorthMeasuring()

        let response = app.assessLeverage().execute(AssessLeverageRequest())

        #expect(response.leverage.isEmpty)
        #expect(response.totalResidual > 0)
    }

    @Test func leavesEveryOtherAssumedEdgeAssumed() {
        let ids = aModelWorthMeasuring()
        let threats = threatIdsOn(ids.storeId)
        setEdges([
            MitigatesEdge(
                source: ComponentId(ids.guardId),
                target: ComponentId(ids.storeId),
                threatIds: threats,
                reducesRiskBy: 50,
                status: .assumed,
                action: EdgeAction(label: "measured", text: "The one measured")
            ),
            MitigatesEdge(
                source: ComponentId(ids.queueId),
                target: ComponentId(ids.storeId),
                threatIds: threats,
                reducesRiskBy: 90,
                status: .assumed
            )
        ])

        let measured = app.assessLeverage().execute(AssessLeverageRequest()).leverage

        // The 90% edge names no action, so it stays assumed while the 50%
        // one is measured. Baseline totals 10 (store 8, queue 2, neither
        // edge adopted). Adopting only the 50% edge leaves store at 4 and
        // queue untouched at 2, for a total of 6: removes = 10 - 6 = 4.
        // Promoting the 90% sibling alongside the measured edge would push
        // store to 1, raising removes to 7, not driving it to nothing -- an
        // inequality check cannot tell the two apart, so this asserts the
        // exact figure.
        #expect(measured[0].removes == 4)
    }
}
