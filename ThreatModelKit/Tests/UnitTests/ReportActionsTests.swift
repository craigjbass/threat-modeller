import Testing
import ThreatModelKit
import TestSupport

struct ReportActionsTests {
    private let app = TestDependencies()

    @Test func theReportCarriesWhatEachActionRemoves() {
        guard case .added(let guardId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-waf", x: 0, y: 0, sensitivity: "restricted")
        ), case .added(let store1Id) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 400, y: 0, sensitivity: "restricted")
        ), case .added(let store2Id) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 400, y: 200, sensitivity: "public")
        ) else {
            Issue.record("the components were not added")
            return
        }
        let allThreats = app.assessThreatModel().execute(AssessThreatModelRequest()).threats
        let threatsOnStore1 = allThreats
            .filter { $0.source.id == "component:\(store1Id)" }
        let threats = threatsOnStore1.map { ThreatId($0.threatId) }

        var model = app.modelStore.current()
        model.mitigatesEdges = [
            MitigatesEdge(
                source: ComponentId(guardId),
                target: ComponentId(store1Id),
                status: .proposed,
                action: EdgeAction(label: "adopt", text: "Adopt the guard", blockedBy: nil)
            )
        ]
        for threat in threatsOnStore1 {
            guard let control = threat.controls.first else { continue }
            model.controlMitigatedBy[ControlKey(control.key)] = [
                ControlMitigation(edgeId: "\(guardId)->\(store1Id)", reducesRiskBy: 75)
            ]
        }
        app.modelStore.save(model)

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report

        #expect(report.actions.count == 1)
        #expect(report.actions[0].text == "Adopt the guard")

        let action = report.actions[0]
        // Guard aws-waf raises no threats. Two stores: one restricted, one public.
        // Store 1 (restricted): threat score 8
        // Store 2 (public): same threat at lower sensitivity score 2
        // Baseline: total 10, worst 8
        // Mitigation targets only store1 with 75% reduction.
        // Store 1: max(1, round(8 × 0.25)) = 2
        // Store 2: 2 (untouched)
        // After: total 4, worst 2
        // Removes: 10 - 4 = 6
        #expect(action.removes == 6)
        #expect(action.totalResidual == 10)
        #expect(action.threatsMoved == 1)
        #expect(action.worstBefore == 8)
        #expect(action.worstAfter == 2)
    }

    @Test func theReportCarriesNoActionForAModelDeclaringNone() {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "restricted")
        )

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report

        #expect(report.actions.isEmpty)
    }
}
