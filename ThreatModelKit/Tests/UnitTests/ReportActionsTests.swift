import Testing
import ThreatModelKit
import TestSupport

struct ReportActionsTests {
    private let app = TestDependencies()

    @Test func theReportCarriesWhatEachActionRemoves() {
        guard case .added(let guardId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-waf", x: 0, y: 0, sensitivity: "restricted")
        ), case .added(let storeId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 400, y: 0, sensitivity: "restricted")
        ) else {
            Issue.record("the components were not added")
            return
        }
        let allThreats = app.assessThreatModel().execute(AssessThreatModelRequest()).threats
        let threatsOnStore = allThreats
            .filter { $0.source.id == "component:\(storeId)" }
        let threats = threatsOnStore.map { ThreatId($0.threatId) }

        var model = app.modelStore.current()
        model.mitigatesEdges = [
            MitigatesEdge(
                source: ComponentId(guardId),
                target: ComponentId(storeId),
                threatIds: threats,
                reducesRiskBy: 50,
                status: .assumed,
                action: EdgeAction(label: "adopt", text: "Adopt the guard", blockedBy: nil)
            )
        ]
        app.modelStore.save(model)

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report

        #expect(report.actions.count == 1)
        #expect(report.actions[0].text == "Adopt the guard")

        let action = report.actions[0]
        // Guard aws-waf raises no threats. Only store (aws-rds) threats remain.
        // Baseline: store threat score 8, total 8, worst 8
        // After 50% mitigation: max(1, round(8 × 0.5)) = 4
        // Removes: 8 - 4 = 4 (one threat moves from 8 to 4)
        // Total after: 4
        // Worst after: 4 (the mitigated threat becomes the worst)
        #expect(action.removes == 4)
        #expect(action.totalResidual == 8)
        #expect(action.threatsMoved == 1)
        #expect(action.worstBefore == 8)
        #expect(action.worstAfter == 4)
    }

    @Test func theReportCarriesNoActionForAModelDeclaringNone() {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "restricted")
        )

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report

        #expect(report.actions.isEmpty)
    }
}
