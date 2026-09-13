import Testing
import ThreatModelKit
import TestSupport

struct ReportActionsTests {
    private let app = TestDependencies()

    @Test func theReportCarriesWhatEachActionRemoves() {
        guard case .added(let guardId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "restricted")
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
        // Baseline: threats score [16, 8, 8, 4], total 36, worst 16
        // Store threat baseline score: 8
        // After 50% mitigation: max(1, round(8 × 0.5)) = 4
        // Removes: 8 - 4 = 4 (one threat moves from 8 to 4)
        // Total after mitigation: 36 - 4 = 32
        // Worst after: still 16 (the worst threat is not mitigated)
        #expect(action.removes == 4)
        #expect(action.totalResidual == 36)
        #expect(action.threatsMoved == 1)
        #expect(action.worstBefore == 16)
        #expect(action.worstAfter == 16)
    }

    @Test func theReportCarriesNoActionForAModelDeclaringNone() {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "restricted")
        )

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report

        #expect(report.actions.isEmpty)
    }
}
