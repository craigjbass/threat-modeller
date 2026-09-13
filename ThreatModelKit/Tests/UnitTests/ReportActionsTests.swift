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
        let threats = app.assessThreatModel().execute(AssessThreatModelRequest()).threats
            .filter { $0.source.id == "component:\(storeId)" }
            .map { ThreatId($0.threatId) }

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
        #expect(report.actions[0].removes > 0)
        #expect(report.actions[0].totalResidual > 0)
    }

    @Test func theReportCarriesNoActionForAModelDeclaringNone() {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "restricted")
        )

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report

        #expect(report.actions.isEmpty)
    }
}
