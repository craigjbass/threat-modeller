import Testing
import ThreatModelKit
import TestSupport

/// Given a threat model with components, a link and a zone
/// When I export it
/// Then Markdown, threatcl, the PDF renderer and the picture all say the same
/// thing about it
struct ReportingAThreatModelTests {
    private let app = TestDependencies()

    private func aModelWorthReporting() -> (source: String, target: String) {
        _ = app.renameThreatModel().execute(RenameThreatModelRequest(name: "Payments"))
        guard case .added(let source) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "restricted")
        ), case .added(let target) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 400, y: 0, sensitivity: "restricted")
        ) else {
            Issue.record("the components were not added")
            return ("", "")
        }
        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: source, targetComponentId: target)
        )
        _ = app.addZone().execute(AddZoneRequest(x: -100, y: -100, width: 900, height: 700))
        return (source, target)
    }

    @Test func writesEverythingTheSidebarShowsIntoTheReport() throws {
        _ = aModelWorthReporting()
        let assessment = app.assessThreatModel().execute(AssessThreatModelRequest())

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report

        #expect(report.modelName == "Payments")
        #expect(report.components.count == 2)
        #expect(report.connections.count == 1)
        #expect(report.zones.count == 1)
        // A report can never disagree with what the user saw on screen.
        #expect(report.threats.count == assessment.threats.count)
        #expect(report.threats.map(\.name) == assessment.threats.map(\.name))
        #expect(report.summary.totalThreats == assessment.threats.count)
    }

    @Test func writesTheSameModelAsMarkdown() {
        _ = aModelWorthReporting()

        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest())

        #expect(markdown.fileName == "Payments.md")
        #expect(markdown.markdown.hasPrefix("# Payments\n"))
        #expect(markdown.markdown.contains("## Components"))
        #expect(markdown.markdown.contains("| EC2 | aws-ec2 | Restricted |"))
        #expect(markdown.markdown.contains("EC2 \u{2192} RDS"))
        #expect(markdown.markdown.contains("## Zones"))
        #expect(markdown.markdown.contains("- Holds: EC2, RDS"))
        #expect(markdown.markdown.contains("## Threats"))
    }

    @Test func writesTheSameModelAsThreatcl() {
        _ = aModelWorthReporting()

        let threatcl = app.exportModelAsThreatcl().execute(ExportModelAsThreatclRequest())

        #expect(threatcl.fileName == "Payments.hcl")
        #expect(threatcl.hcl.contains("threatmodel \"Payments\" {"))
        #expect(threatcl.hcl.contains("  information_asset \"EC2\" {"))
        #expect(threatcl.hcl.contains("  information_asset \"RDS\" {"))
        #expect(threatcl.hcl.contains("EC2 sends data to RDS"))
        #expect(threatcl.hcl.contains("  threat {"))
    }

    @Test func asksTheRendererForTheSameModelAsPdf() {
        _ = aModelWorthReporting()

        let response = app.exportModelAsPdf().execute(ExportModelAsPdfRequest())

        guard case .exported(let bytes, let fileName) = response else {
            Issue.record("expected .exported, got \(response)")
            return
        }
        #expect(fileName == "Payments.pdf")
        #expect(bytes.isEmpty == false)
    }

    @Test func saysWhatThePictureShouldDraw() {
        _ = aModelWorthReporting()

        let area = app.exportModelAsImage().execute(ExportModelAsImageRequest())

        #expect(area.fileName == "Payments.png")
        #expect(area.isEmpty == false)
        // The zone is the widest thing on the model, so the picture holds it
        // with a margin on each side.
        #expect(area.x == -140)
        #expect(area.width == 900 + 80)
    }

    @Test func saysTheSameThingAfterTheFileIsSavedAndOpenedAgain() throws {
        _ = aModelWorthReporting()
        let before = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown
        guard case .saved(let data) = app.saveThreatModel().execute(SaveThreatModelRequest()) else {
            Issue.record("the model was not saved")
            return
        }

        let reopened = TestDependencies()
        _ = reopened.openThreatModel().execute(OpenThreatModelRequest(data: data))

        #expect(
            reopened.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown
                == before
        )
    }
}
