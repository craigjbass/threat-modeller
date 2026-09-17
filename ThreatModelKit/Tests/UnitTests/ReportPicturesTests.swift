import CommandLineApplication
import DiagramRendering
import Foundation
import Testing
import TestSupport
import ThreatModelKit

/// One picture set for the window and for the executable.
///
/// The design is
/// `docs/superpowers/specs/2026-09-17-report-stage-pictures-design.md`.
@Suite("The pictures a report holds")
struct ReportPicturesTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
      component "store" {
        technology = "aws-rds"
        data       = "restricted"
      }
      flow api -> store
    }

    """

    /// The model as the report draws it, read through the use cases.
    private func aModel() -> (DiagramBuilder.Model, Report) {
        let useCases = TestDependencies()
        _ = useCases.importArchitecture()
            .execute(ImportArchitectureRequest(text: payments))
        let canvas = useCases.viewThreatModel().execute(ViewThreatModelRequest())
        let assessment = useCases.assessThreatModel().execute(AssessThreatModelRequest())
        let report = useCases.buildThreatModelReport()
            .execute(BuildThreatModelReportRequest()).report

        return (
            DiagramBuilder.Model(
                components: canvas.components,
                connections: canvas.connections,
                zones: canvas.zones,
                risks: ElementRiskRollup.byElement(
                    assessment.threats,
                    levelOrder: assessment.severities.map(\.id)
                ),
                guards: EdgeGuards.byElement(assessment.threats)
            ),
            report
        )
    }

    /// Every top residual threat is drawn, and the file name the report links
    /// carries the bytes the page inlines.
    @Test func drawsOnePictureForEachTopResidualThreat() {
        let (model, report) = aModel()

        let drawn = ReportPictures.of(model: model, report: report, stem: "payments")

        #expect(drawn.threatPictures.isEmpty == false)
        #expect(drawn.threatPictures.count == report.rollups.topResidual.count)
        for (_, fileName) in drawn.threatPictures {
            #expect(drawn.sources[fileName]?.hasPrefix("<svg") == true)
        }
        #expect(drawn.wholePicture.hasPrefix("<svg"))
    }

    /// A control picture per protection dependency, keyed by the component the
    /// protection comes from.
    @Test func drawsOnePictureForEachControl() {
        let (model, report) = aModel()

        let drawn = ReportPictures.of(model: model, report: report, stem: "payments")

        #expect(drawn.controlPictures.count == report.protectionDependencies.count)
        for (_, fileName) in drawn.controlPictures {
            #expect(drawn.sources[fileName] != nil)
        }
    }

    /// A project nobody sampled draws no graph, so the report writes no link
    /// to one.
    @Test func drawsNoRiskGraphWithNoHistorySampled() {
        let (model, report) = aModel()

        let drawn = ReportPictures.of(model: model, report: report, stem: "payments")

        #expect(drawn.riskOverTimePicture == nil)
        #expect(drawn.riskOverTimeChart == nil)
    }

    /// The executable's report verb and the window draw one set, so a page
    /// written either way holds the same figures.
    @Test func drawsTheSetTheExecutableWrites() throws {
        let project = InMemoryProject(root: "/work")
        try project.write(payments, to: "/work/threatmodel/payments.arch")

        var lines: [String] = []
        let code = CommandLineApplication(
            projects: project,
            catalogue: { CatalogueFixture.catalogue() }
        )
        .run(
            arguments: ["threatmodeller", "report", "/work", "--html", "--commits", "0"],
            output: { lines.append($0) }
        )
        #expect(code == 0, Comment(rawValue: lines.joined(separator: "\n")))

        let page = try #require(project.text(at: "/work/threatmodel/payments.html"))
        let (model, report) = aModel()
        let drawn = ReportPictures.of(model: model, report: report, stem: "payments")

        #expect(
            page.components(separatedBy: "<figure").count - 1
                == drawn.threatPictures.count + drawn.controlPictures.count + 1
        )
    }
}
