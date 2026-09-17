import AppKit
import CommandLineApplication
import DiagramRendering
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The Report stage draws the graphics the HTML export draws.
///
/// The design is
/// `docs/superpowers/specs/2026-09-17-report-stage-pictures-design.md`.
@MainActor
struct ReportStagePicturesTests {
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
      component "guard" { technology = "aws-waf" }

      flow api -> store

      mitigates guard -> api {
        threats         = ["credential-theft"]
        reduces_risk_by = 80
      }
    }

    """

    private func aProject(_ text: String? = nil) async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(text ?? payments, at: "/work/threatmodel/payments.arch")
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    private func page(of project: ProjectSession) throws -> ReportStagePage {
        try #require(project.model).reportStagePage(history: project.sampledHistory)
    }

    private func section(
        _ slot: ReportTemplate.Slot,
        of page: ReportStagePage
    ) throws -> ReportStageSection {
        try #require(
            page.sections.first { $0.slot == slot },
            "the page holds no \(slot.rawValue) section"
        )
    }

    private func pictures(of section: ReportStageSection) -> [String] {
        section.blocks.compactMap { block in
            if case .picture(_, let svg) = block { return svg }
            return nil
        }
    }

    // MARK: the data-flow diagram

    /// The picture the stage draws under the title is the picture the image
    /// export writes, pixel for pixel.
    @Test func drawsTheDataFlowPictureTheImageExportWrites() async throws {
        let (project, _) = await aProject()
        let model = try #require(project.model)

        let exported = try #require(await ReportExporter(session: model).data(for: .image))
        let onTheStage = try #require(ReportDataFlowPicture(session: model).pixels())

        #expect(onTheStage == exported.data)
    }

    /// The title's section holds the picture, which is where the page puts it.
    @Test func putsTheDataFlowPictureUnderTheTitle() async throws {
        let (project, _) = await aProject()

        let section = try section(.systemName, of: try page(of: project))

        #expect(section.blocks.contains(.dataFlow))
    }

    // MARK: the threat pictures

    /// One picture per top residual threat, and the count is the count the
    /// Markdown export writes for the same model.
    @Test func drawsOneThreatPicturePerTopResidualThreat() async throws {
        let (project, _) = await aProject()
        let model = try #require(project.model)
        let report = model.builtReport()

        let drawn = pictures(of: try section(.threatPictures, of: try page(of: project)))

        #expect(drawn.isEmpty == false)
        #expect(drawn.count == report.rollups.topResidual.count)
        #expect(drawn.count == model.reportPictureSet().threatPictures.count)

        // The same count the Markdown report writes for the same pictures.
        let set = model.reportPictureSet()
        let markdown = MarkdownThreatPictures.lines(
            report.rollups.topResidual,
            pictures: set.threatPictures
        )
        #expect(markdown.filter { $0.hasPrefix("![") }.count == drawn.count)
    }

    /// Each control's picture is drawn above what the control carries.
    @Test func drawsOnePictureForEachControl() async throws {
        let (project, _) = await aProject()
        let model = try #require(project.model)

        let drawn = pictures(of: try section(.protectionDependencies, of: try page(of: project)))

        #expect(drawn.count == model.builtReport().protectionDependencies.count)
    }

    /// A change on another stage redraws the picture on the next draw, with
    /// no file written.
    @Test func redrawsThePictureAfterAChange() async throws {
        let (project, _) = await aProject()
        let model = try #require(project.model)
        let before = pictures(of: try section(.threatPictures, of: try page(of: project)))

        model.removeConnection(try #require(model.canvas.connections.first).id)

        let after = pictures(of: try section(.threatPictures, of: try page(of: project)))
        #expect(after.isEmpty == false)
        #expect(after != before)
    }

    // MARK: a diagram block

    private func aDiagramProject(kind: String, text: String) async -> ProjectSession {
        let (project, _) = await aProject(
            """
            system "Payments" {
              component "api" {
                technology = "aws-ec2"
                data       = "confidential"
              }
              diagram "Login" {
                kind = "\(kind)"
                text = "\(text)"
              }
            }

            """
        )
        return project
    }

    /// A mermaid block is a picture on the stage, not its own source text.
    @Test func drawsAMermaidBlockAsAPicture() async throws {
        let project = await aDiagramProject(kind: "mermaid", text: "graph TD; a-->b;")

        let section = try section(.diagrams, of: try page(of: project))

        #expect(pictures(of: section).count == 1)
        #expect(
            section.blocks.contains { block in
                if case .fenced = block { return true }
                return false
            } == false
        )
    }

    /// A mermaid diagram of a kind the reader does not read keeps its text
    /// too, so nothing a team wrote is lost.
    @Test func showsTheTextOfAMermaidBlockTheReaderDoesNotRead() async throws {
        let project = await aDiagramProject(kind: "mermaid", text: "sequenceDiagram")

        let section = try section(.diagrams, of: try page(of: project))

        #expect(section.blocks.contains(.fenced(kind: "mermaid", text: "sequenceDiagram")))
        #expect(
            section.blocks.contains(
                .paragraph(
                    "This window draws a mermaid flowchart. This diagram is not one,"
                        + " so the text is what it holds."
                )
            )
        )
    }

    // MARK: the history

    /// Two commits sampled draw the graph and the rows the Markdown writer
    /// writes.
    @Test func drawsTheRiskOverTimeSectionFromASampledHistory() async throws {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        useCases.history.add(
            hash: "aaaaaaaaaaaa",
            date: Date(timeIntervalSince1970: 1_600_000_000),
            files: ["threatmodel/payments.arch": payments]
        )
        useCases.history.add(
            hash: "bbbbbbbbbbbb",
            date: Date(timeIntervalSince1970: 1_700_000_000),
            files: ["threatmodel/payments.arch": payments]
        )
        let project = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await project.open(root: "/work")
        await project.sampleTheHistory()

        let section = try section(.riskOverTime, of: try page(of: project))

        #expect(section.title == "Risk over time")
        #expect(pictures(of: section).count == 1)
        #expect(
            section.blocks.contains { block in
                if case .table = block { return true }
                return false
            }
        )
    }

    /// A project nobody sampled says so and offers the sampling action.
    @Test func offersTheSamplingActionWithNoHistory() async throws {
        let (project, _) = await aProject()

        let section = try section(.riskOverTime, of: try page(of: project))

        #expect(
            section.blocks.contains { block in
                if case .sampleHistory = block { return true }
                return false
            }
        )
        #expect(pictures(of: section).isEmpty)
    }

    // MARK: the file the window writes

    /// The page `Generate Report` writes from the window holds the figures the
    /// executable's report verb writes for the same project.
    @Test func writesTheFigureCountTheReportVerbWrites() async throws {
        let (project, useCases) = await aProject()
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("report-figures-\(UUID().uuidString).html")
        project.reportFormat = .html
        await project.generateReport(chooseFile: { _, _ in url })
        let fromTheWindow = String(decoding: try Data(contentsOf: url), as: UTF8.self)
        try? FileManager.default.removeItem(at: url)

        var lines: [String] = []
        let code = CommandLineApplication(
            projects: useCases.project,
            catalogue: { CatalogueFixture.catalogue() }
        )
        .run(
            arguments: ["threatmodeller", "report", "/work", "--html", "--commits", "0"],
            output: { lines.append($0) }
        )
        #expect(code == 0, Comment(rawValue: lines.joined(separator: "\n")))
        let fromTheVerb = try #require(
            useCases.project.text(at: "/work/threatmodel/payments.html")
        )

        #expect(figures(in: fromTheWindow) > 1)
        #expect(figures(in: fromTheWindow) == figures(in: fromTheVerb))
    }

    /// The Markdown report the window writes holds the picture sections the
    /// verb writes, and the picture files beside it.
    @Test func writesTheMarkdownPicturesTheReportVerbWrites() async throws {
        let (project, useCases) = await aProject()

        project.reportFormat = .markdown
        await project.generateReport()

        let report = try #require(useCases.project.text(at: "/work/threatmodel/payments.md"))
        #expect(report.contains("## Top residual risk in detail"))
        #expect(
            useCases.project.text(at: "/work/threatmodel/payments-threat-1.svg")?
                .hasPrefix("<svg") == true
        )
    }

    private func figures(in html: String) -> Int {
        html.components(separatedBy: "<figure").count - 1
    }
}
