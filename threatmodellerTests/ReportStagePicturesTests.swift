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
    /// export writes, within a small tolerance on each pixel.
    ///
    /// The stage and the export each run their own `ImageRenderer` pass over
    /// the same model value and the same area, at the same scale, so the two
    /// pictures hold the same components in the same place with the same
    /// colours. Two separate anti-aliased renders of the same shape are not
    /// bound to round every edge pixel to the same 8-bit value; issue #182
    /// measured a one-run-in-several difference of 1 unit on 16 of 500,480
    /// pixels, all on a mitigation arc's anti-aliased edge, with the model,
    /// the size and every other pixel unchanged. `pixelsMatch` allows that
    /// rounding and still fails on a real difference in content, position or
    /// colour, which moves many pixels by far more than the tolerance.
    @Test func drawsTheDataFlowPictureTheImageExportWrites() async throws {
        let (project, _) = await aProject()
        let model = try #require(project.model)

        let exported = try #require(await ReportExporter(session: model).data(for: .image))
        let onTheStage = try #require(ReportDataFlowPicture(session: model).pixels())

        #expect(pixelsMatch(onTheStage, exported.data))
    }

    /// True when every pixel of the two PNGs matches within `tolerance` on
    /// every channel. Nil from either argument, or a size mismatch between
    /// the two, is never a match.
    private func pixelsMatch(_ first: Data, _ second: Data, tolerance: Int = 4) -> Bool {
        guard let a = NSBitmapImageRep(data: first), let b = NSBitmapImageRep(data: second) else {
            return false
        }
        guard a.pixelsWide == b.pixelsWide,
            a.pixelsHigh == b.pixelsHigh,
            a.bytesPerRow == b.bytesPerRow,
            let bytesA = a.bitmapData,
            let bytesB = b.bitmapData
        else { return false }

        let count = a.bytesPerRow * a.pixelsHigh
        for offset in 0..<count {
            if abs(Int(bytesA[offset]) - Int(bytesB[offset])) > tolerance { return false }
        }
        return true
    }

    /// A one-unit rounding difference on every channel is still a match, and
    /// a colour the tolerance cannot cover is still a fault.
    @Test func pixelsMatchAllowsRoundingButNotAColourFault() {
        let red = solidPng(width: 2, height: 2, red: 200, green: 40, blue: 40)
        let redRoundedByOne = solidPng(width: 2, height: 2, red: 199, green: 41, blue: 39)
        let blue = solidPng(width: 2, height: 2, red: 40, green: 40, blue: 200)

        #expect(pixelsMatch(red, redRoundedByOne))
        #expect(pixelsMatch(red, blue) == false)
    }

    /// A flat PNG of one colour, the size the caller states.
    private func solidPng(width: Int, height: Int, red: UInt8, green: UInt8, blue: UInt8) -> Data {
        let image = NSImage(size: NSSize(width: width, height: height))
        image.lockFocus()
        NSColor(
            red: Double(red) / 255,
            green: Double(green) / 255,
            blue: Double(blue) / 255,
            alpha: 1
        ).setFill()
        NSRect(x: 0, y: 0, width: width, height: height).fill()
        image.unlockFocus()
        let bitmap = NSBitmapImageRep(
            bitmapDataPlanes: nil,
            pixelsWide: width,
            pixelsHigh: height,
            bitsPerSample: 8,
            samplesPerPixel: 4,
            hasAlpha: true,
            isPlanar: false,
            colorSpaceName: .deviceRGB,
            bytesPerRow: 0,
            bitsPerPixel: 0
        )!
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
        image.draw(at: .zero, from: .zero, operation: .copy, fraction: 1)
        NSGraphicsContext.restoreGraphicsState()
        return bitmap.representation(using: .png, properties: [:])!
    }

    /// The title's section holds the picture, which is where the page puts it.
    @Test func putsTheDataFlowPictureUnderTheTitle() async throws {
        let (project, _) = await aProject()

        let section = try section(.systemName, of: try page(of: project))

        #expect(section.blocks.contains(.dataFlow))
    }

    // MARK: the redraw signature

    /// Two reads of the signature give the same text when nothing about the
    /// picture changed between them.
    @Test func signatureHoldsStillWhenNothingChanged() async throws {
        let (project, _) = await aProject()
        let model = try #require(project.model)

        let before = ReportDataFlowPicture(session: model).signature
        let after = ReportDataFlowPicture(session: model).signature

        #expect(before == after)
    }

    /// A component that moves changes the signature, so the picture is
    /// drawn again at the component's new place.
    @Test func signatureChangesWhenAComponentMoves() async throws {
        let (project, _) = await aProject()
        let model = try #require(project.model)
        let component = try #require(model.canvas.components.first)
        let before = ReportDataFlowPicture(session: model).signature

        model.move([
            ComponentMove(componentId: component.id, x: component.x + 40, y: component.y + 40)
        ])

        #expect(ReportDataFlowPicture(session: model).signature != before)
    }

    /// A component given a different technology changes the signature.
    @Test func signatureChangesWhenATechnologyChanges() async throws {
        let (project, _) = await aProject()
        let model = try #require(project.model)
        let component = try #require(model.canvas.components.first)
        let before = ReportDataFlowPicture(session: model).signature

        model.changeTechnology(componentId: component.id, technologyId: "aws-waf")

        #expect(ReportDataFlowPicture(session: model).signature != before)
    }

    /// An answer given on the Controls stage, which changes a risk, changes
    /// the signature, so the picture is drawn again with the new risk shown.
    @Test func signatureChangesWhenAControlsStageAnswerChangesARisk() async throws {
        let (project, _) = await aProject()
        let model = try #require(project.model)
        let control = try #require(
            model.threats.first { $0.threatId == "credential-theft" }?.controls.first
        )
        let before = ReportDataFlowPicture(session: model).signature

        model.setControl(key: control.key, implemented: true)

        #expect(ReportDataFlowPicture(session: model).signature != before)
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
