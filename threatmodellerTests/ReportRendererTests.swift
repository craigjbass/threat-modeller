import AppKit
import Foundation
import PDFKit
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Spec section 12: the page layout is checked by eye. What is tested here is
/// that the bytes are a PDF, that there is at least one page, and that the
/// model's name is in the text.
struct PDFReportRendererTests {
    private func report(named name: String, components: Int = 1) -> Report {
        let app = TestDependencies()
        _ = app.renameThreatModel().execute(RenameThreatModelRequest(name: name))
        for index in 0 ..< components {
            _ = app.addComponent().execute(
                AddComponentRequest(
                    technologyId: index.isMultiple(of: 2) ? "aws-ec2" : "aws-rds",
                    x: Double(index) * 200,
                    y: 0,
                    sensitivity: "confidential"
                )
            )
        }
        return app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report
    }

    @Test func writesAPdfCarryingTheModelName() throws {
        let bytes = try PDFReportRenderer().render(report(named: "Payments"))

        let document = try #require(PDFDocument(data: Data(bytes)))
        #expect(document.pageCount >= 1)
        #expect(try #require(document.string).contains("Payments"))
    }

    @Test func writesAPdfForAModelWithNothingOnIt() throws {
        let bytes = try PDFReportRenderer().render(report(named: "Empty", components: 0))

        let document = try #require(PDFDocument(data: Data(bytes)))
        #expect(document.pageCount == 1)
        #expect(try #require(document.string).contains("None."))
    }

    @Test func runsOntoMorePagesWhenThereIsMoreToSay() throws {
        let bytes = try PDFReportRenderer().render(report(named: "Wide", components: 12))

        let document = try #require(PDFDocument(data: Data(bytes)))
        #expect(document.pageCount > 1)
    }
}

@MainActor
struct CanvasImageRendererTests {
    @Test func drawsThePngAtTwiceTheSizeItWasAskedFor() throws {
        let app = TestDependencies()
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 100, y: 100, sensitivity: "internal")
        )
        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())
        let area = app.exportModelAsImage().execute(ExportModelAsImageRequest())

        let data = try CanvasImageRenderer().png(of: canvas, area: area)

        let image = try #require(NSBitmapImageRep(data: data))
        #expect(image.pixelsWide == Int(area.width * CanvasImageRenderer.scale))
        #expect(image.pixelsHigh == Int(area.height * CanvasImageRenderer.scale))
    }

    @Test func drawsAPictureOfAnEmptyModel() throws {
        let app = TestDependencies()
        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())
        let area = app.exportModelAsImage().execute(ExportModelAsImageRequest())

        let data = try CanvasImageRenderer().png(of: canvas, area: area)

        #expect(NSBitmapImageRep(data: data) != nil)
    }
}

/// The exporter writes where the user says. These tests answer the panel with
/// a temporary file, so the whole path runs without one.
@MainActor
struct ReportExporterTests {
    private func session() -> ThreatModelSession {
        let session = ThreatModelSession(useCases: TestDependencies())
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        return session
    }

    private func exporter(
        _ session: ThreatModelSession,
        writing directory: URL,
        chosen: UnsafeMutablePointer<[String]>? = nil
    ) -> ReportExporter {
        ReportExporter(session: session) { suggestedName, _ in
            chosen?.pointee.append(suggestedName)
            return directory.appendingPathComponent(suggestedName)
        }
    }

    @Test func writesEveryExportWhereTheUserSaid() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("threat-modeller-export-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let session = session()

        for kind in ReportExporter.Kind.allCases {
            exporter(session, writing: directory).export(kind)
        }

        let written = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
        #expect(written == ["Untitled.hcl", "Untitled.md", "Untitled.pdf", "Untitled.png"])
        #expect(session.errorMessage == nil)
    }

    @Test func writesNothingWhenTheUserCancels() throws {
        let session = session()
        let exporter = ReportExporter(session: session) { _, _ in nil }

        exporter.export(.markdown)

        #expect(session.errorMessage == nil)
    }

    @Test func saysSoWhenTheFileCannotBeWritten() {
        let session = session()
        let exporter = ReportExporter(session: session) { name, _ in
            URL(fileURLWithPath: "/no-such-directory-on-this-machine/\(name)")
        }

        exporter.export(.markdown)

        #expect(session.errorMessage?.hasPrefix("The export could not be written:") == true)
    }
}
