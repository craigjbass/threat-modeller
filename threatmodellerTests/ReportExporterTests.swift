import Foundation
import Testing
import TestSupport
@testable import threatmodeller

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

    @Test func writesEveryExportWhereTheUserSaid() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("threat-modeller-export-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let session = session()

        for kind in ReportExporter.Kind.allCases {
            await exporter(session, writing: directory).export(kind)
        }

        let written = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
        #expect(
            written == [
                "Untitled.hcl", "Untitled.html", "Untitled.md", "Untitled.pdf", "Untitled.png"
            ]
        )
        #expect(session.errorMessage == nil)
    }

    @Test func writesThePageWithItsPicturesInside() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("threat-modeller-export-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        await exporter(session(), writing: directory).export(.html)

        let page = try String(
            contentsOf: directory.appendingPathComponent("Untitled.html"),
            encoding: .utf8
        )
        #expect(page.hasPrefix("<!doctype html>"))
        // The whole diagram, drawn by the same code the command line tool uses.
        #expect(page.contains("<figure class=\"whole\"><svg"))
        #expect(page.contains("src=") == false)
    }

    @Test func writesNothingWhenTheUserCancels() async {
        let session = session()
        let exporter = ReportExporter(session: session) { _, _ in nil }

        await exporter.export(.markdown)

        #expect(session.errorMessage == nil)
    }

    @Test func saysSoWhenTheFileCannotBeWritten() async {
        let session = session()
        let exporter = ReportExporter(session: session) { name, _ in
            URL(fileURLWithPath: "/no-such-directory-on-this-machine/\(name)")
        }

        await exporter.export(.markdown)

        #expect(session.errorMessage?.hasPrefix("The export could not be written:") == true)
    }
}
