import Foundation
import Testing
import TestSupport
import ThreatModelKit
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
                "Untitled.hcl", "Untitled.html", "Untitled.json", "Untitled.md",
                "Untitled.mmd", "Untitled.otm.json", "Untitled.pdf", "Untitled.png"
            ]
        )
        #expect(session.errorMessage == nil)
    }

    /// `ThreatModelCommands` draws one menu item per `Kind`, in this order,
    /// so this order is the menu order.
    @Test func otmSitsNextToJsonInTheExportMenu() {
        let kinds = ReportExporter.Kind.allCases
        guard let jsonIndex = kinds.firstIndex(of: .json) else {
            Issue.record("json is missing from the export kinds")
            return
        }
        #expect(kinds[kinds.index(after: jsonIndex)] == .otm)
        #expect(ReportExporter.Kind.otm.menuTitle == "Export as OTM\u{2026}")
    }

    /// The window's OTM export runs `ExportModelAsOtm` through the same
    /// factory the executable's `export --format otm` verb runs, so the two
    /// write the same bytes for the same system.
    @Test func writesTheSameBytesTheExecutableWrites() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("threat-modeller-export-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let dependencies = TestDependencies()
        let session = ThreatModelSession(useCases: dependencies)
        session.add(technologyId: "aws-ec2", x: 0, y: 0)

        await exporter(session, writing: directory).export(.otm)

        let written = try Data(contentsOf: directory.appendingPathComponent("Untitled.otm.json"))
        let fromExecutable = dependencies.exportModelAsOtm().execute(ExportModelAsOtmRequest())
        #expect(written == Data(fromExecutable.json.utf8))
    }

    @Test func proposesTheOtmFileName() async {
        var chosenNames: [String] = []
        let exporter = ReportExporter(session: session()) { suggestedName, _ in
            chosenNames.append(suggestedName)
            return nil
        }

        await exporter.export(.otm)

        #expect(chosenNames == ["Untitled.otm.json"])
    }

    @Test func saysSoWhenTheOtmFileCannotBeWritten() async {
        let session = session()
        let exporter = ReportExporter(session: session) { name, _ in
            URL(fileURLWithPath: "/no-such-directory-on-this-machine/\(name)")
        }

        await exporter.export(.otm)

        #expect(session.errorMessage?.hasPrefix("The export could not be written:") == true)
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
