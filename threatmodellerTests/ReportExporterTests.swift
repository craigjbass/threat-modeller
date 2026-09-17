import DiagramRendering
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

    /// The picture the diagram writers draw from, built the same way
    /// `threatmodeller draw` builds it, so a test can call a writer directly
    /// and compare its bytes with what the window wrote.
    private func drawnModel(_ dependencies: TestDependencies) -> DiagramBuilder.Model {
        let canvas = dependencies.viewThreatModel().execute(ViewThreatModelRequest())
        let assessment = dependencies.assessThreatModel().execute(AssessThreatModelRequest())
        return DiagramBuilder.Model(
            components: canvas.components,
            connections: canvas.connections,
            zones: canvas.zones,
            risks: ElementRiskRollup.byElement(
                assessment.threats,
                levelOrder: assessment.severities.map(\.id)
            ),
            guards: EdgeGuards.byElement(assessment.threats)
        )
    }

    @Test func writesEveryExportWhereTheUserSaid() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("threat-modeller-export-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let session = session()

        // The PDF export loads the report page through WebKit, and the
        // runner runs no WebKit content process. Every other kind writes
        // its file there.
        let kinds = ReportExporter.Kind.allCases.filter { WebKitInTests.runs || $0 != .pdf }
        for kind in kinds {
            await exporter(session, writing: directory).export(kind)
        }

        // The Markdown report links its pictures by file name, so the export
        // writes each picture beside the report.
        var wanted = [
            "Untitled.d2", "Untitled.dot", "Untitled.hcl", "Untitled.html", "Untitled.json",
            "Untitled.md", "Untitled.mmd", "Untitled.otm.json", "Untitled.pdf", "Untitled.png"
        ] + session.reportPictureFiles().keys
        wanted.sort()
        if WebKitInTests.runs == false { wanted.removeAll { $0 == "Untitled.pdf" } }

        let written = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
        #expect(written == wanted)
        #expect(session.errorMessage == nil)
    }

    /// `ThreatModelCommands` draws one menu item per `Kind`, in this order,
    /// so this order is the menu order.
    @Test func dotAndD2SitBesideMermaidInTheExportMenu() {
        let kinds = ReportExporter.Kind.allCases
        guard let mermaidIndex = kinds.firstIndex(of: .mermaid) else {
            Issue.record("mermaid is missing from the export kinds")
            return
        }
        #expect(kinds[kinds.index(after: mermaidIndex)] == .dot)
        #expect(kinds[kinds.index(mermaidIndex, offsetBy: 2)] == .d2)
        #expect(ReportExporter.Kind.dot.menuTitle == "Export as DOT\u{2026}")
        #expect(ReportExporter.Kind.d2.menuTitle == "Export as D2\u{2026}")
    }

    /// The window's DOT export runs the same writer the executable's
    /// `draw --dot` verb runs, on the same picture, so the two write the same
    /// bytes for the same system.
    @Test func writesTheSameDotBytesTheExecutableWrites() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("threat-modeller-export-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let dependencies = TestDependencies()
        let session = ThreatModelSession(useCases: dependencies)
        session.add(technologyId: "aws-ec2", x: 0, y: 0)

        await exporter(session, writing: directory).export(.dot)

        let written = try String(
            contentsOf: directory.appendingPathComponent("Untitled.dot"),
            encoding: .utf8
        )
        let fromExecutable = TextDiagramWriter.dot(of: drawnModel(dependencies))
        #expect(written == fromExecutable)
    }

    /// The window's D2 export runs the same writer the executable's
    /// `draw --d2` verb runs, on the same picture, so the two write the same
    /// bytes for the same system.
    @Test func writesTheSameD2BytesTheExecutableWrites() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("threat-modeller-export-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let dependencies = TestDependencies()
        let session = ThreatModelSession(useCases: dependencies)
        session.add(technologyId: "aws-ec2", x: 0, y: 0)

        await exporter(session, writing: directory).export(.d2)

        let written = try String(
            contentsOf: directory.appendingPathComponent("Untitled.d2"),
            encoding: .utf8
        )
        let fromExecutable = TextDiagramWriter.d2(of: drawnModel(dependencies))
        #expect(written == fromExecutable)
    }

    @Test func proposesTheDotAndD2FileNames() async {
        var chosenNames: [String] = []
        let dotExporter = ReportExporter(session: session()) { suggestedName, _ in
            chosenNames.append(suggestedName)
            return nil
        }
        await dotExporter.export(.dot)

        let d2Exporter = ReportExporter(session: session()) { suggestedName, _ in
            chosenNames.append(suggestedName)
            return nil
        }
        await d2Exporter.export(.d2)

        #expect(chosenNames == ["Untitled.dot", "Untitled.d2"])
    }

    @Test func saysSoWhenTheDotFileCannotBeWritten() async {
        let session = session()
        let exporter = ReportExporter(session: session) { name, _ in
            URL(fileURLWithPath: "/no-such-directory-on-this-machine/\(name)")
        }

        await exporter.export(.dot)

        #expect(session.errorMessage?.hasPrefix("The export could not be written:") == true)
    }

    @Test func saysSoWhenTheD2FileCannotBeWritten() async {
        let session = session()
        let exporter = ReportExporter(session: session) { name, _ in
            URL(fileURLWithPath: "/no-such-directory-on-this-machine/\(name)")
        }

        await exporter.export(.d2)

        #expect(session.errorMessage?.hasPrefix("The export could not be written:") == true)
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
