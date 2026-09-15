import AppKit
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// A workspace that opens nothing and states what it was asked to open.
@MainActor
final class FakeWorkspace: Workspace {
    private(set) var opened: [String] = []
    private(set) var revealed: [String] = []
    /// What `open` answers. False stands for "no application opened it".
    var opens = true

    @discardableResult
    func open(path: String) -> Bool {
        opened.append(path)
        return opens
    }

    func reveal(path: String) {
        revealed.append(path)
    }
}

/// Opening the report this session wrote.
@MainActor
@Suite("The last report")
struct LastReportTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private func aProject() async -> (ProjectSession, FakeWorkspace) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        let workspace = FakeWorkspace()
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults(),
            workspace: workspace
        )
        await session.open(root: "/work")
        return (session, workspace)
    }

    @Test func opensNothingUntilAReportIsWritten() async {
        let (session, workspace) = await aProject()

        #expect(session.canOpenReport == false)
        session.openLastReport()

        #expect(workspace.opened.isEmpty)
    }

    @Test func opensTheReportThisSessionWrote() async throws {
        let (session, workspace) = await aProject()
        session.compileReport()
        let path = try #require(session.reportPath)

        #expect(session.canOpenReport)
        session.openLastReport()

        #expect(workspace.opened == [path])
    }

    @Test func showsTheReportInFinder() async throws {
        let (session, workspace) = await aProject()
        session.compileReport()
        let path = try #require(session.reportPath)

        session.revealLastReport()

        #expect(workspace.revealed == [path])
    }

    @Test func saysSoWhenNoApplicationOpensTheReport() async {
        let (session, workspace) = await aProject()
        workspace.opens = false
        session.compileReport()

        session.openLastReport()

        #expect(session.errorMessage?.contains("No application opened") == true)
    }
}

/// A fault a person can open and copy.
@MainActor
@Suite("The diagnostics sheet")
struct DiagnosticsSheetTests {
    private let faults = [
        Diagnostic(severity: .error, line: 3, column: 12, message: "kind is \"secret\""),
        Diagnostic(severity: .warning, line: 7, column: 1, message: "the zone holds no components"),
        Diagnostic(severity: .warning, line: 9, column: 4, message: "the flow names no kind")
    ]

    @Test func opensTheFileTheFaultBelongsTo() {
        let workspace = FakeWorkspace()
        let sheet = DiagnosticsSheet(
            fileName: "payments.arch",
            diagnostics: faults,
            dismiss: {},
            path: "/work/threatmodel/payments.arch",
            workspace: workspace
        )

        // What the row's button calls.
        workspace.open(path: sheet.path ?? "")

        #expect(workspace.opened == ["/work/threatmodel/payments.arch"])
    }

    @Test func copiesEveryRowTheWayTheCommandLinePrintsIt() {
        let sheet = DiagnosticsSheet(
            fileName: "payments.arch",
            diagnostics: faults,
            dismiss: {},
            path: "/work/threatmodel/payments.arch"
        )

        #expect(
            sheet.lines == [
                "/work/threatmodel/payments.arch:3:12: kind is \"secret\"",
                "/work/threatmodel/payments.arch:7:1: the zone holds no components",
                "/work/threatmodel/payments.arch:9:4: the flow names no kind"
            ]
        )
    }

    @Test func namesTheFileWhenThereIsNoPathToOpen() {
        let sheet = DiagnosticsSheet(
            fileName: "a library",
            diagnostics: faults,
            dismiss: {}
        )

        #expect(sheet.path == nil)
        #expect(sheet.lines[0].hasPrefix("a library:3:12:"))
    }

    @Test func statesThePathOfTheFileTheFaultsBelongTo() async {
        let useCases = TestDependencies()
        useCases.project.put(
            "system \"P\" {\n  zone \"z\" { kind = \"secret\" }\n}\n",
            at: "/work/threatmodel/p.arch"
        )
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")

        #expect(session.diagnostics.isEmpty == false)
        #expect(session.diagnosticsPath == "/work/threatmodel/p.arch")
    }
}
