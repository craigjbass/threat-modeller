import AppKit
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The History toolbar control, and what the window reads to draw it.
@MainActor
struct HistoryControlGuardTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private func aProject(open: Bool) async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        if open {
            await session.open(root: "/work")
        }
        return (session, useCases)
    }

    /// The window a person sees the project in, wide and tall enough that
    /// the toolbar draws every item in place rather than folding the
    /// History control into the overflow chevron.
    private func aProjectWindow(_ session: ProjectSession) -> NSWindow {
        hostedWindow(of: ProjectWindow(session: session).frame(minWidth: 1400, minHeight: 900))
    }

    /// The History toolbar item's own view, in window coordinates, so a test
    /// can click the point AppKit draws it at.
    private func historyControlFrame(in window: NSWindow) throws -> NSRect {
        let toolbar = try #require(window.toolbar, "the window drew no toolbar")
        let item = try #require(
            toolbar.items.first { $0.label == "History" },
            "the toolbar drew no History item"
        )
        let view = try #require(item.view, "the History item drew no view")
        return view.convert(view.bounds, to: nil)
    }

    /// A click on the History control while the session holds no history
    /// opens no sheet: the control is off.
    @Test func theHistoryControlIsOffWhileTheSessionHoldsNoHistory() async throws {
        let (session, _) = await aProject(open: false)
        let window = aProjectWindow(session)
        defer { window.orderOut(nil) }
        let frame = try historyControlFrame(in: window)

        click(window, at: NSPoint(x: frame.midX, y: frame.midY))
        settle(window, 0.5)

        #expect(window.attachedSheet == nil, "the History control opened a sheet with no history to read")
    }

    /// Runs the run loop in short steps until this holds, or a second
    /// passes. A poll finds work that finishes fast without paying the full
    /// wait every time, and still fails when the work never finishes.
    private func withinASecond(_ isTrue: () -> Bool) {
        let deadline = Date().addingTimeInterval(1)
        while isTrue() == false, Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.02))
        }
    }

    /// A click on the History control once the session holds history
    /// attaches the sheet within a second: the control is on.
    @Test func theHistoryControlIsOnOnceTheSessionHoldsHistory() async throws {
        let (session, _) = await aProject(open: true)
        let window = aProjectWindow(session)
        defer { window.orderOut(nil) }
        let frame = try historyControlFrame(in: window)

        click(window, at: NSPoint(x: frame.midX, y: frame.midY))
        withinASecond { window.attachedSheet != nil }

        #expect(window.attachedSheet != nil, "the History control opened no sheet within a second with history to read")
    }

    @Test func theSessionHoldsHistoryOnceAProjectIsOpenSoTheControlIsOn() async throws {
        let (closed, _) = await aProject(open: false)
        let (open, _) = await aProject(open: true)

        #expect(closed.history == nil, "a session with no project holds history")
        #expect(open.history != nil, "a session with a project open holds no history")
    }

    /// Opening the project window reads no history: the fake gateway's read
    /// count stays nought until a person presses Read.
    @Test func openingTheProjectWindowReadsNoHistory() async throws {
        let (session, useCases) = await aProject(open: true)
        let window = aProjectWindow(session)
        defer { window.orderOut(nil) }

        #expect(
            useCases.history.readCount == 0,
            "opening the window read history \(useCases.history.readCount) times"
        )
    }
}
