import AppKit
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Where the project window puts its parts, measured in a real window.
///
/// `ImageRenderer` draws a view but tells nothing about what covers what. These
/// tests put the window in an `NSWindow`, let AppKit lay it out, and read the
/// frames back.
@MainActor
struct WindowLayoutTests {
    private static let width = 1200.0
    private static let height = 800.0

    private func aDrawnProject() -> ProjectSession {
        let useCases = TestDependencies()
        useCases.project.put(
            """
            system "Payments" {
              component "api" {
                technology = "aws-ec2"
                data       = "confidential"
              }
            }

            """,
            at: "/work/threatmodel/payments.arch"
        )
        let session = ProjectSession(useCases: useCases, watcher: FakeProjectWatcher(), defaults: aTestDefaults())
        session.open(root: "/work")
        return session
    }

    /// A window holding the view, laid out.
    private func laidOut(_ view: some View) -> NSWindow {
        let hosting = NSHostingView(rootView: view)
        hosting.frame = NSRect(x: 0, y: 0, width: Self.width, height: Self.height)
        let window = NSWindow(
            contentRect: hosting.frame,
            styleMask: [.titled, .closable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.contentView = hosting
        hosting.layoutSubtreeIfNeeded()
        RunLoop.current.run(until: Date().addingTimeInterval(1))
        hosting.layoutSubtreeIfNeeded()
        return window
    }

    /// The split view holding the three columns.
    private func columns(in view: NSView) -> NSSplitView? {
        if let split = view as? NSSplitView { return split }
        for child in view.subviews {
            if let split = columns(in: child) { return split }
        }
        return nil
    }

    /// Every view drawn outside the columns, as one rectangle in window
    /// coordinates. That is the chrome: the workflow bar and the notices under
    /// it.
    private func chrome(in view: NSView, outside columns: NSSplitView) -> NSRect? {
        if view === columns { return nil }

        var rectangle: NSRect?
        for child in view.subviews {
            guard let found = chrome(in: child, outside: columns) else { continue }
            rectangle = rectangle.map { $0.union(found) } ?? found
        }
        if rectangle != nil { return rectangle }

        let own = view.convert(view.bounds, to: nil)
        guard view.subviews.isEmpty, own.width > 0, own.height > 0 else { return nil }
        return own
    }

    /// The workflow bar sits above the columns, not over them.
    ///
    /// `safeAreaInset` does not inset a `NavigationSplitView` on macOS: the
    /// columns still take the whole window, so a bar drawn that way covers the
    /// top of the palette and of the threat sidebar, and no scroll brings that
    /// top back into view.
    @Test func keepsTheWorkflowBarAboveTheColumns() throws {
        let window = laidOut(ProjectWindow(session: aDrawnProject()))
        let content = try #require(window.contentView)
        let columns = try #require(self.columns(in: content))
        let bar = try #require(chrome(in: content, outside: columns))

        let columnsTop = columns.convert(columns.bounds, to: nil).maxY

        #expect(
            bar.minY >= columnsTop,
            "the chrome sits at \(bar.minY)…\(bar.maxY) and the columns reach \(columnsTop)"
        )
    }
}
