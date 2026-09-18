import AppKit
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// A real `NSEvent` local monitor gives back an opaque token, with no way to
/// ask how many are active. This fake counts installs and removals instead,
/// so a test can state that a stage switch and back leaves one monitor
/// running, not two.
@MainActor
private final class FakeLocalEventMonitoring: LocalEventMonitoring {
    private(set) var activeCount = 0
    private(set) var installCount = 0

    /// One token per install, so a removal of the wrong token would show up
    /// as a count that never reaches nought.
    private final class Token {}

    func addLocalMonitor(
        matching mask: NSEvent.EventTypeMask,
        handler: @escaping (NSEvent) -> NSEvent?
    ) -> Any? {
        installCount += 1
        activeCount += 1
        return Token()
    }

    func removeMonitor(_ monitor: Any) {
        activeCount -= 1
    }
}

/// Shows or hides the canvas the way `ProjectColumns` shows or hides it on a
/// stage switch: the canvas leaves the view tree, and a switch back builds a
/// fresh one. `@Observable` carries the flip into the hosted view without a
/// `@State`, which a test outside the view cannot reach.
@MainActor
@Observable
private final class StageSwitch {
    var isShown = true
}

private struct ToggledCanvas: View {
    let session: ThreatModelSession
    let canvas: CanvasState
    let monitors: FakeLocalEventMonitoring
    let stage: StageSwitch

    var body: some View {
        if stage.isShown {
            CanvasView(session: session, canvas: canvas, eventMonitors: monitors)
        } else {
            Color.clear
        }
    }
}

private struct ToggledTreeCanvas: View {
    let editor: TreeEditor
    let canvas: TreeCanvasState
    let monitors: FakeLocalEventMonitoring
    let stage: StageSwitch

    var body: some View {
        if stage.isShown {
            TreeCanvas(editor: editor, canvas: canvas, elements: [], bound: nil, eventMonitors: monitors)
        } else {
            Color.clear
        }
    }
}

/// What the diagram and the tree canvas hold for a hosted view: the window
/// keeps it on screen, so `.onAppear` and `.onDisappear` fire the way they
/// do in the running application.
@MainActor
private func hosted(_ view: some View) -> (host: NSHostingView<AnyView>, window: NSWindow) {
    let host = NSHostingView(rootView: AnyView(view.frame(width: 400, height: 300)))
    host.frame = CGRect(x: 0, y: 0, width: 400, height: 300)
    let window = NSWindow(
        contentRect: host.frame,
        styleMask: [.titled],
        backing: .buffered,
        defer: false
    )
    window.contentView = host
    window.orderBack(nil)
    host.layoutSubtreeIfNeeded()
    RunLoop.current.run(until: Date().addingTimeInterval(0.3))
    return (host, window)
}

/// A stage switch away and back must leave one scroll monitor running, not
/// two stacked on top of each other, and the canvas leaves none behind once
/// it is gone for good.
@MainActor
@Suite("The scroll monitor's lifetime")
struct ScrollMonitorTests {
    @Test func oneScrollMonitorRunsAfterAStageSwitchAndBackOnTheDiagram() {
        let session = ThreatModelSession(useCases: TestDependencies())
        let canvas = CanvasState()
        let monitors = FakeLocalEventMonitoring()
        let stage = StageSwitch()
        let (host, _) = hosted(ToggledCanvas(session: session, canvas: canvas, monitors: monitors, stage: stage))

        #expect(monitors.activeCount == 1)

        stage.isShown = false
        host.layoutSubtreeIfNeeded()
        RunLoop.current.run(until: Date().addingTimeInterval(0.3))
        #expect(monitors.activeCount == 0)

        stage.isShown = true
        host.layoutSubtreeIfNeeded()
        RunLoop.current.run(until: Date().addingTimeInterval(0.3))
        #expect(monitors.activeCount == 1)
        #expect(monitors.installCount == 2)

        stage.isShown = false
        host.layoutSubtreeIfNeeded()
        RunLoop.current.run(until: Date().addingTimeInterval(0.3))
        #expect(monitors.activeCount == 0)
    }

    @Test func oneScrollMonitorRunsAfterAStageSwitchAndBackOnTheTreeCanvas() {
        let editor = TreeEditor()
        let canvas = TreeCanvasState()
        let monitors = FakeLocalEventMonitoring()
        let stage = StageSwitch()
        let (host, _) = hosted(ToggledTreeCanvas(editor: editor, canvas: canvas, monitors: monitors, stage: stage))

        #expect(monitors.activeCount == 1)

        stage.isShown = false
        host.layoutSubtreeIfNeeded()
        RunLoop.current.run(until: Date().addingTimeInterval(0.3))
        #expect(monitors.activeCount == 0)

        stage.isShown = true
        host.layoutSubtreeIfNeeded()
        RunLoop.current.run(until: Date().addingTimeInterval(0.3))
        #expect(monitors.activeCount == 1)
        #expect(monitors.installCount == 2)

        stage.isShown = false
        host.layoutSubtreeIfNeeded()
        RunLoop.current.run(until: Date().addingTimeInterval(0.3))
        #expect(monitors.activeCount == 0)
    }
}
