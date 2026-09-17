import Foundation
import ThreatModelKit

/// Takes every report the layout search makes and draws some of them.
///
/// The search reports from its own thread, and redrawing the whole picture is
/// the most expensive thing the preview does. So `receive(_:)` stores the
/// report and returns: it takes a lock, reads the clock and asks for a redraw
/// at most once every `redrawInterval`. It never draws, and it never waits
/// for the window.
///
/// `drawTheLast()` asks for a redraw whatever the interval says, so the
/// preview ends on the final plan.
///
/// A redraw reads `latest` rather than a report carried on the call, so two
/// redraws that reach the window in either order both draw the newest report
/// and the final plan cannot be overtaken by an earlier one.
///
/// `docs/superpowers/specs/2026-09-17-layout-preview-design.md` states the
/// interval and the measurement behind it.
nonisolated final class LayoutPreviewSampler: @unchecked Sendable {
    /// How often the preview redraws, at most.
    ///
    /// On the sixty-component sample the search reports five plans in 0.359
    /// seconds, at 0, 0.015, 0.029, 0.195 and 0.359 seconds. This interval
    /// draws the first, the fourth and the fifth, and caps the window at ten
    /// redraws a second.
    static let redrawInterval: TimeInterval = 0.1

    private let lock = NSLock()
    private var newest: LayOutModelResponse?
    private var redrawnAt: TimeInterval?
    private var redraws = 0
    private let now: @Sendable () -> TimeInterval
    private let redraw: @Sendable () -> Void

    init(
        now: @escaping @Sendable () -> TimeInterval = { Date().timeIntervalSinceReferenceDate },
        redraw: @escaping @Sendable () -> Void
    ) {
        self.now = now
        self.redraw = redraw
    }

    /// What the search calls, on the search's own thread.
    func receive(_ report: LayOutModelResponse) {
        lock.lock()
        newest = report
        let reading = now()
        let isDue = redrawnAt.map { reading - $0 >= Self.redrawInterval } ?? true
        if isDue {
            redrawnAt = reading
            redraws += 1
        }
        lock.unlock()

        if isDue { redraw() }
    }

    /// Draws the newest report whatever the interval says. The load calls it
    /// once the search returns.
    func drawTheLast() {
        lock.lock()
        let hasAReport = newest != nil
        if hasAReport {
            redrawnAt = now()
            redraws += 1
        }
        lock.unlock()

        if hasAReport { redraw() }
    }

    /// The newest report, which is what a redraw draws.
    var latest: LayOutModelResponse? {
        lock.lock()
        defer { lock.unlock() }
        return newest
    }

    /// How many redraws this sampler has asked for.
    var redrawCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return redraws
    }
}
