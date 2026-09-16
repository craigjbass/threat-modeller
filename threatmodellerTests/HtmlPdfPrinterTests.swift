import Testing
import Foundation
import WebKit
@testable import threatmodeller

/// The page a person exports and the page the PDF prints are one page.
@MainActor
struct HtmlPdfPrinterTests {
    /// A navigation error with no meaning beyond its identity.
    private struct Boom: Error {}

    /// The one test that builds a web view. It builds the web view through
    /// `HtmlPdfPrinter`, which is the path the product runs. Every other
    /// test calls the `LoadWatcher` entry points that the delegate methods
    /// call, so no other test starts a WebKit content process.
    @Test func printsAPageToPdfBytes() async throws {
        let data = try await HtmlPdfPrinter().pdf(
            fromHtml: "<html><body><h1>Payments</h1></body></html>"
        )

        #expect(data.isEmpty == false)
        #expect(data.starts(with: Array("%PDF".utf8)))
    }

    /// A navigation error that arrives while `waitForLoad()` waits must
    /// resume the continuation, not just record the fault. The `onWaiting`
    /// hook reports the fault at the point the continuation is stored, so
    /// the test needs no second task and no scheduling order. A
    /// `resume(throwing:)` left out would leave the caller waiting forever;
    /// the time limit fails the test instead of hanging the suite.
    @Test(.timeLimit(.minutes(1)))
    func throwsWhenTheLoadFailsWhileTheCallerWaits() async {
        let watcher = LoadWatcher()
        watcher.onWaiting = { [weak watcher] in
            watcher?.loadFailed(Boom())
        }

        await #expect(throws: Boom.self) {
            try await watcher.waitForLoad()
        }
    }

    /// The load can end before anything calls `waitForLoad()`. The watcher
    /// keeps the fault and throws it at once when the wait begins.
    @Test(.timeLimit(.minutes(1)))
    func throwsWhenTheLoadFailedBeforeTheCallerWaits() async {
        let watcher = LoadWatcher()
        watcher.loadFailed(Boom())

        await #expect(throws: Boom.self) {
            try await watcher.waitForLoad()
        }
    }

    /// The content process can die mid-load with no `Error` of its own. The
    /// watcher resumes the waiting continuation instead of leaving the
    /// caller waiting forever.
    @Test(.timeLimit(.minutes(1)))
    func throwsWhenTheContentProcessDiesWhileTheCallerWaits() async {
        let watcher = LoadWatcher()
        watcher.onWaiting = { [weak watcher] in
            watcher?.contentProcessDied()
        }

        await #expect(throws: HtmlPdfPrinter.Fault.self) {
            try await watcher.waitForLoad()
        }
    }

    /// The content process can die before anything calls `waitForLoad()`.
    /// The watcher keeps that fault and throws it at once.
    @Test(.timeLimit(.minutes(1)))
    func throwsWhenTheContentProcessDiedBeforeTheCallerWaits() async {
        let watcher = LoadWatcher()
        watcher.contentProcessDied()

        await #expect(throws: HtmlPdfPrinter.Fault.self) {
            try await watcher.waitForLoad()
        }
    }

    /// A load that finished before the wait returns at once.
    @Test(.timeLimit(.minutes(1)))
    func returnsWhenTheLoadFinishedBeforeTheCallerWaits() async throws {
        let watcher = LoadWatcher()
        watcher.loadFinished()

        try await watcher.waitForLoad()
    }

    /// A load that finishes while the caller waits resumes the caller.
    @Test(.timeLimit(.minutes(1)))
    func returnsWhenTheLoadFinishesWhileTheCallerWaits() async throws {
        let watcher = LoadWatcher()
        watcher.onWaiting = { [weak watcher] in
            watcher?.loadFinished()
        }

        try await watcher.waitForLoad()
    }

    /// The first outcome stands. A second report changes nothing, and it
    /// must not resume a continuation a second time.
    @Test(.timeLimit(.minutes(1)))
    func keepsTheFirstOutcomeWhenASecondReportArrives() async throws {
        let watcher = LoadWatcher()
        watcher.loadFinished()
        watcher.loadFailed(Boom())

        try await watcher.waitForLoad()
        try await watcher.waitForLoad()
    }
}
