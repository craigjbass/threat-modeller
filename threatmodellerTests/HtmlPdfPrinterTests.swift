import Testing
import Foundation
import WebKit
@testable import threatmodeller

/// The page a person exports and the page the PDF prints are one page.
@MainActor
struct HtmlPdfPrinterTests {
    /// A navigation error with no meaning beyond its identity.
    private struct Boom: Error {}

    /// The delegate methods never read the web view they are given. One view
    /// serves every test here, because each new `WKWebView` costs main
    /// thread time that the test does not need to spend.
    private static let view = WKWebView()

    @Test func printsAPageToPdfBytes() async throws {
        let data = try await HtmlPdfPrinter().pdf(
            fromHtml: "<html><body><h1>Payments</h1></body></html>"
        )

        #expect(data.isEmpty == false)
        #expect(data.starts(with: Array("%PDF".utf8)))
    }

    /// Fires one delegate method from the main queue. The main actor runs
    /// the main queue, so the call lands as soon as the waiting test
    /// releases the main actor. A `Task` would need a thread from the
    /// cooperative pool, and a loaded test run can hold every thread in that
    /// pool for longer than the time limit.
    private func fireFromTheMainQueue(_ call: @escaping @Sendable @MainActor () -> Void) {
        DispatchQueue.main.async {
            MainActor.assumeIsolated { call() }
        }
    }

    /// A navigation error that arrives while `waitForLoad()` waits must
    /// resume the continuation, not just record the fault. A
    /// `resume(throwing:)` left out would leave the caller waiting forever;
    /// the time limit fails the test instead of hanging the suite.
    @Test(.timeLimit(.minutes(1)))
    func throwsWhenNavigationFailsBeforeItCommitsWhileTheCallerWaits() async {
        let watcher = LoadWatcher()
        fireFromTheMainQueue {
            watcher.webView(Self.view, didFailProvisionalNavigation: nil, withError: Boom())
        }

        await #expect(throws: Boom.self) {
            try await watcher.waitForLoad()
        }
    }

    /// The load can end before anything calls `waitForLoad()`. The watcher
    /// keeps the fault and throws it at once when the wait begins.
    @Test(.timeLimit(.minutes(1)))
    func throwsWhenNavigationFailedBeforeTheCallerWaits() async {
        let watcher = LoadWatcher()
        watcher.webView(Self.view, didFailProvisionalNavigation: nil, withError: Boom())

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
        fireFromTheMainQueue {
            watcher.webViewWebContentProcessDidTerminate(Self.view)
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
        watcher.webViewWebContentProcessDidTerminate(Self.view)

        await #expect(throws: HtmlPdfPrinter.Fault.self) {
            try await watcher.waitForLoad()
        }
    }

    /// A load that finished before the wait returns at once.
    @Test(.timeLimit(.minutes(1)))
    func returnsWhenTheLoadFinishedBeforeTheCallerWaits() async throws {
        let watcher = LoadWatcher()
        watcher.webView(Self.view, didFinish: nil)

        try await watcher.waitForLoad()
    }

    /// A load that finishes while the caller waits resumes the caller.
    @Test(.timeLimit(.minutes(1)))
    func returnsWhenTheLoadFinishesWhileTheCallerWaits() async throws {
        let watcher = LoadWatcher()
        fireFromTheMainQueue {
            watcher.webView(Self.view, didFinish: nil)
        }

        try await watcher.waitForLoad()
    }

    /// A second delegate call after the load ended must not resume a
    /// continuation twice, and must not change the outcome.
    @Test(.timeLimit(.minutes(1)))
    func keepsTheFirstOutcomeWhenASecondDelegateCallArrives() async throws {
        let watcher = LoadWatcher()
        watcher.webView(Self.view, didFinish: nil)
        watcher.webView(Self.view, didFailProvisionalNavigation: nil, withError: Boom())

        try await watcher.waitForLoad()
        try await watcher.waitForLoad()
    }
}
