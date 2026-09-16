import Testing
import Foundation
import WebKit
@testable import threatmodeller

/// The page a person exports and the page the PDF prints are one page.
@MainActor
struct HtmlPdfPrinterTests {
    /// A navigation error with no meaning beyond its identity.
    private struct Boom: Error {}

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
    /// cooperative pool, and a loaded test run can hold every thread of that
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
    ///
    /// The limit is five minutes, not one. The whole application suite takes
    /// about sixty seconds, and this test waits for a main queue block that
    /// sits behind the main actor work of the other tests. A one minute
    /// limit is the size of the whole suite, so a normal backlog failed the
    /// test. Five minutes still catches a continuation that is never
    /// resumed, because that one waits forever.
    @Test(.timeLimit(.minutes(5)))
    func throwsWhenNavigationFailsBeforeItCommitsWhileTheCallerWaits() async {
        let watcher = LoadWatcher()
        let view = WKWebView()
        fireFromTheMainQueue {
            watcher.webView(view, didFailProvisionalNavigation: nil, withError: Boom())
        }

        do {
            try await watcher.waitForLoad()
            Issue.record("did not throw")
        } catch {
            #expect(error is Boom)
        }
    }

    /// The load can end before anything calls `waitForLoad()`. The watcher
    /// keeps the fault and throws it at once when the wait begins.
    @Test(.timeLimit(.minutes(1)))
    func throwsWhenNavigationFailedBeforeTheCallerWaits() async {
        let watcher = LoadWatcher()
        watcher.webView(WKWebView(), didFailProvisionalNavigation: nil, withError: Boom())

        do {
            try await watcher.waitForLoad()
            Issue.record("did not throw")
        } catch {
            #expect(error is Boom)
        }
    }

    /// The content process can die mid-load with no `Error` of its own. The
    /// watcher resumes the waiting continuation instead of leaving the
    /// caller waiting forever.
    ///
    /// The limit is five minutes for the reason given on
    /// `throwsWhenNavigationFailsBeforeItCommitsWhileTheCallerWaits()`.
    @Test(.timeLimit(.minutes(5)))
    func throwsWhenTheContentProcessDiesWhileTheCallerWaits() async {
        let watcher = LoadWatcher()
        let view = WKWebView()
        fireFromTheMainQueue {
            watcher.webViewWebContentProcessDidTerminate(view)
        }

        do {
            try await watcher.waitForLoad()
            Issue.record("did not throw")
        } catch {
            #expect(error is HtmlPdfPrinter.Fault)
        }
    }

    /// The content process can die before anything calls `waitForLoad()`.
    /// The watcher keeps that fault and throws it at once.
    @Test(.timeLimit(.minutes(1)))
    func throwsWhenTheContentProcessDiedBeforeTheCallerWaits() async {
        let watcher = LoadWatcher()
        watcher.webViewWebContentProcessDidTerminate(WKWebView())

        do {
            try await watcher.waitForLoad()
            Issue.record("did not throw")
        } catch {
            #expect(error is HtmlPdfPrinter.Fault)
        }
    }

    /// A load that finished before the wait returns at once.
    @Test(.timeLimit(.minutes(1)))
    func returnsWhenTheLoadFinishedBeforeTheCallerWaits() async throws {
        let watcher = LoadWatcher()
        watcher.webView(WKWebView(), didFinish: nil)

        try await watcher.waitForLoad()
    }
}
