import Testing
import Foundation
import WebKit
@testable import threatmodeller

/// The page a person exports and the page the PDF prints are one page.
@MainActor
struct HtmlPdfPrinterTests {
    @Test func printsAPageToPdfBytes() async throws {
        let data = try await HtmlPdfPrinter().pdf(
            fromHtml: "<html><body><h1>Payments</h1></body></html>"
        )

        #expect(data.isEmpty == false)
        #expect(data.starts(with: Array("%PDF".utf8)))
    }

    /// Runs the task until `waitForLoad()` stores its continuation. One
    /// `Task.yield()` does not promise the task reaches that point, so the
    /// test reads the watcher's own state instead. The time limit fails the
    /// test if the task never reaches the suspension point.
    private func waitUntilWaiting(_ watcher: LoadWatcher) async {
        while watcher.isWaiting == false {
            await Task.yield()
        }
    }

    /// A navigation error that arrives while `waitForLoad()` waits must
    /// resume the continuation, not just record the fault. A
    /// `resume(throwing:)` left out would leave the task waiting forever;
    /// the time limit fails the test instead of hanging the suite.
    @Test(.timeLimit(.minutes(1)))
    func throwsWhenNavigationFailsBeforeItCommitsWhileTheCallerWaits() async {
        let watcher = LoadWatcher()
        struct Boom: Error {}
        let task = Task { try await watcher.waitForLoad() }
        await waitUntilWaiting(watcher)
        watcher.webView(WKWebView(), didFailProvisionalNavigation: nil, withError: Boom())

        await #expect(throws: Boom.self) {
            try await task.value
        }
    }

    /// The load can end before anything calls `waitForLoad()`. The watcher
    /// keeps the fault and throws it at once when the wait begins.
    @Test(.timeLimit(.minutes(1)))
    func throwsWhenNavigationFailedBeforeTheCallerWaits() async {
        let watcher = LoadWatcher()
        struct Boom: Error {}
        watcher.webView(WKWebView(), didFailProvisionalNavigation: nil, withError: Boom())

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
        let task = Task { try await watcher.waitForLoad() }
        await waitUntilWaiting(watcher)
        watcher.webViewWebContentProcessDidTerminate(WKWebView())

        await #expect(throws: HtmlPdfPrinter.Fault.self) {
            try await task.value
        }
    }

    /// The content process can die before anything calls `waitForLoad()`.
    /// The watcher keeps that fault and throws it at once.
    @Test(.timeLimit(.minutes(1)))
    func throwsWhenTheContentProcessDiedBeforeTheCallerWaits() async {
        let watcher = LoadWatcher()
        watcher.webViewWebContentProcessDidTerminate(WKWebView())

        await #expect(throws: HtmlPdfPrinter.Fault.self) {
            try await watcher.waitForLoad()
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
