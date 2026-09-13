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

    /// A navigation error that arrives after `waitForLoad()` is already
    /// waiting must resume the continuation, not just record the fault. The
    /// task starts the wait first, yields so it reaches the suspension
    /// point, then the delegate method fires. A `resume(throwing:)` left out
    /// would leave the task waiting forever; the time limit fails the test
    /// instead of hanging the suite in that case.
    @Test(.timeLimit(.minutes(1)))
    func throwsRatherThanHangingWhenNavigationFailsBeforeItCommits() async {
        let watcher = LoadWatcher()
        struct Boom: Error {}
        let task = Task { try await watcher.waitForLoad() }
        await Task.yield()
        watcher.webView(WKWebView(), didFailProvisionalNavigation: nil, withError: Boom())

        await #expect(throws: Boom.self) {
            try await task.value
        }
    }

    /// The content process can die mid-load with no `Error` of its own. The
    /// same structure as above proves `LoadWatcher` resumes the waiting
    /// continuation instead of leaving the caller waiting forever.
    @Test(.timeLimit(.minutes(1)))
    func throwsRatherThanHangingWhenTheContentProcessDies() async {
        let watcher = LoadWatcher()
        let task = Task { try await watcher.waitForLoad() }
        await Task.yield()
        watcher.webViewWebContentProcessDidTerminate(WKWebView())

        await #expect(throws: HtmlPdfPrinter.Fault.self) {
            try await task.value
        }
    }
}
