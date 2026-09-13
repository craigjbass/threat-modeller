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

    /// A navigation error that arrives before the page commits must not hang
    /// the wait. `waitForLoad()` checks a fault already on record before it
    /// creates a continuation, so calling the delegate method first, then
    /// awaiting, cannot suspend when the fix is correct. The time limit
    /// fails the test instead of hanging the suite when it is not.
    @Test(.timeLimit(.minutes(1)))
    func throwsRatherThanHangingWhenNavigationFailsBeforeItCommits() async {
        let watcher = LoadWatcher()
        struct Boom: Error {}
        watcher.webView(WKWebView(), didFailProvisionalNavigation: nil, withError: Boom())

        await #expect(throws: Boom.self) {
            try await watcher.waitForLoad()
        }
    }

    /// The content process can die mid-load with no `Error` of its own. The
    /// same structure as above proves `LoadWatcher` throws instead of
    /// leaving the caller waiting forever.
    @Test(.timeLimit(.minutes(1)))
    func throwsRatherThanHangingWhenTheContentProcessDies() async {
        let watcher = LoadWatcher()
        watcher.webViewWebContentProcessDidTerminate(WKWebView())

        await #expect(throws: HtmlPdfPrinter.Fault.self) {
            try await watcher.waitForLoad()
        }
    }
}
