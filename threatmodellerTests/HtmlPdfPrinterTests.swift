import Testing
import Foundation
@testable import threatmodeller

/// The page a person exports and the page the PDF prints are one page.
///
/// Only `printsAPageToPdfBytes()` and `throwsWhenTheFileIsNotThere()` load a
/// page, and both load it through `HtmlPdfPrinter`. No test builds a
/// `WKWebView`. A test that builds one holds the main actor while WebKit
/// starts a content process, and on the runner that wait passed the time
/// limit. Every other test reports the load outcome through the
/// `LoadWatcher` entry points, which run on the main actor and return at
/// once.
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

    /// The delegate wiring carries a real navigation failure to the caller.
    /// The printer loads a file path that is not there, WebKit reports the
    /// failure through `didFailProvisionalNavigation`, and `pdf(fromFileAt:)`
    /// throws the error WebKit gave.
    ///
    /// This test and `printsAPageToPdfBytes()` carry no time limit. Both
    /// start a WebKit content process, and the start time belongs to WebKit,
    /// not to `LoadWatcher`.
    @Test func throwsWhenTheFileIsNotThere() async {
        let missing = FileManager.default.temporaryDirectory
            .appendingPathComponent("no-such-report-\(UUID().uuidString).html")

        do {
            _ = try await HtmlPdfPrinter().pdf(fromFileAt: missing)
            Issue.record("did not throw")
        } catch {
            let fault = error as NSError
            #expect(fault.domain == NSURLErrorDomain)
            #expect(fault.code == NSURLErrorFileDoesNotExist)
        }
    }

    /// A navigation error that arrives while `waitForLoad()` waits must
    /// resume the continuation, not just record the fault. A
    /// `resume(throwing:)` left out would leave the caller waiting forever;
    /// the time limit fails the test instead of hanging the suite.
    ///
    /// The `onWaiting` hook runs the moment `waitForLoad()` stores the
    /// continuation, so the report lands while the caller waits with no
    /// queue hop and no wait on the clock.
    @Test(.timeLimit(.minutes(1)))
    func throwsWhenNavigationFailsBeforeItCommitsWhileTheCallerWaits() async {
        let watcher = LoadWatcher()
        watcher.onWaiting = { [weak watcher] in watcher?.loadFailed(Boom()) }

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
        watcher.loadFailed(Boom())

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
    @Test(.timeLimit(.minutes(1)))
    func throwsWhenTheContentProcessDiesWhileTheCallerWaits() async {
        let watcher = LoadWatcher()
        watcher.onWaiting = { [weak watcher] in watcher?.contentProcessDied() }

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
        watcher.contentProcessDied()

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
        watcher.loadFinished()

        try await watcher.waitForLoad()
    }
}
