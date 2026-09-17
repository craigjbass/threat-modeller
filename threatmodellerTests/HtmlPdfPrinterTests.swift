import Testing
import Foundation
@testable import threatmodeller

/// Says whether a test may start a WebKit content process.
///
/// The GitHub runner's sandbox refuses the first connection to a WebKit
/// content process, with
/// `Connection init failed at lookup with error 159 - Sandbox restriction`,
/// and WebKit retries. The retry costs tens of seconds, and the caller
/// waits for it on the main actor, so every other main actor test waits
/// too. The runner sets `THREATMODELLER_SKIP_WEBKIT` to `1` and runs no
/// test that loads a page. A developer machine sets no such value and runs
/// every one of them.
enum WebKitInTests {
    static var runs: Bool {
        ProcessInfo.processInfo.environment["THREATMODELLER_SKIP_WEBKIT"] == nil
    }
}

/// The page a person exports and the page the PDF prints are one page.
///
/// No test here loads a page, and no test here builds a `WKWebView`. Each
/// test reports the load outcome through the `LoadWatcher` entry points,
/// which run on the main actor and return at once. The two tests that load
/// a page sit in `HtmlPdfPrinterWebKitTests`, which the runner skips.
@MainActor
struct HtmlPdfPrinterTests {
    /// A navigation error with no meaning beyond its identity.
    private struct Boom: Error {}

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


/// The two `HtmlPdfPrinter` tests that load a page.
///
/// Each test starts a WebKit content process, and the wait for that start
/// holds the main actor. On run 35170183316 the wait cost
/// `throwsWhenTheFileIsNotThere()` 46.9 seconds and
/// `printsAPageToPdfBytes()` 101.8 seconds. On run 35172118320 neither test
/// returned in 106 seconds, the five `HtmlPdfPrinterTests` watcher tests
/// waited for the main actor past their one-minute limit, and the test
/// process was killed and restarted.
///
/// `WebKitInTests` says why the runner runs neither test.
/// `ReportExporterTests.writesEveryExportWhereTheUserSaid()` reads the same
/// value and leaves the PDF kind out on the runner, so the runner starts no
/// WebKit content process at all. This suite is serialized: one WebKit
/// content process starts at a time.
@Suite(.serialized, .enabled(if: WebKitInTests.runs))
@MainActor
struct HtmlPdfPrinterWebKitTests {
    /// The printer turns HTML into PDF bytes.
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
    /// This test carries no time limit. The start time belongs to WebKit,
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
}
