import Foundation
import WebKit

/// Prints the report page to PDF.
///
/// The report has one path: `ExportModelAsMarkdown` writes it,
/// `ExportModelAsHtml` converts it, and this prints that page. A second
/// renderer would drift from the first, and the one this replaced did.
@MainActor
struct HtmlPdfPrinter {
    /// A4 at 72 points to the inch, which is what the page's stylesheet
    /// targets.
    static let pageSize = CGSize(width: 595, height: 842)

    enum Fault: Error {
        /// The WebKit content process died mid-load. No navigation callback
        /// carries an `Error` for this case, so `LoadWatcher` throws this
        /// one in its place.
        case webContentProcessTerminated
    }

    func pdf(fromHtml html: String) async throws -> Data {
        try await pdf { view in view.loadHTMLString(html, baseURL: nil) }
    }

    /// Prints the page at a file path.
    ///
    /// The delegate test loads an unreachable path through this call, so a
    /// real navigation failure reaches `LoadWatcher` through the delegate
    /// method. No test builds a `WKWebView` of its own.
    func pdf(fromFileAt url: URL) async throws -> Data {
        try await pdf { view in
            view.loadFileURL(
                url,
                allowingReadAccessTo: url.deletingLastPathComponent()
            )
        }
    }

    /// Builds the view, starts the load the caller gives, waits for the
    /// delegate, then prints the page.
    private func pdf(load: (WKWebView) -> Void) async throws -> Data {
        let view = WKWebView(
            frame: CGRect(origin: .zero, size: Self.pageSize),
            configuration: WKWebViewConfiguration()
        )
        let delegate = LoadWatcher()
        view.navigationDelegate = delegate

        load(view)
        try await delegate.waitForLoad()

        let configuration = WKPDFConfiguration()
        configuration.rect = CGRect(origin: .zero, size: view.bounds.size)
        return try await view.pdf(configuration: configuration)
    }
}

/// Waits for one page to finish loading. `WKWebView` reports the load through
/// its delegate, and the print must not start before it.
///
/// The load can end before the caller calls `waitForLoad()`, and it can end
/// in the gap between the call and the point where the continuation is
/// stored. `LoadWatcher` keeps the outcome, and `waitForLoad()` reads the
/// kept outcome inside the continuation body, where no other code on the
/// main actor runs between the read and the store. A caller that waits
/// after the load ended gets the outcome at once.
@MainActor
final class LoadWatcher: NSObject, WKNavigationDelegate {
    private var waiting: CheckedContinuation<Void, Error>?
    private var outcome: Result<Void, Error>?

    /// Runs the moment `waitForLoad()` stores the continuation. A test
    /// reports a load outcome from this hook, so the report arrives while
    /// the caller waits with no queue hop and no time-based wait. The
    /// printer leaves the hook empty.
    var onWaiting: (@MainActor () -> Void)?

    func waitForLoad() async throws {
        try await withCheckedThrowingContinuation { continuation in
            if let outcome {
                continuation.resume(with: outcome)
                return
            }
            waiting = continuation
            onWaiting?()
        }
    }

    /// The page finished loading. `webView(_:didFinish:)` forwards to this.
    func loadFinished() {
        end(with: .success(()))
    }

    /// The load failed with `error`. Both navigation failure delegate
    /// methods forward to this.
    func loadFailed(_ error: Error) {
        end(with: .failure(error))
    }

    /// The WebKit content process died mid-load.
    /// `webViewWebContentProcessDidTerminate(_:)` forwards to this.
    func contentProcessDied() {
        end(with: .failure(HtmlPdfPrinter.Fault.webContentProcessTerminated))
    }

    /// Records the outcome and resumes the waiting caller.
    private func end(with result: Result<Void, Error>) {
        guard outcome == nil else { return }
        outcome = result
        let continuation = waiting
        waiting = nil
        continuation?.resume(with: result)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        loadFinished()
    }

    func webView(
        _ webView: WKWebView,
        didFail navigation: WKNavigation!,
        withError error: Error
    ) {
        loadFailed(error)
    }

    func webView(
        _ webView: WKWebView,
        didFailProvisionalNavigation navigation: WKNavigation!,
        withError error: Error
    ) {
        loadFailed(error)
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        contentProcessDied()
    }
}
