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
        case couldNotLoad(String)
    }

    func pdf(fromHtml html: String) async throws -> Data {
        let view = WKWebView(
            frame: CGRect(origin: .zero, size: Self.pageSize),
            configuration: WKWebViewConfiguration()
        )
        let delegate = LoadWatcher()
        view.navigationDelegate = delegate

        view.loadHTMLString(html, baseURL: nil)
        try await delegate.waitForLoad()

        let configuration = WKPDFConfiguration()
        configuration.rect = CGRect(origin: .zero, size: view.bounds.size)
        return try await view.pdf(configuration: configuration)
    }
}

/// Waits for one page to finish loading. `WKWebView` reports the load through
/// its delegate, and the print must not start before it.
@MainActor
private final class LoadWatcher: NSObject, WKNavigationDelegate {
    private var waiting: CheckedContinuation<Void, Error>?
    private var finished = false
    private var fault: Error?

    func waitForLoad() async throws {
        if finished { return }
        if let fault { throw fault }
        try await withCheckedThrowingContinuation { continuation in
            waiting = continuation
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        finished = true
        waiting?.resume()
        waiting = nil
    }

    func webView(
        _ webView: WKWebView,
        didFail navigation: WKNavigation!,
        withError error: Error
    ) {
        fault = error
        waiting?.resume(throwing: error)
        waiting = nil
    }
}
