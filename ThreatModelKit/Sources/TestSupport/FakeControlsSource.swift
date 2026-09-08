import ThreatModelKit

/// Stands in for the real controls language in a test that is not about
/// parsing. It remembers what it wrote rather than reading text.
public final class FakeControlsSource: ControlsSourceGateway, @unchecked Sendable {
    private var byText: [String: ControlsSource] = [:]
    public private(set) var written: String?

    public init() {}

    public func read(_ text: String) -> ControlsRead {
        guard let source = byText[text] else {
            return ControlsRead(
                source: nil,
                diagnostics: [
                    Diagnostic(
                        severity: .error,
                        line: 1,
                        column: 1,
                        message: "this fake was never given that text"
                    )
                ]
            )
        }
        return ControlsRead(source: source, diagnostics: [])
    }

    public func write(_ source: ControlsSource) -> String {
        let text = "fake-controls:\(source.systemName):\(source.answers.count)"
        byText[text] = source
        written = text
        return text
    }
}
