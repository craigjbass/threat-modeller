import ThreatModelKit

/// Stands in for the real language in a test that is not about parsing.
///
/// It holds the source it was last given rather than reading text, so a test
/// can state what a file says without writing one.
public final class FakeArchitectureSource: ArchitectureSourceGateway, @unchecked Sendable {
    /// What the next read returns, whatever the text says.
    public var nextRead: ArchitectureRead?
    /// What the last write produced.
    public private(set) var written: String?

    private var byText: [String: ArchitectureSource] = [:]

    public init() {}

    public func read(_ text: String) -> ArchitectureRead {
        if let nextRead { return nextRead }
        guard let source = byText[text] else {
            return ArchitectureRead(
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
        return ArchitectureRead(source: source, diagnostics: [])
    }

    public func write(_ source: ArchitectureSource) -> String {
        let text = "fake:\(source.systemName):\(source.everyComponent.count)"
        byText[text] = source
        written = text
        return text
    }
}
