import ThreatModelKit

/// Reads and writes the controls language.
public struct HclControlsSource: ControlsSourceGateway {
    public init() {}

    public func read(_ text: String) -> ControlsRead {
        let scanned = Lexer(text).scan()
        var parser = ControlsParser(tokens: scanned.tokens, faults: scanned.faults)
        return parser.parse()
    }

    public func write(_ source: ControlsSource) -> String {
        ControlsWriter().write(source)
    }
}
