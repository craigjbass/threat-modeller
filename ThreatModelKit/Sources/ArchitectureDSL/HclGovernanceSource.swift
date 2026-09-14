import ThreatModelKit

/// Reads and writes a `.governance` file in the language of section 8 of the
/// language guide.
public struct HclGovernanceSource: GovernanceSourceGateway {
    public init() {}

    public func read(_ text: String) -> GovernanceRead {
        let scanned = Lexer(text).scan()
        var parser = GovernanceParser(tokens: scanned.tokens, faults: scanned.faults)
        return parser.parse()
    }

    public func write(_ source: GovernanceSource) -> String {
        GovernanceWriter().write(source)
    }
}
