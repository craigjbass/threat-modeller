import ThreatModelKit

/// Reads and writes the architecture language.
public struct HclArchitectureSource: ArchitectureSourceGateway {
    public init() {}

    public func read(_ text: String) -> ArchitectureRead {
        let scanned = Lexer(text).scan()
        var parser = ArchitectureParser(tokens: scanned.tokens, faults: scanned.faults)
        return parser.parse()
    }

    public func write(_ source: ArchitectureSource) -> String {
        ArchitectureWriter().write(source)
    }
}
