import ThreatModelKit

/// The library language over the lexer, the parser and the writer.
public struct HclLibrarySource: LibrarySourceGateway {
    public init() {}

    public func read(_ text: String) -> LibraryRead {
        let scanned = Lexer(text).scan()
        var parser = LibraryParser(tokens: scanned.tokens, faults: scanned.faults)
        return parser.parse()
    }

    public func write(_ source: LibrarySource) -> String {
        LibraryWriter().write(source)
    }
}
