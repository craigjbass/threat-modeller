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

    /// Issue #144. A `.governance` file written before the key fix holds two
    /// blocks with one key. The parser refuses the whole file, so the window
    /// does not open the system and nothing reads the owners inside it.
    ///
    /// The repair merges the blocks that share a key and writes the file
    /// again. It states `repaired` only when the file it wrote parses with no
    /// fault, so a repair never hands back a file the parser still refuses.
    public func repair(_ text: String) -> GovernanceRepair {
        let scanned = Lexer(text).scan()
        var parser = GovernanceParser(tokens: scanned.tokens, faults: scanned.faults)
        let read = parser.parseKeepingEveryBlock()

        guard read.hasErrors else { return .notNeeded }
        guard let source = read.source else { return .cannotRepair(diagnostics: read.diagnostics) }

        let merged = source.keysGovernedTwice + source.labelsGovernedTwice
        guard merged.isEmpty == false else { return .cannotRepair(diagnostics: read.diagnostics) }

        let written = write(source.mergingBlocksThatShareAKey())
        guard self.read(written).hasErrors == false else {
            return .cannotRepair(diagnostics: read.diagnostics)
        }
        return .repaired(text: written, merged: merged)
    }
}
