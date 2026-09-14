import ThreatModelKit

/// Reads and writes the attack tree language.
public struct HclAttackTreeSource: AttackTreeSourceGateway {
    public init() {}

    public func read(_ text: String) -> AttackTreeRead {
        let scanned = Lexer(text).scan()
        var parser = AttackTreeParser(tokens: scanned.tokens, faults: scanned.faults)
        return parser.parse()
    }

    public func write(_ source: AttackTreeSource) -> String {
        AttackTreeWriter().write(source)
    }
}
