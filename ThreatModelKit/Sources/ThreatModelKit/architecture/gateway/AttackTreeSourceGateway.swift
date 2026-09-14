/// Reads and writes the attack tree language.
public protocol AttackTreeSourceGateway: Sendable {
    func read(_ text: String) -> AttackTreeRead
    func write(_ source: AttackTreeSource) -> String
}
