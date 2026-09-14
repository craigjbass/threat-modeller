/// Reads and writes a `.governance` file.
public protocol GovernanceSourceGateway: Sendable {
    func read(_ text: String) -> GovernanceRead
    func write(_ source: GovernanceSource) -> String
}
