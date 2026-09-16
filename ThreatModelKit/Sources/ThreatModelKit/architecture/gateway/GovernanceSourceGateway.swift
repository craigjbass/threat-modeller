/// Reads and writes a `.governance` file.
public protocol GovernanceSourceGateway: Sendable {
    func read(_ text: String) -> GovernanceRead
    func write(_ source: GovernanceSource) -> String
    /// A file the parser refuses only because two blocks hold one key, put
    /// back into the shape the parser reads. Every attribute a person wrote
    /// stays. Issue #144.
    func repair(_ text: String) -> GovernanceRepair
}
