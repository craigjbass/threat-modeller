/// An attack tree gateway for a caller that reads no tree file.
///
/// It answers with no trees and refuses nothing, so a use case that takes the
/// gateway need not take an optional one.
public struct NoAttackTreeSource: AttackTreeSourceGateway {
    public init() {}

    /// A source holding no tree, so a caller that reads a tree file with this
    /// gateway states no fault and imports no tree.
    public func read(_ text: String) -> AttackTreeRead {
        AttackTreeRead(source: AttackTreeSource(systemName: "", trees: []), diagnostics: [])
    }

    public func write(_ source: AttackTreeSource) -> String { "" }
}
