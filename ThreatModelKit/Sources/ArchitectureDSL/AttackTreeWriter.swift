import ThreatModelKit

/// Writes an attack tree source in the canonical shape.
struct AttackTreeWriter {
    func write(_ source: AttackTreeSource) -> String {
        "attack_trees for \"\(source.systemName)\" {\n}\n"
    }
}
