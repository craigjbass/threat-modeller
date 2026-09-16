import Foundation
import ThreatModelKit

/// What a person is writing, before it becomes a tree in the file.
///
/// A threat is chosen by its key — `<threat id>@<source id>` — because that is
/// what the assessment hands out, and a step naming anything else binds to
/// nothing.
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a pure value with no shared state.
nonisolated struct TreeDraft: Equatable {
    struct Step: Equatable {
        var key: String
        var note: String?
    }

    var id: String
    var name: String
    var description: String
    var raisesRiskBy: Int
    var goalKey: String
    var steps: [Step]

    init(
        id: String,
        name: String,
        description: String,
        raisesRiskBy: Int,
        goalKey: String,
        steps: [Step]
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.raisesRiskBy = raisesRiskBy
        self.goalKey = goalKey
        self.steps = steps
    }

    init(_ tree: SourceAttackTree) {
        id = tree.id
        name = tree.name ?? tree.id
        description = tree.description ?? ""
        raisesRiskBy = tree.raisesRiskBy
        goalKey = Self.key(of: tree.goal)
        steps = tree.steps.map { Step(key: Self.key(of: $0.target), note: $0.note) }
    }

    /// The tree this draft states, or nil when it states no step: a tree body
    /// holds exactly one root, and a root of nothing is not a tree.
    func source() -> SourceAttackTree? {
        guard let goal = Self.target(of: goalKey), steps.isEmpty == false else { return nil }
        let written = steps.compactMap { step -> SourceTreeNode? in
            guard let target = Self.target(of: step.key) else { return nil }
            return .step(SourceTreeStep(target: target, note: step.note))
        }
        guard written.isEmpty == false else { return nil }

        return SourceAttackTree(
            id: id,
            name: name.isEmpty ? nil : name,
            description: description.isEmpty ? nil : description,
            raisesRiskBy: raisesRiskBy,
            goal: goal,
            root: .all(written)
        )
    }

    /// The key the assessment hands out for one target.
    static func key(of target: SourceTreeTarget) -> String {
        "\(target.threatId)@\(target.sourceKind == "flow" ? "connection" : target.sourceKind):"
            + target.sourceId
    }

    /// The target one key names, or nil for a key this cannot read.
    static func target(of key: String) -> SourceTreeTarget? {
        let parts = key.split(separator: "@", maxSplits: 1).map(String.init)
        guard parts.count == 2 else { return nil }
        let source = parts[1].split(separator: ":", maxSplits: 1).map(String.init)
        guard source.count == 2 else { return nil }
        return SourceTreeTarget(
            threatId: parts[0],
            sourceKind: source[0] == "connection" ? "flow" : source[0],
            sourceId: source[1]
        )
    }
}
