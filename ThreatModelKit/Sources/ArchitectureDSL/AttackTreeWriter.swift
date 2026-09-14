import ThreatModelKit

/// Writes an attack tree source in the canonical shape.
///
/// The shape follows section 8 of the language guide: two spaces for each
/// level, the equals signs of one run of attributes lined up, a blank line
/// between blocks, none before a closing brace, and no attribute holding its
/// default value. A node writes its children in the order the source states
/// them, because that order is what a person reads.
struct AttackTreeWriter {
    func write(_ source: AttackTreeSource) -> String {
        var lines: [String] = []
        lines.append("attack_trees for \(quoted(source.systemName)) {")

        var body: [String] = []
        if let catalogueTag = source.catalogueTag {
            body.append("catalogue = \(quoted(catalogueTag))")
            body.append("")
        }

        for tree in source.trees {
            body += treeBlock(tree)
            body.append("")
        }

        while body.last == "" { body.removeLast() }
        lines += indent(body)
        lines.append("}")
        return lines.joined(separator: "\n") + "\n"
    }

    private func treeBlock(_ tree: SourceAttackTree) -> [String] {
        var lines: [String] = ["tree \(quoted(tree.id)) {"]
        var body: [String] = []

        var attributes: [(String, String)] = []
        if let name = tree.name { attributes.append(("name", quoted(name))) }
        if let description = tree.description {
            attributes.append(("description", quoted(description)))
        }
        if tree.raisesRiskBy != 0 {
            attributes.append(("raises_risk_by", String(tree.raisesRiskBy)))
        }
        if attributes.isEmpty == false {
            body += aligned(attributes)
            body.append("")
        }

        body.append("goal \(target(tree.goal))")
        body.append("")
        body += node(tree.root)

        lines += indent(body)
        lines.append("}")
        return lines
    }

    private func node(_ node: SourceTreeNode) -> [String] {
        switch node {
        case .step(let step):
            return stepBlock(step)
        case .all(let children):
            return group("all_of", children)
        case .any(let children):
            return group("any_of", children)
        }
    }

    /// Writes the children of `all_of` or `any_of`.
    ///
    /// A blank line separates two children when either one is a block — a
    /// step with a note, or a nested `all_of` or `any_of` — because that is
    /// what "a blank line between blocks" means here. Two plain steps next
    /// to each other, each a single line, write with no blank line between
    /// them.
    private func group(_ word: String, _ children: [SourceTreeNode]) -> [String] {
        var body: [String] = []
        var previousIsBlock = false
        for (index, child) in children.enumerated() {
            let childLines = node(child)
            let isBlock = childLines.count > 1
            if index > 0 && (previousIsBlock || isBlock) {
                body.append("")
            }
            body += childLines
            previousIsBlock = isBlock
        }
        return ["\(word) {"] + indent(body) + ["}"]
    }

    private func stepBlock(_ step: SourceTreeStep) -> [String] {
        let header = "step \(target(step.target))"
        guard let note = step.note else { return [header] }
        return [header + " {"] + indent(["note = \(quoted(note))"]) + ["}"]
    }

    private func target(_ target: SourceTreeTarget) -> String {
        "\(quoted(target.threatId)) on \(target.sourceKind) \(quoted(target.sourceId))"
    }

    private func aligned(_ attributes: [(String, String)]) -> [String] {
        let width = attributes.map(\.0.count).max() ?? 0
        return attributes.map { name, value in
            name.padding(toLength: width, withPad: " ", startingAt: 0) + " = " + value
        }
    }

    private func indent(_ lines: [String]) -> [String] {
        lines.map { $0.isEmpty ? "" : "  " + $0 }
    }

    private func quoted(_ text: String) -> String {
        "\"" + text
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "\t", with: "\\t")
            + "\""
    }
}
