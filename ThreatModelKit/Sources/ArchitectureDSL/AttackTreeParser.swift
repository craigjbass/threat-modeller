import ThreatModelKit

/// Turns tokens into an `AttackTreeSource`.
///
/// Like the other three parsers it never throws and never stops at the first
/// fault.
struct AttackTreeParser {
    private let tokens: [Token]
    private var index = 0
    private var diagnostics: [Diagnostic]

    init(tokens: [Token], faults: [Diagnostic]) {
        self.tokens = tokens
        diagnostics = faults
    }

    private static let sourceKinds: Set<String> = ["component", "zone", "flow"]

    mutating func parse() -> AttackTreeRead {
        guard let source = parseDocument() else {
            return AttackTreeRead(source: nil, diagnostics: diagnostics)
        }
        return AttackTreeRead(
            source: diagnostics.contains { $0.severity == .error } ? nil : source,
            diagnostics: diagnostics
        )
    }

    private mutating func parseDocument() -> AttackTreeSource? {
        guard expectKeyword("attack_trees") else { return nil }
        guard expectKeyword("for") else { return nil }
        guard let name = expect(.string, "the system's name") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var catalogueTag: String?
        var trees: [SourceAttackTree] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "catalogue":
                catalogueTag = parseTextAttribute()
            case "tree":
                if let tree = parseTree() { trees.append(tree) }
            default:
                record("an attack tree file holds catalogue and tree, not \"\(current.text)\"")
                skipToNextBlock()
            }
        }
        _ = expect(.rightBrace, "}")

        var seen: Set<String> = []
        for tree in trees where seen.insert(tree.id).inserted == false {
            record("the tree \"\(tree.id)\" is declared twice", at: tokens[0])
        }

        return AttackTreeSource(systemName: name.text, catalogueTag: catalogueTag, trees: trees)
    }

    private mutating func parseTree() -> SourceAttackTree? {
        let treeToken = current
        guard expectKeyword("tree") else { return nil }
        guard let id = expect(.string, "the tree's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var name: String?
        var description: String?
        var raisesRiskBy = 0
        var goals: [SourceTreeTarget] = []
        var roots: [SourceTreeNode] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "name": name = parseTextAttribute()
            case "description": description = parseTextAttribute()
            case "raises_risk_by":
                let token = current
                if let value = parseNumberAttribute() {
                    if (0...100).contains(value) {
                        raisesRiskBy = value
                    } else {
                        record("raises_risk_by is \(value); it runs from 0 to 100", at: token)
                    }
                }
            case "goal":
                if let goal = parseGoal() { goals.append(goal) }
            case "all_of", "any_of", "then":
                if let node = parseNode(treeId: id.text) { roots.append(node) }
            case "step":
                if let step = parseStep() { roots.append(.step(step)) }
            default:
                record(
                    "a tree holds name, description, raises_risk_by, goal, all_of, any_of, then "
                        + "and step, not \"\(current.text)\""
                )
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        if goals.isEmpty {
            record("the tree \"\(id.text)\" states no goal", at: treeToken)
            return nil
        }
        if goals.count > 1 {
            record("the tree \"\(id.text)\" states two goals; it states one", at: treeToken)
            return nil
        }
        if roots.isEmpty {
            record("the tree \"\(id.text)\" holds no steps", at: treeToken)
            return nil
        }
        if roots.count > 1 {
            record("the tree \"\(id.text)\" holds two roots; it holds one", at: treeToken)
            return nil
        }

        return SourceAttackTree(
            id: id.text,
            name: name,
            description: description,
            raisesRiskBy: raisesRiskBy,
            goal: goals[0],
            root: roots[0]
        )
    }

    private mutating func parseGoal() -> SourceTreeTarget? {
        advance()
        return parseTarget()
    }

    private mutating func parseStep() -> SourceTreeStep? {
        advance()
        guard let target = parseTarget() else { return nil }
        guard current.kind == .leftBrace else {
            return SourceTreeStep(target: target)
        }
        advance()

        var note: String?
        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "note": note = parseTextAttribute()
            default:
                record("a step holds note, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")
        return SourceTreeStep(target: target, note: note)
    }

    /// The `"<threat>" on component "<id>"` header, which the controls
    /// language writes the same way.
    private mutating func parseTarget() -> SourceTreeTarget? {
        guard let threatId = expect(.string, "the threat's identifier") else { return nil }

        guard current.kind == .identifier, current.text == "on" else {
            record("a step says what raises it: on component, on zone or on flow")
            return nil
        }
        advance()

        let kindToken = current
        guard let kind = expect(.identifier, "component, zone or flow") else { return nil }
        if Self.sourceKinds.contains(kind.text) == false {
            record(
                "a step is raised by a component, a zone or a flow, not \"\(kind.text)\"",
                at: kindToken
            )
        }
        guard let sourceId = expect(.string, "the identifier of what raises it") else { return nil }

        return SourceTreeTarget(
            threatId: threatId.text,
            sourceKind: kind.text,
            sourceId: sourceId.text
        )
    }

    private mutating func parseNode(treeId: String) -> SourceTreeNode? {
        let word = current.text
        let token = current
        advance()
        guard expect(.leftBrace, "{") != nil else { return nil }

        var children: [SourceTreeNode] = []
        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "step":
                if let step = parseStep() { children.append(.step(step)) }
            case "all_of", "any_of", "then":
                if let child = parseNode(treeId: treeId) { children.append(child) }
            default:
                record("\(article(word)) \(word) holds step, all_of, any_of and then, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        if children.isEmpty {
            record("the \(word) in the tree \"\(treeId)\" holds nothing", at: token)
            return nil
        }
        switch word {
        case "all_of":
            return .all(children)
        case "any_of":
            return .any(children)
        default:
            // A chain is a line of steps. The first link may be a branch, the
            // thing the attacker did before the line starts; every later
            // link is one step, because the canvas draws a link as one node
            // feeding the next and a junction takes its own children.
            for link in children.dropFirst() {
                guard case .step = link else {
                    record(
                        "the then in the tree \"\(treeId)\" holds a branch after its first link; "
                            + "a later link is a step",
                        at: token
                    )
                    return nil
                }
            }
            return .then(children)
        }
    }

    private func article(_ word: String) -> String {
        word == "then" ? "a" : "an"
    }

    // MARK: reading the token list

    private var current: Token { tokens[min(index, tokens.count - 1)] }

    private mutating func advance() {
        if index < tokens.count - 1 { index += 1 }
    }

    private mutating func expectKeyword(_ keyword: String) -> Bool {
        guard current.kind == .identifier, current.text == keyword else {
            record("expected \(keyword), not \"\(current.text)\"")
            return false
        }
        advance()
        return true
    }

    private mutating func expect(_ kind: TokenKind, _ what: String) -> Token? {
        guard current.kind == kind else {
            record("expected \(what)")
            return nil
        }
        let token = current
        advance()
        return token
    }

    private mutating func parseTextAttribute() -> String? {
        advance()
        guard expect(.equals, "=") != nil else { return nil }
        return expect(.string, "a text in quotation marks")?.text
    }

    private mutating func parseNumberAttribute() -> Int? {
        advance()
        guard expect(.equals, "=") != nil else { return nil }
        guard let token = expect(.number, "a whole number") else { return nil }
        return Int(token.text)
    }

    private mutating func record(
        _ message: String,
        at token: Token? = nil,
        severity: Diagnostic.Severity = .error
    ) {
        let where_ = token ?? current
        diagnostics.append(
            Diagnostic(severity: severity, line: where_.line, column: where_.column, message: message)
        )
    }

    private mutating func skipToNextBlock() {
        var depth = 0
        while current.kind != .endOfFile {
            if current.kind == .leftBrace { depth += 1 }
            if current.kind == .rightBrace {
                if depth == 0 { return }
                depth -= 1
                advance()
                if depth == 0 { return }
                continue
            }
            advance()
        }
    }

    private mutating func skipAttribute() {
        advance()
        if current.kind == .equals {
            advance()
            advance()
        } else if current.kind == .leftBrace {
            skipToNextBlock()
        }
    }
}
