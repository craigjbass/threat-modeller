/// What an attack tree file says, as plain values.
public struct AttackTreeSource: Equatable, Sendable {
    public let systemName: String
    public let catalogueTag: String?
    public let trees: [SourceAttackTree]

    public init(systemName: String, catalogueTag: String? = nil, trees: [SourceAttackTree] = []) {
        self.systemName = systemName
        self.catalogueTag = catalogueTag
        self.trees = trees
    }
}

/// One route a person wrote down.
public struct SourceAttackTree: Equatable, Sendable {
    public let id: String
    public let name: String?
    public let description: String?
    /// The percentage this tree adds to its goal when every step is open.
    /// Zero is a tree that narrates and moves no score.
    public let raisesRiskBy: Int
    public let goal: SourceTreeTarget
    public let root: SourceTreeNode

    public init(
        id: String,
        name: String? = nil,
        description: String? = nil,
        raisesRiskBy: Int = 0,
        goal: SourceTreeTarget,
        root: SourceTreeNode
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.raisesRiskBy = raisesRiskBy
        self.goal = goal
        self.root = root
    }

    /// Every step in the tree, in the order the file declares them.
    public var steps: [SourceTreeStep] { root.steps }

    /// The name a report shows, which is the `name` when the file states one
    /// and the id when it does not.
    public var displayName: String { name ?? id }
}

/// A branch of a tree, a chain through it, or a step at the end of one.
public indirect enum SourceTreeNode: Equatable, Sendable {
    case step(SourceTreeStep)
    /// Open while every child is open.
    case all([SourceTreeNode])
    /// Open while any child is open.
    case any([SourceTreeNode])
    /// A chain: the links in the order the attacker walks them. Open while
    /// every link is open. The first link is any node; every later link is
    /// a step, which the parser and the canvas both hold to.
    case then([SourceTreeNode])

    public var steps: [SourceTreeStep] {
        switch self {
        case .step(let step): [step]
        case .all(let children), .any(let children), .then(let children): children.flatMap(\.steps)
        }
    }
}

public struct SourceTreeStep: Equatable, Sendable {
    public let target: SourceTreeTarget
    public let note: String?

    public init(target: SourceTreeTarget, note: String? = nil) {
        self.target = target
        self.note = note
    }
}

/// A threat on the thing that raises it, which is the shape the controls
/// language already writes as `threat "<id>" on component "<id>"`.
public struct SourceTreeTarget: Equatable, Sendable {
    public let threatId: String
    /// `component`, `zone` or `flow`.
    public let sourceKind: String
    public let sourceId: String

    public init(threatId: String, sourceKind: String, sourceId: String) {
        self.threatId = threatId
        self.sourceKind = sourceKind
        self.sourceId = sourceId
    }

    /// The key the resolver mints for the same threat. The file says `flow`
    /// and the resolver says `connection`; `SourceThreatAnswer` holds the one
    /// rule that maps them.
    public var key: ThreatKey {
        ThreatKey(
            threatId: threatId,
            sourceId: "\(SourceThreatAnswer.resolverKind(sourceKind)):\(sourceId)"
        )
    }
}

public struct AttackTreeRead: Equatable, Sendable {
    public let source: AttackTreeSource?
    public let diagnostics: [Diagnostic]

    public init(source: AttackTreeSource?, diagnostics: [Diagnostic]) {
        self.source = source
        self.diagnostics = diagnostics
    }

    public var hasErrors: Bool {
        diagnostics.contains { $0.severity == .error }
    }
}
