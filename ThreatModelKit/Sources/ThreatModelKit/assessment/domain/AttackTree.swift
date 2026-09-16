/// What one step of a tree is doing today.
public enum StepState: String, Equatable, Sendable {
    /// The model raises this threat, and nothing closes it.
    case open
    /// An implemented control or a compensating control closes it.
    case closed
    /// The model no longer raises this threat on this source.
    case unbound
}

/// One step of a tree, matched against the resolved model.
public struct BoundStep: Equatable, Sendable {
    public let key: ThreatKey
    public let threatName: String
    public let sourceName: String
    public let state: StepState
    /// The control that closed this step, or nil when nothing closed it.
    public let closedBy: String?
    /// The likelihood factor this step carries, from 0.0 to 1.0.
    public let factor: Double
    public let note: String?
    /// Which chain of the tree this step is a link of, counted from 1 in
    /// the order the file states the chains, or nil for a step outside every
    /// chain. A step inside a nested chain names the innermost one.
    public let chain: Int?
    /// The step's position in that chain, counted from 1, or nil outside
    /// every chain. Every step of a branch that is one link shares the
    /// link's position.
    public let position: Int?

    public init(
        key: ThreatKey,
        threatName: String,
        sourceName: String,
        state: StepState,
        closedBy: String? = nil,
        factor: Double,
        note: String? = nil,
        chain: Int? = nil,
        position: Int? = nil
    ) {
        self.key = key
        self.threatName = threatName
        self.sourceName = sourceName
        self.state = state
        self.closedBy = closedBy
        self.factor = factor
        self.note = note
        self.chain = chain
        self.position = position
    }
}

/// One tree a person wrote, matched against the resolved model and scored.
public struct BoundAttackTree: Equatable, Sendable {
    public let id: String
    public let name: String
    public let description: String?
    public let raisesRiskBy: Int
    public let goal: ThreatKey
    public let goalName: String
    public let goalSourceName: String
    /// Every step, in the order the file states them.
    public let steps: [BoundStep]
    /// The factor the weakest open step gave, from 0.0 to 1.0. Zero when the
    /// root is closed or the tree is stale.
    public let chainFactor: Double
    public let isOpen: Bool
    /// True when a step or the goal no longer binds. A stale tree moves no
    /// score, and `threatmodeller check` exits 1 while one remains.
    public let isStale: Bool
    public let scoreBefore: Int
    public let score: Int

    public init(
        id: String,
        name: String,
        description: String?,
        raisesRiskBy: Int,
        goal: ThreatKey,
        goalName: String,
        goalSourceName: String,
        steps: [BoundStep],
        chainFactor: Double,
        isOpen: Bool,
        isStale: Bool,
        scoreBefore: Int,
        score: Int
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.raisesRiskBy = raisesRiskBy
        self.goal = goal
        self.goalName = goalName
        self.goalSourceName = goalSourceName
        self.steps = steps
        self.chainFactor = chainFactor
        self.isOpen = isOpen
        self.isStale = isStale
        self.scoreBefore = scoreBefore
        self.score = score
    }

    /// The chain factor as a whole percentage, which is what the controls file
    /// and the report both print.
    public var chainPercentage: Int { Int((chainFactor * 100).rounded()) }
}

public extension BoundAttackTree {
    /// The same tree with the score its goal reached.
    func withScore(_ score: Int) -> BoundAttackTree {
        BoundAttackTree(
            id: id,
            name: name,
            description: description,
            raisesRiskBy: raisesRiskBy,
            goal: goal,
            goalName: goalName,
            goalSourceName: goalSourceName,
            steps: steps,
            chainFactor: chainFactor,
            isOpen: isOpen,
            isStale: isStale,
            scoreBefore: scoreBefore,
            score: score
        )
    }
}
