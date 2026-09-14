/// What a controls file says, as plain values.
public struct ControlsSource: Equatable, Sendable {
    public let systemName: String
    public let catalogueTag: String?
    /// The risk level a likelihood finding may answer up to, written by the
    /// compiler from the architecture file. Nil means low.
    public let riskTolerance: String?
    public let answers: [SourceThreatAnswer]
    /// What the compiler found out about the trees a person wrote. The
    /// application recomputes every number here, so an edit changes nothing.
    public let trees: [SourceTreeAnswer]

    public init(
        systemName: String,
        catalogueTag: String? = nil,
        riskTolerance: String? = nil,
        answers: [SourceThreatAnswer] = [],
        trees: [SourceTreeAnswer] = []
    ) {
        self.systemName = systemName
        self.catalogueTag = catalogueTag
        self.riskTolerance = riskTolerance
        self.answers = answers
        self.trees = trees
    }

    public func answer(for key: ThreatKey) -> SourceThreatAnswer? {
        answers.first { $0.key == key }
    }
}

public struct SourceThreatAnswer: Equatable, Sendable {
    public let threatId: String
    /// `component`, `zone` or `flow`.
    public let sourceKind: String
    public let sourceId: String
    /// Written by the compiler so the file reads alone. A person editing it
    /// changes nothing: the application recomputes both.
    public let severityLabel: String?
    public let score: Int?
    /// What a person found out about how often this attack happens, or nil.
    public let likelihood: LikelihoodFinding?
    /// What a person decided this threat's severity is, and why, or nil when
    /// the catalogue's own severity stands.
    public let severityDecision: SeverityDecision?
    public let controls: [SourceControlAnswer]
    public let compensating: [CompensatingControl]
    public let recommendations: [SourceRecommendation]
    /// True when the architecture no longer raises this threat. Nothing deletes
    /// a stale answer. A person deletes it.
    public let isStale: Bool

    public init(
        threatId: String,
        sourceKind: String,
        sourceId: String,
        severityLabel: String? = nil,
        score: Int? = nil,
        likelihood: LikelihoodFinding? = nil,
        severityDecision: SeverityDecision? = nil,
        controls: [SourceControlAnswer] = [],
        compensating: [CompensatingControl] = [],
        recommendations: [SourceRecommendation] = [],
        isStale: Bool = false
    ) {
        self.threatId = threatId
        self.sourceKind = sourceKind
        self.sourceId = sourceId
        self.severityLabel = severityLabel
        self.score = score
        self.likelihood = likelihood
        self.severityDecision = severityDecision
        self.controls = controls
        self.compensating = compensating
        self.recommendations = recommendations
        self.isStale = isStale
    }

    /// The source id the resolver mints. The file says `flow`, and the
    /// resolver says `connection`; this is the one place that maps them.
    public var key: ThreatKey {
        ThreatKey(threatId: threatId, sourceId: "\(Self.resolverKind(sourceKind)):\(sourceId)")
    }

    /// The word the resolver uses for what a file calls `sourceKind`.
    public static func resolverKind(_ sourceKind: String) -> String {
        sourceKind == "flow" ? "connection" : sourceKind
    }

    /// The word a file uses for what the resolver calls `resolverKind`.
    public static func fileKind(_ resolverKind: String) -> String {
        resolverKind == "connection" ? "flow" : resolverKind
    }

    public var isAnswered: Bool {
        compensating.isEmpty == false || controls.contains { $0.status.isAnswered }
    }

    /// True when a person has answered this threat.
    ///
    /// A likelihood finding answers a threat only inside the project's
    /// tolerance: evidence closes a threat nobody exploits, and it never
    /// closes a High one.
    public func isAnswered(within tolerance: RiskLevel) -> Bool {
        if isAnswered { return true }
        guard likelihood != nil, let score else { return false }
        return RiskScore(value: score).level.rank <= tolerance.rank
    }
}

/// What a person says should be done about a threat.
///
/// It answers nothing. `isAnswered` ignores it, so `threatmodeller check`
/// still exits 1 for a threat that holds a recommendation and no answer.
public struct SourceRecommendation: Equatable, Sendable {
    public let text: String
    public let note: String?
    /// Where the recommendation comes from. Empty when a person names none.
    public let sources: [String]

    public init(text: String, note: String? = nil, sources: [String] = []) {
        self.text = text
        self.note = note
        self.sources = sources
    }
}

public struct SourceControlAnswer: Equatable, Sendable {
    /// The control's description, which is what the catalogue gives and what
    /// the control key is minted from.
    public let description: String
    public let status: ControlStatus
    public let note: String?

    public init(description: String, status: ControlStatus, note: String? = nil) {
        self.description = description
        self.status = status
        self.note = note
    }
}

public struct ControlsRead: Equatable, Sendable {
    public let source: ControlsSource?
    public let diagnostics: [Diagnostic]

    public init(source: ControlsSource?, diagnostics: [Diagnostic]) {
        self.source = source
        self.diagnostics = diagnostics
    }

    public var hasErrors: Bool {
        diagnostics.contains { $0.severity == .error }
    }

    public var warnings: [Diagnostic] {
        diagnostics.filter { $0.severity == .warning }
    }
}

/// One tree, as the compiler wrote it into the controls file.
public struct SourceTreeAnswer: Equatable, Sendable {
    public let treeId: String
    /// The threat key the boost lands on, as `<threat>@<kind>:<id>`.
    public let goalKey: String
    /// The chain factor as a whole percentage.
    public let chain: Int
    public let raisesRiskBy: Int
    public let score: Int
    public let scoreBefore: Int
    public let steps: [SourceTreeStepAnswer]
    /// True when a step or the goal no longer binds. A person deletes a stale
    /// tree, or restores what the tree names.
    public let isStale: Bool

    public init(
        treeId: String,
        goalKey: String = "",
        chain: Int = 0,
        raisesRiskBy: Int = 0,
        score: Int = 0,
        scoreBefore: Int = 0,
        steps: [SourceTreeStepAnswer] = [],
        isStale: Bool = false
    ) {
        self.treeId = treeId
        self.goalKey = goalKey
        self.chain = chain
        self.raisesRiskBy = raisesRiskBy
        self.score = score
        self.scoreBefore = scoreBefore
        self.steps = steps
        self.isStale = isStale
    }
}

public struct SourceTreeStepAnswer: Equatable, Sendable {
    /// `<threat>@<kind>:<id>`.
    public let key: String
    /// `open`, `closed` or `unbound`. A live stanza never holds `unbound`.
    public let state: String
    /// The control that closed this step, or nil.
    public let closedBy: String?

    public init(key: String, state: String, closedBy: String? = nil) {
        self.key = key
        self.state = state
        self.closedBy = closedBy
    }
}
