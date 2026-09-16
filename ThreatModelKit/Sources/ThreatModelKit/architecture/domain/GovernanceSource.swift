/// What a governance file says, as plain values.
///
/// This is the boundary, the way `ControlsSource` is. An accepted risk states
/// who carries it and when it is read again; planned work states who does it
/// and by when.
public struct GovernanceSource: Equatable, Sendable {
    public let systemName: String
    /// One block per governed threat, in the order the file states them.
    public let threats: [SourceGovernedThreat]
    /// The actions the `.arch` file declares, governed here.
    public let actions: [SourcePlannedWork]

    public init(
        systemName: String,
        threats: [SourceGovernedThreat] = [],
        actions: [SourcePlannedWork] = []
    ) {
        self.systemName = systemName
        self.threats = threats
        self.actions = actions
    }

    public func threat(for key: ThreatKey) -> SourceGovernedThreat? {
        threats.first { $0.key == key }
    }
}

/// The governance of one threat on one source.
public struct SourceGovernedThreat: Equatable, Sendable {
    public let threatId: String
    /// `component`, `zone` or `flow`.
    public let sourceKind: String
    public let sourceId: String
    public let accepted: [SourceAcceptedRisk]
    public let work: [SourcePlannedWork]
    /// True when the architecture no longer raises this threat.
    public let isStale: Bool

    public init(
        threatId: String,
        sourceKind: String,
        sourceId: String,
        accepted: [SourceAcceptedRisk] = [],
        work: [SourcePlannedWork] = [],
        isStale: Bool = false
    ) {
        self.threatId = threatId
        self.sourceKind = sourceKind
        self.sourceId = sourceId
        self.accepted = accepted
        self.work = work
        self.isStale = isStale
    }

    /// The key section 5.10 of the language guide gives. The file says
    /// `flow` and the key says `connection`, so a governance block and a
    /// controls answer on one flow hold one key.
    public var key: ThreatKey {
        ThreatKey(
            threatId: threatId,
            sourceId: "\(SourceThreatAnswer.resolverKind(sourceKind)):\(sourceId)"
        )
    }
}

/// A risk the organisation decided to carry, and who decided it.
public struct SourceAcceptedRisk: Equatable, Sendable {
    /// The control's description, which is its identity in both files.
    public let control: String
    public let owner: String
    /// A date written `YYYY-MM-DD`, or nil.
    public let acceptedOn: String?
    public let reviewBy: String?
    public let rationale: String
    public let sources: [String]
    /// True when the control is no longer accepted.
    public let isStale: Bool

    public init(
        control: String,
        owner: String = "",
        acceptedOn: String? = nil,
        reviewBy: String? = nil,
        rationale: String = "",
        sources: [String] = [],
        isStale: Bool = false
    ) {
        self.control = control
        self.owner = owner
        self.acceptedOn = acceptedOn
        self.reviewBy = reviewBy
        self.rationale = rationale
        self.sources = sources
        self.isStale = isStale
    }
}

/// Work a team means to do: a recommendation on a threat, or an action the
/// `.arch` file declares.
public struct SourcePlannedWork: Equatable, Sendable {
    /// The recommendation's text, or the action's label.
    public let label: String
    public let owner: String
    /// `small`, `medium` or `large`, or nil.
    public let effort: String?
    /// A date written `YYYY-MM-DD`, or nil.
    public let dueBy: String?
    /// `planned`, `in_progress`, `done` or `dropped`.
    public let status: String
    public let acceptance: String
    public let note: String
    public let sources: [String]
    /// True when the recommendation or the action is gone.
    public let isStale: Bool

    public init(
        label: String,
        owner: String = "",
        effort: String? = nil,
        dueBy: String? = nil,
        status: String = SourcePlannedWork.defaultStatus,
        acceptance: String = "",
        note: String = "",
        sources: [String] = [],
        isStale: Bool = false
    ) {
        self.label = label
        self.owner = owner
        self.effort = effort
        self.dueBy = dueBy
        self.status = status
        self.acceptance = acceptance
        self.note = note
        self.sources = sources
        self.isStale = isStale
    }

    /// What a stanza states when it states nothing.
    public static let defaultStatus = "planned"
    public static let statuses = ["planned", "in_progress", "done", "dropped"]
    public static let efforts = ["small", "medium", "large"]

    /// What the report writes after the text: who, how big, by when and where
    /// it stands. Nil when the stanza states nothing at all.
    public var says: String? {
        var parts: [String] = []
        if owner.isEmpty == false { parts.append(owner) }
        if let effort { parts.append("\(effort) effort") }
        if let dueBy { parts.append("due \(dueBy)") }
        parts.append(status)
        return parts.count == 1 && owner.isEmpty && effort == nil && dueBy == nil
            ? nil
            : parts.joined(separator: ", ")
    }
}

public struct GovernanceRead: Equatable, Sendable {
    public let source: GovernanceSource?
    public let diagnostics: [Diagnostic]

    public init(source: GovernanceSource?, diagnostics: [Diagnostic]) {
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
