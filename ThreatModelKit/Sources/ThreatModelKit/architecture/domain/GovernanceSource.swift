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

    public var key: ThreatKey {
        SourceThreatAnswer.key(threatId: threatId, sourceKind: sourceKind, sourceId: sourceId)
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

/// What a repair did to one governance file.
public enum GovernanceRepair: Equatable, Sendable {
    /// The parser reads the file as it stands.
    case notNeeded
    /// The file the repair writes, and the key of each block it merged.
    case repaired(text: String, merged: [String])
    /// The file fails for a reason a merge does not fix. A person reads the
    /// diagnostics and edits the file.
    case cannotRepair(diagnostics: [Diagnostic])
}

/// Merging the blocks of a governance file that hold one key.
///
/// Issue #144. A file written before the key fix holds two blocks with one
/// key, and the parser refuses it, so the window does not open the system.
/// The merge puts those blocks back into one and keeps every attribute a
/// person wrote, so nothing a person decided is lost.
extension GovernanceSource {
    /// The key of each threat block beyond the first that holds that key, in
    /// file order. One entry for each block the parser calls governed twice.
    public var keysGovernedTwice: [String] {
        var seen: Set<String> = []
        return threats.compactMap { seen.insert($0.key.value).inserted ? nil : $0.key.value }
    }

    /// The label of each action beyond the first that holds that label.
    public var labelsGovernedTwice: [String] {
        var seen: Set<String> = []
        return actions.compactMap { seen.insert($0.label).inserted ? nil : $0.label }
    }

    /// The same governance with every block that shares a key merged into one
    /// block, in the place the first of them stands.
    public func mergingBlocksThatShareAKey() -> GovernanceSource {
        var order: [String] = []
        var byKey: [String: SourceGovernedThreat] = [:]
        for threat in threats {
            let key = threat.key.value
            guard let already = byKey[key] else {
                order.append(key)
                byKey[key] = threat
                continue
            }
            byKey[key] = Self.merged(already, threat)
        }

        var actionOrder: [String] = []
        var byLabel: [String: SourcePlannedWork] = [:]
        for action in actions {
            guard let already = byLabel[action.label] else {
                actionOrder.append(action.label)
                byLabel[action.label] = action
                continue
            }
            byLabel[action.label] = Self.merged(already, action)
        }

        return GovernanceSource(
            systemName: systemName,
            threats: order.compactMap { byKey[$0] },
            actions: actionOrder.compactMap { byLabel[$0] }
        )
    }

    /// Two blocks of one key as one block. The block is stale only when both
    /// are stale, because a block that is not stale says the architecture
    /// raises the threat.
    private static func merged(
        _ first: SourceGovernedThreat,
        _ second: SourceGovernedThreat
    ) -> SourceGovernedThreat {
        var accepted = first.accepted
        for risk in second.accepted {
            if let already = accepted.firstIndex(where: { $0.control == risk.control }) {
                accepted[already] = merged(accepted[already], risk)
            } else {
                accepted.append(risk)
            }
        }

        var work = first.work
        for planned in second.work {
            if let already = work.firstIndex(where: { $0.label == planned.label }) {
                work[already] = merged(work[already], planned)
            } else {
                work.append(planned)
            }
        }

        return SourceGovernedThreat(
            threatId: first.threatId,
            sourceKind: first.sourceKind,
            sourceId: first.sourceId,
            accepted: accepted,
            work: work,
            isStale: first.isStale && second.isStale
        )
    }

    /// Two accepted stanzas of one control as one stanza. Each attribute
    /// takes the first value a person wrote, in file order.
    private static func merged(
        _ first: SourceAcceptedRisk,
        _ second: SourceAcceptedRisk
    ) -> SourceAcceptedRisk {
        SourceAcceptedRisk(
            control: first.control,
            owner: first.owner.isEmpty ? second.owner : first.owner,
            acceptedOn: first.acceptedOn ?? second.acceptedOn,
            reviewBy: first.reviewBy ?? second.reviewBy,
            rationale: first.rationale.isEmpty ? second.rationale : first.rationale,
            sources: first.sources.isEmpty ? second.sources : first.sources,
            isStale: first.isStale && second.isStale
        )
    }

    /// Two work stanzas of one label as one stanza, by the same rule.
    private static func merged(
        _ first: SourcePlannedWork,
        _ second: SourcePlannedWork
    ) -> SourcePlannedWork {
        SourcePlannedWork(
            label: first.label,
            owner: first.owner.isEmpty ? second.owner : first.owner,
            effort: first.effort ?? second.effort,
            dueBy: first.dueBy ?? second.dueBy,
            status: first.status == SourcePlannedWork.defaultStatus ? second.status : first.status,
            acceptance: first.acceptance.isEmpty ? second.acceptance : first.acceptance,
            note: first.note.isEmpty ? second.note : first.note,
            sources: first.sources.isEmpty ? second.sources : first.sources,
            isStale: first.isStale && second.isStale
        )
    }
}
