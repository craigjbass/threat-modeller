/// Work a team means to do: a recommendation on a threat, or an action the
/// architecture file declares.
public struct PlannedWork: Equatable, Sendable {
    /// How big the work is.
    public enum Effort: String, CaseIterable, Equatable, Sendable {
        case small
        case medium
        case large
    }

    /// Where the work stands.
    public enum Status: String, CaseIterable, Equatable, Sendable {
        case planned
        case inProgress = "in_progress"
        case done
        case dropped

        public var label: String {
            switch self {
            case .planned: "planned"
            case .inProgress: "in progress"
            case .done: "done"
            case .dropped: "dropped"
            }
        }
    }

    /// The recommendation's text, or the action's label.
    public let label: String
    public let owner: String
    public let effort: Effort?
    public let dueBy: GovernanceDate?
    public let status: Status
    public let acceptance: String
    public let note: String
    public let sources: [String]

    public init(
        label: String,
        owner: String = "",
        effort: Effort? = nil,
        dueBy: GovernanceDate? = nil,
        status: Status = .planned,
        acceptance: String = "",
        note: String = "",
        sources: [String] = []
    ) {
        self.label = label
        self.owner = owner
        self.effort = effort
        self.dueBy = dueBy
        self.status = status
        self.acceptance = acceptance
        self.note = note
        self.sources = sources
    }

    /// What the report writes under the work: who, how big, by when and where
    /// it stands. Nil when the stanza states nothing but its default status,
    /// because a line saying only "planned" tells a reader nothing.
    public var says: String? {
        guard owner.isEmpty == false || effort != nil || dueBy != nil || status != .planned else {
            return nil
        }
        var parts: [String] = []
        if owner.isEmpty == false { parts.append(owner) }
        if let effort { parts.append("\(effort.rawValue) effort") }
        if let dueBy { parts.append("due \(dueBy)") }
        parts.append(status.label)
        return parts.joined(separator: ", ")
    }
}
