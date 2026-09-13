/// One thing a team could do, and every assumed edge it would adopt.
///
/// An action is not a property of one edge: adopting a guard across two
/// elements is one piece of work, and its leverage is what both edges remove
/// together.
public struct Action: Equatable, Sendable {
    public let label: String
    public let text: String
    public let note: String?
    public let blockedBy: String?
    public let sources: [String]
    /// The edges this action adopts, in the order the file declares them.
    public let edgeIds: [String]

    public init(
        label: String,
        text: String,
        note: String? = nil,
        blockedBy: String? = nil,
        sources: [String] = [],
        edgeIds: [String] = []
    ) {
        self.label = label
        self.text = text
        self.note = note
        self.blockedBy = blockedBy
        self.sources = sources
        self.edgeIds = edgeIds
    }
}

/// Collects the edges that name one action.
public enum Actions {
    /// One action per label, ordered by where its text is declared, so two
    /// runs of one model read the same.
    ///
    /// A label no edge gives text to is dropped. The parser reports that
    /// fault; this refuses it again rather than minting an action with no
    /// name for a reader.
    public static func build(from edges: [MitigatesEdge]) -> [Action] {
        var edgeIdsByLabel: [String: [String]] = [:]
        var statedByLabel: [String: EdgeAction] = [:]
        var order: [String] = []

        for edge in edges {
            guard let action = edge.action else { continue }
            edgeIdsByLabel[action.label, default: []].append(edge.id)
            if action.text != nil, statedByLabel[action.label] == nil {
                statedByLabel[action.label] = action
                order.append(action.label)
            }
        }

        return order.compactMap { label in
            guard let stated = statedByLabel[label], let text = stated.text else { return nil }
            return Action(
                label: label,
                text: text,
                note: stated.note,
                blockedBy: stated.blockedBy,
                sources: stated.sources,
                edgeIds: edgeIdsByLabel[label] ?? []
            )
        }
    }
}
