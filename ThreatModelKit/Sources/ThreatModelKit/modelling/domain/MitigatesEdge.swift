/// What a team would do to adopt one assumed edge.
///
/// The label is the action's identity. Several edges can name one label, and
/// then they are one action whose leverage totals across all of them. Exactly
/// one of those edges states the text; the rest name the label alone.
public struct EdgeAction: Equatable, Sendable {
    public let label: String
    /// Stated on exactly one edge per label, and nil on the others.
    public let text: String?
    public let note: String?
    /// The assumption blocking this edge, or nil.
    public let blockedBy: String?
    public let sources: [String]

    public init(
        label: String,
        text: String? = nil,
        note: String? = nil,
        blockedBy: String? = nil,
        sources: [String] = []
    ) {
        self.label = label
        self.text = text
        self.note = note
        self.blockedBy = blockedBy
        self.sources = sources
    }
}

/// One component answers a named threat on another component.
///
/// This is the shape of the problem "a security product protects a host". The
/// product is a component like any other, and what it answers is an edge, not
/// prose repeated in every compensating control.
public struct MitigatesEdge: Equatable, Sendable {
    public var source: ComponentId
    public var target: ComponentId
    public var threatIds: [ThreatId]
    public var reducesRiskBy: Int
    /// What the file states, or nil when the file states none.
    public var status: MitigationStatus?
    /// What a team would do to adopt this edge, or nil when it names none.
    /// Only an assumed edge carries one: an adopted edge has no leverage left
    /// to claim, because its reduction is already in the residual score.
    public var action: EdgeAction?

    public init(
        source: ComponentId,
        target: ComponentId,
        threatIds: [ThreatId],
        reducesRiskBy: Int,
        status: MitigationStatus? = nil,
        action: EdgeAction? = nil
    ) {
        self.source = source
        self.target = target
        self.threatIds = threatIds
        self.reducesRiskBy = reducesRiskBy
        self.status = status
        self.action = action
    }

    /// The identifier, minted the way a flow's is.
    public var id: String { "\(source.value)->\(target.value)" }

    /// What a check uses: what the file states, or `.adopted` when the file
    /// states none.
    public var effectiveStatus: MitigationStatus { status ?? .adopted }

    public func answers(_ threatId: ThreatId) -> Bool {
        threatIds.contains(threatId)
    }
}

/// Whether a team has done the work an edge describes.
public enum MitigationStatus: String, CaseIterable, Equatable, Sendable {
    case adopted
    case assumed

    public var label: String {
        switch self {
        case .adopted: "Adopted"
        case .assumed: "Assumed"
        }
    }
}
