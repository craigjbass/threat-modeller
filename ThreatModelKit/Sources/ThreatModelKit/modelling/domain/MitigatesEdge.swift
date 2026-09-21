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
///
/// The edge states what it answers and whether it is in place. How much it
/// takes off is the answer a person writes on a control, in the `.controls`
/// file, because the same edge is worth a different amount to each control it
/// stands for.
public struct MitigatesEdge: Equatable, Sendable {
    public var source: ComponentId
    public var target: ComponentId
    public var threatIds: [ThreatId]
    /// What the file states, or nil when the file states none.
    public var status: ComponentStatus?
    /// What a team would do to put this edge in place, or nil when it names
    /// none. Only a proposed edge carries one: an edge in place has no
    /// leverage left to claim.
    public var action: EdgeAction?

    public init(
        source: ComponentId,
        target: ComponentId,
        threatIds: [ThreatId],
        status: ComponentStatus? = nil,
        action: EdgeAction? = nil
    ) {
        self.source = source
        self.target = target
        self.threatIds = threatIds
        self.status = status
        self.action = action
    }

    /// The identifier, minted the way a flow's is.
    public var id: String { "\(source.value)->\(target.value)" }

    /// What a check uses: what the file states, or `.live` when the file
    /// states none.
    public var effectiveStatus: ComponentStatus { status ?? ComponentStatus.default }

    public func answers(_ threatId: ThreatId) -> Bool {
        threatIds.contains(threatId)
    }
}

/// How much one `mitigates` edge takes off one control's threat.
///
/// A control names the edges that implement it, and each one states its own
/// reduction: the same guard is worth 80% to one control and 20% to another.
public struct ControlMitigation: Hashable, Sendable {
    /// `<protector>-><protected>`, the identifier `MitigatesEdge.id` mints.
    public let edgeId: String
    public let reducesRiskBy: Int

    public init(edgeId: String, reducesRiskBy: Int) {
        self.edgeId = edgeId
        self.reducesRiskBy = reducesRiskBy
    }
}
