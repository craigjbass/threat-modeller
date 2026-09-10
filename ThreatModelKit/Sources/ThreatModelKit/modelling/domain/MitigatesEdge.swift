/// One component answers a named threat on another component.
///
/// This is the shape of the problem "a security product protects a host". The
/// product is a component like any other, and what it answers is an edge, not
/// prose repeated in every compensating control.
public struct MitigatesEdge: Equatable, Sendable {
    public let source: ComponentId
    public let target: ComponentId
    public let threatIds: [ThreatId]
    public let reducesRiskBy: Int
    /// What the file states, or nil when the file states none.
    public let status: MitigationStatus?

    public init(
        source: ComponentId,
        target: ComponentId,
        threatIds: [ThreatId],
        reducesRiskBy: Int,
        status: MitigationStatus? = nil
    ) {
        self.source = source
        self.target = target
        self.threatIds = threatIds
        self.reducesRiskBy = reducesRiskBy
        self.status = status
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
