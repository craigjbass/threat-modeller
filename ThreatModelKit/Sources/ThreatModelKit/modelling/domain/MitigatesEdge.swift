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

    public init(
        source: ComponentId,
        target: ComponentId,
        threatIds: [ThreatId],
        reducesRiskBy: Int
    ) {
        self.source = source
        self.target = target
        self.threatIds = threatIds
        self.reducesRiskBy = reducesRiskBy
    }

    /// The identifier, minted the way a flow's is.
    public var id: String { "\(source.value)->\(target.value)" }

    public func answers(_ threatId: ThreatId) -> Bool {
        threatIds.contains(threatId)
    }
}
