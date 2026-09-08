/// Identifies a severity the user has overridden. Spec section 5.3.
///
/// WARNING: a component threat is keyed by its **technology**, not by the
/// component. An override set on one EC2 node applies to every EC2 node, and a
/// link or zone override applies to every link or every zone. That is the
/// original application's behaviour and the ported tests hold it.
public struct SeverityOverrideKey: Hashable, Sendable, CustomStringConvertible {
    public let value: String
    public init(_ value: String) { self.value = value }
    public var description: String { value }

    public static func forComponent(technologyId: TechnologyId, threatId: ThreatId) -> SeverityOverrideKey {
        SeverityOverrideKey("\(technologyId.value)::\(threatId.value)")
    }

    public static func forConnection(threatId: ThreatId) -> SeverityOverrideKey {
        SeverityOverrideKey("connection::\(threatId.value)")
    }

    public static func forZone(threatId: ThreatId) -> SeverityOverrideKey {
        SeverityOverrideKey("zone::\(threatId.value)")
    }
}
