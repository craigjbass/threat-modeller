/// Something a team does that answers a threat the catalogue's controls do not.
///
/// It is the one thing in a controls file that changes a number, so it carries
/// a rationale: a reduction nobody can justify is not one.
public struct CompensatingControl: Equatable, Sendable {
    public let label: String
    /// 0 to 100.
    public let reducesRiskBy: Int
    public let rationale: String

    public init(label: String, reducesRiskBy: Int, rationale: String) {
        self.label = label
        self.reducesRiskBy = reducesRiskBy
        self.rationale = rationale
    }
}

/// Names one threat on one source.
///
/// `"<threatId>@<sourceId>"` — the pair `ThreatResolver` already mints to raise
/// a duplicate threat once.
public struct ThreatKey: Hashable, Sendable, CustomStringConvertible {
    public let value: String

    public init(threatId: String, sourceId: String) {
        value = "\(threatId)@\(sourceId)"
    }

    public init(_ value: String) {
        self.value = value
    }

    public var description: String { value }
}
