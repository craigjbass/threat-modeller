public enum RiskLevel: String, Equatable, Sendable {
    case low
    case medium
    case high
    case critical
}

/// Severity rank multiplied by data sensitivity rank, giving 1–16.
///
/// Later milestones fold in the zone multiplier and pathway reduction; the
/// thresholds below stay as they are.
public struct RiskScore: Equatable, Sendable {
    public let value: Int

    public init(value: Int) {
        self.value = value
    }

    public init(severity: ThreatSeverity, sensitivity: DataSensitivity) {
        self.value = severity.rank * sensitivity.rank
    }

    public var level: RiskLevel {
        if value >= 12 { return .critical }
        if value >= 8 { return .high }
        if value >= 4 { return .medium }
        return .low
    }
}
