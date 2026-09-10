public enum RiskLevel: String, CaseIterable, Equatable, Sendable {
    case low
    case medium
    case high
    case critical

    public var label: String {
        switch self {
        case .low: "Low"
        case .medium: "Medium"
        case .high: "High"
        case .critical: "Critical"
        }
    }

    /// Weakest first, so a check can ask whether one level sits inside another.
    public var rank: Int {
        switch self {
        case .low: 1
        case .medium: 2
        case .high: 3
        case .critical: 4
        }
    }
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
