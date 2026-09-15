public enum RiskLevel: String, CaseIterable, Equatable, Hashable, Sendable {
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

    /// The top of the scale: the highest severity rank multiplied by the
    /// highest data sensitivity rank.
    public static let maximum = 16

    public init(value: Int) {
        self.value = value
    }

    /// The threat's severity rank multiplied by the data's rank.
    ///
    /// The data's rank is its position in the scheme the project holds,
    /// counting from 1, so a four level scheme and a five level scheme both
    /// score. A scheme is stated only by a library; with none, the standard
    /// four stand.
    public init(
        severity: ThreatSeverity,
        sensitivity: DataSensitivity,
        classifications: ClassificationScheme = .standard
    ) {
        self.value = severity.rank * sensitivity.rank(in: classifications)
    }

    public var level: RiskLevel {
        if value >= 12 { return .critical }
        if value >= 8 { return .high }
        if value >= 4 { return .medium }
        return .low
    }
}
