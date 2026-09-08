import Foundation

/// What a mitigation does to a threat it answers.
public enum PathwayMitigationMode: String, CaseIterable, Equatable, Sendable {
    /// The threat is dropped entirely.
    case remove
    /// The score is lowered but never to nothing.
    case reduce

    public var label: String {
        switch self {
        case .remove: "Remove the threat"
        case .reduce: "Lower the score"
        }
    }
}

/// How the user has set one mitigation.
public struct PathwayMitigationConfig: Equatable, Sendable {
    public let isEnabled: Bool
    public let mode: PathwayMitigationMode
    /// 0 to 100. Only read in `reduce` mode.
    public let reductionPercent: Int

    public init(isEnabled: Bool, mode: PathwayMitigationMode, reductionPercent: Int) {
        self.isEnabled = isEnabled
        self.mode = mode
        self.reductionPercent = reductionPercent
    }
}

/// Every pathway mitigation setting on a model.
///
/// The master toggle starts off: a model must not score lower than the
/// catalogue says until the user states the mitigation is real on their
/// system. A mitigation the user has never touched takes `defaultConfig`.
public struct PathwayMitigationSettings: Equatable, Sendable {
    public static let defaultConfig = PathwayMitigationConfig(
        isEnabled: true,
        mode: .reduce,
        reductionPercent: 50
    )

    public var isMasterEnabled: Bool
    public var configs: [PathwayMitigationId: PathwayMitigationConfig]

    public init(
        isMasterEnabled: Bool = false,
        configs: [PathwayMitigationId: PathwayMitigationConfig] = [:]
    ) {
        self.isMasterEnabled = isMasterEnabled
        self.configs = configs
    }

    public func config(for id: PathwayMitigationId) -> PathwayMitigationConfig {
        configs[id] ?? Self.defaultConfig
    }
}

/// What happened to a threat's score.
public enum PathwayMitigationOutcome: Equatable, Sendable {
    case unchanged
    case removed
    case reduced(to: Int)
}

/// What a mitigation does to a score. Spec section 5.3.
public enum PathwayMitigation {
    /// `remove` drops the threat. `reduce` gives
    /// `max(1, floor(score − score × percent / 100))`, so a reduced threat
    /// never reaches zero: a control that lowers a risk has not removed it.
    public static func outcome(
        score: Int,
        mode: PathwayMitigationMode,
        percent: Int
    ) -> PathwayMitigationOutcome {
        switch mode {
        case .remove:
            return .removed
        case .reduce:
            let reduced = Double(score) - Double(score) * Double(percent) / 100
            return .reduced(to: max(1, Int(reduced.rounded(.down))))
        }
    }
}
