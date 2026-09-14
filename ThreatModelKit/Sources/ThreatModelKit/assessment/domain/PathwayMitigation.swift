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
    /// What a mitigation takes when neither the user nor the catalogue states
    /// a mode or a percentage. The vendored library states neither today.
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

    /// The configuration for one definition.
    ///
    /// The user's own settings win. A definition the user has never touched
    /// takes the mode and the percentage the catalogue states for it, and
    /// takes `defaultConfig` only for what the catalogue leaves out.
    public func config(for definition: PathwayMitigationDefinition) -> PathwayMitigationConfig {
        if let config = configs[definition.id] { return config }
        return PathwayMitigationConfig(
            isEnabled: Self.defaultConfig.isEnabled,
            mode: definition.defaultMode ?? Self.defaultConfig.mode,
            reductionPercent: definition.reducesRiskBy ?? Self.defaultConfig.reductionPercent
        )
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
        combined(score: score, by: [(mode: mode, percent: percent)])
    }

    /// What two or more mitigations answering one threat do to a score.
    ///
    /// The mitigations compound: each one acts on the risk the one before it
    /// left, which is `score × (1 − p1/100) × (1 − p2/100) × …`, floored, and
    /// never below 1. One mitigation in `remove` mode drops the threat, so the
    /// other modes do not matter.
    ///
    /// Multiplication does not care about order, and the floor runs once at
    /// the end, so the same set of mitigations always gives the same score.
    public static func combined(
        score: Int,
        by mitigations: [(mode: PathwayMitigationMode, percent: Int)]
    ) -> PathwayMitigationOutcome {
        guard mitigations.isEmpty == false else { return .unchanged }
        if mitigations.contains(where: { $0.mode == .remove }) { return .removed }

        var remaining = Double(score)
        for mitigation in mitigations {
            remaining -= remaining * Double(mitigation.percent) / 100
        }
        return .reduced(to: max(1, Int(remaining.rounded(.down))))
    }
}
