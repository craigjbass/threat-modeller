public protocol SummariseRiskUseCase {
    func execute(_ request: SummariseRiskRequest) -> SummariseRiskResponse
}

public struct SummariseRiskRequest: Equatable, Sendable {
    public init() {}
}

public struct RiskLevelCount: Equatable, Sendable {
    public let levelId: String
    public let label: String
    public let count: Int

    public init(levelId: String, label: String, count: Int) {
        self.levelId = levelId
        self.label = label
        self.count = count
    }
}

public struct StrideCount: Equatable, Sendable {
    public let strideId: String
    public let label: String
    public let count: Int

    public init(strideId: String, label: String, count: Int) {
        self.strideId = strideId
        self.label = label
        self.count = count
    }
}

public struct SummariseRiskResponse: Equatable, Sendable {
    public let totalThreats: Int
    /// Worst first: critical, high, medium, low. Every level appears, even at
    /// zero, so the strip does not change shape as the model changes.
    public let byLevel: [RiskLevelCount]
    /// In taxonomy order. Every category appears, even at zero. A threat
    /// carrying two categories is counted once in each.
    public let byStride: [StrideCount]
    /// Distinct control keys the model offers, and how many are recorded. A
    /// control consolidated across links or zones counts once.
    public let controlsOffered: Int
    public let controlsRecorded: Int

    public init(
        totalThreats: Int,
        byLevel: [RiskLevelCount],
        byStride: [StrideCount],
        controlsOffered: Int,
        controlsRecorded: Int
    ) {
        self.totalThreats = totalThreats
        self.byLevel = byLevel
        self.byStride = byStride
        self.controlsOffered = controlsOffered
        self.controlsRecorded = controlsRecorded
    }
}

/// Counts what the model raises.
///
/// It reads the same `ThreatResolver` the sidebar's list reads, so a count can
/// never disagree with the rows beneath it.
public struct SummariseRisk: SummariseRiskUseCase {
    private static let worstFirst: [RiskLevel] = [.critical, .high, .medium, .low]

    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: SummariseRiskRequest) -> SummariseRiskResponse {
        let resolved = ThreatResolver(model: models.current(), catalogue: catalogue).resolve()

        var levels: [RiskLevel: Int] = [:]
        var stride: [StrideId: Int] = [:]
        var offered: Set<ControlKey> = []
        var recorded: Set<ControlKey> = []

        for threat in resolved {
            levels[threat.score.level, default: 0] += 1
            for category in Set(threat.threat.stride) {
                stride[category, default: 0] += 1
            }
            for control in threat.controls {
                offered.insert(control.key)
                if control.isImplemented { recorded.insert(control.key) }
            }
        }

        return SummariseRiskResponse(
            totalThreats: resolved.count,
            byLevel: Self.worstFirst.map {
                RiskLevelCount(levelId: $0.rawValue, label: $0.label, count: levels[$0] ?? 0)
            },
            byStride: catalogue.taxonomy().stride.map {
                StrideCount(strideId: $0.id.value, label: $0.label, count: stride[$0.id] ?? 0)
            },
            controlsOffered: offered.count,
            controlsRecorded: recorded.count
        )
    }
}
