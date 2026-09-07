public struct StrideCategory: Equatable, Sendable {
    public let id: StrideId
    public let label: String

    public init(id: StrideId, label: String) {
        self.id = id
        self.label = label
    }
}

public struct ThreatSeverity: Equatable, Sendable {
    public let id: String
    public let label: String
    /// 1-based position in the taxonomy's severity order. Drives risk scoring.
    public let rank: Int

    public init(id: String, label: String, rank: Int) {
        self.id = id
        self.label = label
        self.rank = rank
    }
}

public struct ServiceCategory: Equatable, Sendable {
    public let id: CategoryId
    public let label: String
    public let presetThreatIds: [ThreatId]

    public init(id: CategoryId, label: String, presetThreatIds: [ThreatId]) {
        self.id = id
        self.label = label
        self.presetThreatIds = presetThreatIds
    }
}

public struct Taxonomy: Equatable, Sendable {
    public let stride: [StrideCategory]
    public let severities: [ThreatSeverity]
    public let categories: [ServiceCategory]

    public init(stride: [StrideCategory], severities: [ThreatSeverity], categories: [ServiceCategory]) {
        self.stride = stride
        self.severities = severities
        self.categories = categories
    }

    public func severity(id: String) -> ThreatSeverity? {
        severities.first { $0.id == id }
    }

    public func category(id: CategoryId) -> ServiceCategory? {
        categories.first { $0.id == id }
    }

    public func strideCategory(id: StrideId) -> StrideCategory? {
        stride.first { $0.id == id }
    }
}
