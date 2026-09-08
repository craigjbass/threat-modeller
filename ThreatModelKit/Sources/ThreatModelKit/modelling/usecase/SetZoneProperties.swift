public protocol SetZonePropertiesUseCase {
    func execute(_ request: SetZonePropertiesRequest) -> SetZonePropertiesResponse
}

public struct SetZonePropertiesRequest: Equatable, Sendable {
    public let zoneId: String
    /// Whitespace is trimmed. An empty name means the zone has none, and its
    /// display name falls back to the network type or the zone kind.
    public let name: String?
    public let networkZone: String
    public let networkType: String
    public let riskReductionEnabled: Bool
    /// 0 to 100 inclusive.
    public let riskReductionPercent: Int

    public init(
        zoneId: String,
        name: String?,
        networkZone: String,
        networkType: String,
        riskReductionEnabled: Bool,
        riskReductionPercent: Int
    ) {
        self.zoneId = zoneId
        self.name = name
        self.networkZone = networkZone
        self.networkType = networkType
        self.riskReductionEnabled = riskReductionEnabled
        self.riskReductionPercent = riskReductionPercent
    }
}

public enum SetZonePropertiesResponse: Equatable, Sendable {
    case updated
    case unknownZone
    case unknownNetworkZone
    case unknownNetworkType
    case reductionOutOfRange
}

/// Sets everything about a zone except its rectangle.
///
/// The change is all or nothing: one bad value leaves every property as it
/// was, so a rejected form never half-applies.
public struct SetZoneProperties: SetZonePropertiesUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetZonePropertiesRequest) -> SetZonePropertiesResponse {
        let id = ZoneId(request.zoneId)

        return models.mutate { model in
            guard let index = model.zones.firstIndex(where: { $0.id == id }) else {
                return .unknownZone
            }
            guard let networkZone = NetworkZone(rawValue: request.networkZone) else {
                return .unknownNetworkZone
            }
            guard let networkType = ZoneNetworkType(rawValue: request.networkType) else {
                return .unknownNetworkType
            }
            guard (0...100).contains(request.riskReductionPercent) else {
                return .reductionOutOfRange
            }

            let trimmed = request.name?.trimmingWhitespace()

            model.zones[index].name = (trimmed?.isEmpty == false) ? trimmed : nil
            model.zones[index].networkZone = networkZone
            model.zones[index].networkType = networkType
            model.zones[index].riskReductionEnabled = request.riskReductionEnabled
            model.zones[index].riskReductionPercent = request.riskReductionPercent
            return .updated
        }
    }
}
