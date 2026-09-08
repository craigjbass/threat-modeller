public protocol RemoveZoneUseCase {
    func execute(_ request: RemoveZoneRequest) -> RemoveZoneResponse
}

public struct RemoveZoneRequest: Equatable, Sendable {
    public let zoneId: String

    public init(zoneId: String) {
        self.zoneId = zoneId
    }
}

public enum RemoveZoneResponse: Equatable, Sendable {
    case removed
    case unknownZone
}

/// Removes one zone.
///
/// Every component the zone held stays on the model, where it was. A zone
/// holds nothing: membership is derived from the geometry, so removing the
/// zone simply leaves those components in no zone.
public struct RemoveZone: RemoveZoneUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RemoveZoneRequest) -> RemoveZoneResponse {
        let id = ZoneId(request.zoneId)

        return models.mutate { model in
            guard model.zones.contains(where: { $0.id == id }) else {
                return .unknownZone
            }

            model.zones.removeAll { $0.id == id }
            return .removed
        }
    }
}
