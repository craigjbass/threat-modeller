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
public struct RemoveZone: RemoveZoneUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RemoveZoneRequest) -> RemoveZoneResponse {
        let id = ZoneId(request.zoneId)

        return models.mutate(label: ChangeLabel.removeZone) { model in
            guard model.zones.contains(where: { $0.id == id }) else {
                return .unknownZone
            }

            model.zones.removeAll { $0.id == id }
            for index in model.components.indices where model.components[index].zoneId == id {
                model.components[index].zoneId = ZoneContainment.zone(
                    holding: model.components[index].centre,
                    in: model.zones
                )?.id
            }
            return .removed
        }
    }
}
