public protocol AddZoneUseCase {
    func execute(_ request: AddZoneRequest) -> AddZoneResponse
}

public struct AddZoneRequest: Equatable, Sendable {
    public let x: Double
    public let y: Double
    public let width: Double
    public let height: Double

    public init(x: Double, y: Double, width: Double, height: Double) {
        self.x = x
        self.y = y
        self.width = width
        self.height = height
    }
}

public enum AddZoneResponse: Equatable, Sendable {
    case added(zoneId: String)
    /// Smaller than `Zone.minimumSize`. A drag that barely moves would
    /// otherwise leave a zone too small to see or to grab.
    case tooSmall
}

/// Draws a new zone.
///
/// A new zone is private, generic and reducing risk by the default
/// percentage, because that is the zone a threat modeller draws most often.
/// `SetZoneProperties` changes any of it. The zone goes on the end of the
/// list, so it wins over the zones already drawn where they overlap.
public struct AddZone: AddZoneUseCase {
    private let models: ThreatModelGateway
    private let ids: IdentityGenerator

    public init(models: ThreatModelGateway, ids: IdentityGenerator) {
        self.models = models
        self.ids = ids
    }

    public func execute(_ request: AddZoneRequest) -> AddZoneResponse {
        guard request.width >= Zone.minimumSize.width,
              request.height >= Zone.minimumSize.height else {
            return .tooSmall
        }

        let zone = Zone(
            id: ZoneId(ids.next()),
            rect: Rect(x: request.x, y: request.y, width: request.width, height: request.height)
        )

        return models.mutate { model in
            model.zones.append(zone)
            return .added(zoneId: zone.id.value)
        }
    }
}
