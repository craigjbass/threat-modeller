public protocol ReorderZonesUseCase {
    func execute(_ request: ReorderZonesRequest) -> ReorderZonesResponse
}

/// Where the named zones go in the drawing order.
///
/// The canvas draws the zones in the order the model holds them, so the last
/// zone draws over the ones before it. `front` therefore means last, and
/// `back` means first.
public enum ZonePlacement: String, Equatable, Sendable {
    case front
    case back
}

public struct ReorderZonesRequest: Equatable, Sendable {
    public let zoneIds: [String]
    public let placement: ZonePlacement

    public init(zoneIds: [String], placement: ZonePlacement) {
        self.zoneIds = zoneIds
        self.placement = placement
    }
}

public enum ReorderZonesResponse: Equatable, Sendable {
    /// The whole drawing order after the change, first drawn first.
    case reordered(zoneIds: [String])
    case unknownZone(zoneId: String)
}

/// Changes which zone draws over which.
///
/// Two zones that overlap need an order a person can state, because the one
/// drawn last takes the click. The order is the order the model holds, and the
/// architecture file writes and reads the zones in that same order, so the
/// order a person sets is the order they get back.
///
/// Zones named together keep their order among themselves.
public struct ReorderZones: ReorderZonesUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: ReorderZonesRequest) -> ReorderZonesResponse {
        models.mutate(label: ChangeLabel.reorderZones) { model in
            var moving: Set<ZoneId> = []

            for zoneId in request.zoneIds {
                let id = ZoneId(zoneId)
                guard model.zones.contains(where: { $0.id == id }) else {
                    return .unknownZone(zoneId: zoneId)
                }
                moving.insert(id)
            }

            guard moving.isEmpty == false else {
                return .reordered(zoneIds: model.zones.map(\.id.value))
            }

            let picked = model.zones.filter { moving.contains($0.id) }
            let rest = model.zones.filter { moving.contains($0.id) == false }
            model.zones = request.placement == .front ? rest + picked : picked + rest
            return .reordered(zoneIds: model.zones.map(\.id.value))
        }
    }
}
