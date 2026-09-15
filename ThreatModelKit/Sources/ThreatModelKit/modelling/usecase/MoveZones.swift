public protocol MoveZonesUseCase {
    func execute(_ request: MoveZonesRequest) -> MoveZonesResponse
}

/// One zone's new top-left corner, in model coordinates.
public struct ZoneMove: Equatable, Sendable {
    public let zoneId: String
    public let x: Double
    public let y: Double

    public init(zoneId: String, x: Double, y: Double) {
        self.zoneId = zoneId
        self.x = x
        self.y = y
    }
}

public struct MoveZonesRequest: Equatable, Sendable {
    public let moves: [ZoneMove]

    public init(moves: [ZoneMove]) {
        self.moves = moves
    }
}

public enum MoveZonesResponse: Equatable, Sendable {
    /// The number of distinct zones that moved.
    case moved(count: Int)
    case unknownZone(zoneId: String)
}

/// Puts zones at new positions, as one change.
///
/// A zone keeps its width and its height: this moves the rectangle and does
/// not resize it, which is what `ResizeZone` is for. Positions are absolute,
/// so the same request applied twice leaves the same model. The move is all or
/// nothing: one unknown zone leaves every position as it was. Naming a zone
/// twice in one request takes the last position given for it.
///
/// Moving several zones together is one change, so one undo takes the whole
/// move back.
public struct MoveZones: MoveZonesUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: MoveZonesRequest) -> MoveZonesResponse {
        models.mutate(label: ChangeLabel.moveZones) { model in
            var corners: [ZoneId: Point] = [:]

            for move in request.moves {
                let id = ZoneId(move.zoneId)
                guard model.zones.contains(where: { $0.id == id }) else {
                    return .unknownZone(zoneId: move.zoneId)
                }
                corners[id] = Point(x: move.x, y: move.y)
            }

            guard corners.isEmpty == false else { return .moved(count: 0) }

            for index in model.zones.indices {
                guard let corner = corners[model.zones[index].id] else { continue }
                let size = model.zones[index].rect.size
                model.zones[index].rect = Rect(
                    x: corner.x,
                    y: corner.y,
                    width: size.width,
                    height: size.height
                )
            }
            // A zone that moves takes the components its new rectangle holds
            // and releases the rest, the way a resize does.
            for index in model.components.indices {
                model.components[index].zoneId = ZoneContainment.zone(
                    holding: model.components[index].centre,
                    in: model.zones
                )?.id
            }

            return .moved(count: corners.count)
        }
    }
}
