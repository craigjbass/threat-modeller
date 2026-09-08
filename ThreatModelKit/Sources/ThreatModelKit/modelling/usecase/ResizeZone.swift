public protocol ResizeZoneUseCase {
    func execute(_ request: ResizeZoneRequest) -> ResizeZoneResponse
}

public struct ResizeZoneRequest: Equatable, Sendable {
    public let zoneId: String
    public let x: Double
    public let y: Double
    public let width: Double
    public let height: Double

    public init(zoneId: String, x: Double, y: Double, width: Double, height: Double) {
        self.zoneId = zoneId
        self.x = x
        self.y = y
        self.width = width
        self.height = height
    }
}

public enum ResizeZoneResponse: Equatable, Sendable {
    case resized
    case unknownZone
    case tooSmall
}

/// Puts a zone at a new rectangle.
///
/// Moving and resizing are the same change to the same rectangle, so one use
/// case covers both: a move keeps the width and the height. The rectangle is
/// absolute, so the same request applied twice leaves the same model. The
/// zone's other properties and its place in the drawing order do not change.
public struct ResizeZone: ResizeZoneUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: ResizeZoneRequest) -> ResizeZoneResponse {
        let id = ZoneId(request.zoneId)

        var model = models.current()
        guard let index = model.zones.firstIndex(where: { $0.id == id }) else {
            return .unknownZone
        }
        guard request.width >= Zone.minimumSize.width,
              request.height >= Zone.minimumSize.height else {
            return .tooSmall
        }

        model.zones[index].rect = Rect(
            x: request.x,
            y: request.y,
            width: request.width,
            height: request.height
        )
        models.save(model)

        return .resized
    }
}
