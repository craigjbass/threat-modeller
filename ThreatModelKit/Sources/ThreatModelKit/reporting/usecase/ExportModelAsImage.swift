public protocol ExportModelAsImageUseCase {
    func execute(_ request: ExportModelAsImageRequest) -> ExportModelAsImageResponse
}

public struct ExportModelAsImageRequest: Equatable, Sendable {
    public init() {}
}

public struct ExportModelAsImageResponse: Equatable, Sendable {
    public let fileName: String
    /// What the exporter should draw, in model coordinates, with a margin
    /// around everything the model holds.
    public let x: Double
    public let y: Double
    public let width: Double
    public let height: Double
    /// True when the model holds nothing to draw.
    public let isEmpty: Bool

    public init(
        fileName: String,
        x: Double,
        y: Double,
        width: Double,
        height: Double,
        isEmpty: Bool
    ) {
        self.fileName = fileName
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.isEmpty = isEmpty
    }
}

/// Says what to draw and what to call the file. The bitmap itself is produced
/// by the delivery mechanism, because the picture is the canvas as drawn and a
/// use case never holds a bitmap.
public struct ExportModelAsImage: ExportModelAsImageUseCase {
    /// The blank space left around everything the model holds.
    public static let margin = 40.0
    /// The extra blank a model that can route a flow needs. A detour passes
    /// `FlowRouting.clearance` outside a zone, and the curve's controls pull
    /// up to 150 further, so a picture cut to the zones alone clips the flow.
    public static let routingAllowance = 150.0
    /// What an empty model draws, so the file is a picture rather than nothing.
    public static let emptySize = 400.0

    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: ExportModelAsImageRequest) -> ExportModelAsImageResponse {
        let model = models.current()
        let fileName = "\(FileNaming.stem(from: model.name)).png"

        var lowestX = Double.greatestFiniteMagnitude
        var lowestY = Double.greatestFiniteMagnitude
        var highestX = -Double.greatestFiniteMagnitude
        var highestY = -Double.greatestFiniteMagnitude

        func hold(x: Double, y: Double, width: Double, height: Double) {
            lowestX = min(lowestX, x)
            lowestY = min(lowestY, y)
            highestX = max(highestX, x + width)
            highestY = max(highestY, y + height)
        }

        // The widest and the tallest footprint, around the centre of the slot.
        // A component's shape is not known here, and a process draws as a
        // circle that passes the slot above and below.
        let widest = DiagramShape.allCases.map { Component.footprint(for: $0).width }.max() ?? 0
        let tallest = DiagramShape.allCases.map { Component.footprint(for: $0).height }.max() ?? 0

        for component in model.components {
            hold(
                x: component.centre.x - widest / 2,
                y: component.centre.y - tallest / 2,
                width: widest,
                height: tallest
            )
        }
        for zone in model.zones {
            hold(
                x: zone.rect.origin.x,
                y: zone.rect.origin.y,
                width: zone.rect.size.width,
                height: zone.rect.size.height
            )
        }

        // Only a model with more than one zone can route a flow round one.
        if model.zones.count > 1 {
            lowestX -= Self.routingAllowance
            lowestY -= Self.routingAllowance
            highestX += Self.routingAllowance
            highestY += Self.routingAllowance
        }

        guard model.components.isEmpty == false || model.zones.isEmpty == false else {
            return ExportModelAsImageResponse(
                fileName: fileName,
                x: 0,
                y: 0,
                width: Self.emptySize,
                height: Self.emptySize,
                isEmpty: true
            )
        }

        return ExportModelAsImageResponse(
            fileName: fileName,
            x: lowestX - Self.margin,
            y: lowestY - Self.margin,
            width: highestX - lowestX + Self.margin * 2,
            height: highestY - lowestY + Self.margin * 2,
            isEmpty: false
        )
    }
}
