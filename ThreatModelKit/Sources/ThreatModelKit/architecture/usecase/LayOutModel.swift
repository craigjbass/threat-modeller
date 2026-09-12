import Foundation

public protocol LayOutModelUseCase {
    func execute(_ request: LayOutModelRequest) -> LayOutModelResponse
}

public struct LayOutModelRequest: Equatable, Sendable {
    public let source: ArchitectureSource
    public init(source: ArchitectureSource) { self.source = source }
}

public struct LaidOutComponent: Equatable, Sendable {
    public let id: String
    public let x: Double
    public let y: Double

    public init(id: String, x: Double, y: Double) {
        self.id = id
        self.x = x
        self.y = y
    }
}

public struct LaidOutZone: Equatable, Sendable {
    public let id: String
    public let x: Double
    public let y: Double
    public let width: Double
    public let height: Double

    public init(id: String, x: Double, y: Double, width: Double, height: Double) {
        self.id = id
        self.x = x
        self.y = y
        self.width = width
        self.height = height
    }
}

public struct LayOutModelResponse: Equatable, Sendable {
    public let components: [LaidOutComponent]
    public let zones: [LaidOutZone]

    public init(components: [LaidOutComponent], zones: [LaidOutZone]) {
        self.components = components
        self.zones = zones
    }
}

/// Places a diagram from declaration order alone.
///
/// The same source always draws the same picture. There is no force-directed
/// placement and no crossing minimisation: a user who wants a tidier diagram
/// reorders their declarations.
public struct LayOutModel: LayOutModelUseCase {
    /// The size the canvas draws a node at.
    static let nodeWidth = 160.0
    static let nodeHeight = 72.0
    static let columnGap = 60.0
    /// A row leaves room for the tallest footprint, which is the process
    /// circle. That circle passes the 160 by 72 slot by 16 points above and 16
    /// below, so a gap of 48 would leave two circles 16 points apart.
    public static let rowGap = 72.0
    /// A zone pads its contents, and reserves a header band the containment
    /// rule already needs: a component's centre must sit below it.
    static let zonePadding = 40.0
    static let zoneHeader = 40.0
    static let zoneGap = 60.0
    /// A row of zones wraps once it would pass this width.
    ///
    /// A wide, short diagram reads badly: a flow runs the whole width, and its
    /// label crosses everything between its two ends. Wrapping sooner squares
    /// the picture up and keeps a flow short.
    static let rowWidth = 1400.0

    public init() {}

    public func execute(_ request: LayOutModelRequest) -> LayOutModelResponse {
        var components: [LaidOutComponent] = []
        var zones: [LaidOutZone] = []
        var y = Self.zonePadding

        // Components outside every zone go in one band across the top.
        let loose = request.source.components
        if loose.isEmpty == false {
            for (index, component) in loose.enumerated() {
                components.append(
                    LaidOutComponent(
                        id: component.id,
                        x: Self.zonePadding + Double(index) * (Self.nodeWidth + Self.columnGap),
                        y: y
                    )
                )
            }
            y += Self.nodeHeight + Self.rowGap * 2
        }

        var x = Self.zonePadding
        var tallestInRow = 0.0

        for zone in request.source.zones {
            let size = Self.size(ofZoneHolding: zone.components.count)

            if x > Self.zonePadding && x + size.width > Self.rowWidth {
                x = Self.zonePadding
                y += tallestInRow + Self.zoneGap
                tallestInRow = 0
            }

            zones.append(
                LaidOutZone(id: zone.id, x: x, y: y, width: size.width, height: size.height)
            )
            components += Self.place(zone.components, inZoneAt: x, y)

            x += size.width + Self.zoneGap
            tallestInRow = max(tallestInRow, size.height)
        }

        return LayOutModelResponse(components: components, zones: zones)
    }

    /// A grid `ceil(sqrt(n))` columns wide, so four components make a square.
    static func columns(for count: Int) -> Int {
        max(1, Int(Double(count).squareRoot().rounded(.up)))
    }

    static func size(ofZoneHolding count: Int) -> (width: Double, height: Double) {
        // A zone that holds nothing still gets one cell, so it stays visible
        // and selectable.
        let cells = max(1, count)
        let columns = Self.columns(for: cells)
        let rows = Int((Double(cells) / Double(columns)).rounded(.up))

        return (
            width: Double(columns) * nodeWidth
                + Double(columns - 1) * columnGap
                + zonePadding * 2,
            height: zoneHeader
                + Double(rows) * nodeHeight
                + Double(rows - 1) * rowGap
                + zonePadding * 2
        )
    }

    private static func place(
        _ components: [SourceComponent],
        inZoneAt zoneX: Double,
        _ zoneY: Double
    ) -> [LaidOutComponent] {
        let columns = Self.columns(for: max(1, components.count))

        return components.enumerated().map { index, component in
            let column = index % columns
            let row = index / columns
            return LaidOutComponent(
                id: component.id,
                x: zoneX + zonePadding + Double(column) * (nodeWidth + columnGap),
                y: zoneY + zoneHeader + zonePadding + Double(row) * (nodeHeight + rowGap)
            )
        }
    }
}
