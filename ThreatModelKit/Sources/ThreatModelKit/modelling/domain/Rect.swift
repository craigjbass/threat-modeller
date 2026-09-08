public struct Size: Equatable, Sendable {
    public let width: Double
    public let height: Double

    public init(width: Double, height: Double) {
        self.width = width
        self.height = height
    }
}

/// An axis-aligned rectangle in model coordinates. The origin is the top-left
/// corner, the same corner a component's position names.
public struct Rect: Equatable, Sendable {
    public let origin: Point
    public let size: Size

    public init(origin: Point, size: Size) {
        self.origin = origin
        self.size = size
    }

    public init(x: Double, y: Double, width: Double, height: Double) {
        self.init(origin: Point(x: x, y: y), size: Size(width: width, height: height))
    }

    public var minX: Double { origin.x }
    public var minY: Double { origin.y }
    public var maxX: Double { origin.x + size.width }
    public var maxY: Double { origin.y + size.height }

    /// Half-open, the way `CGRect` behaves: the near edges are inside and the
    /// far edges are outside. Two rectangles sharing an edge never both claim
    /// the same point.
    public func contains(_ point: Point) -> Bool {
        point.x >= minX && point.x < maxX && point.y >= minY && point.y < maxY
    }

    /// The rectangle with a band removed from its top edge, never shrinking
    /// past its own bottom. Zone containment ignores the zone's header band.
    public func insetFromTop(by amount: Double) -> Rect {
        let removed = min(max(amount, 0), size.height)
        return Rect(
            x: origin.x,
            y: origin.y + removed,
            width: size.width,
            height: size.height - removed
        )
    }
}
