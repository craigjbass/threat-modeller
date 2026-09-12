import Foundation

/// Where a flow meets a component.
public enum ConnectionAnchor: String, CaseIterable, Equatable, Sendable {
    case top
    case right
    case bottom
    case left
}

/// The anchor points of a footprint, and the pair a flow between two
/// footprints uses.
public enum AnchorGeometry {
    public static func point(_ anchor: ConnectionAnchor, of rect: Rect) -> Point {
        switch anchor {
        case .top: Point(x: (rect.minX + rect.maxX) / 2, y: rect.minY)
        case .right: Point(x: rect.maxX, y: (rect.minY + rect.maxY) / 2)
        case .bottom: Point(x: (rect.minX + rect.maxX) / 2, y: rect.maxY)
        case .left: Point(x: rect.minX, y: (rect.minY + rect.maxY) / 2)
        }
    }

    /// How much a zone in the way costs, against one point of length. A pair
    /// that leaves the far side of a node beats a short pair that runs over a
    /// zone the flow has nothing to do with.
    static let costOfAZoneInTheWay = 4000.0

    /// The anchor pair a flow leaves and arrives on.
    ///
    /// The shortest straight line wins, unless it runs over a zone the flow
    /// should avoid: each of those costs `costOfAZoneInTheWay`. A tie keeps
    /// the pair found first in `ConnectionAnchor.allCases` order, so the same
    /// layout always draws the same flow.
    public static func nearestPair(
        from source: Rect,
        to target: Rect,
        avoiding zones: [Rect] = []
    ) -> (source: ConnectionAnchor, target: ConnectionAnchor) {
        var best = (source: ConnectionAnchor.top, target: ConnectionAnchor.top)
        var lowest = Double.infinity

        for sourceAnchor in ConnectionAnchor.allCases {
            let start = point(sourceAnchor, of: source)
            for targetAnchor in ConnectionAnchor.allCases {
                let end = point(targetAnchor, of: target)
                let cost = hypot(end.x - start.x, end.y - start.y)
                    + costOfAZoneInTheWay * Double(inTheWay(from: start, to: end, zones: zones))

                if cost < lowest {
                    lowest = cost
                    best = (sourceAnchor, targetAnchor)
                }
            }
        }

        return best
    }

    /// How many of the zones the straight line between the two points enters.
    private static func inTheWay(from start: Point, to end: Point, zones: [Rect]) -> Int {
        guard zones.isEmpty == false else { return 0 }

        let steps = 32
        return zones.count { zone in
            (0...steps).contains { step in
                let t = Double(step) / Double(steps)
                return zone.contains(
                    Point(x: start.x + (end.x - start.x) * t, y: start.y + (end.y - start.y) * t)
                )
            }
        }
    }
}
