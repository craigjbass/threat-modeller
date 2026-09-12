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

    /// The anchor pair with the shortest straight line between the two
    /// footprints. A tie keeps the pair found first in
    /// `ConnectionAnchor.allCases` order, so the same layout always draws the
    /// same flow.
    public static func nearestPair(
        from source: Rect,
        to target: Rect
    ) -> (source: ConnectionAnchor, target: ConnectionAnchor) {
        var best = (source: ConnectionAnchor.top, target: ConnectionAnchor.top)
        var shortest = Double.infinity

        for sourceAnchor in ConnectionAnchor.allCases {
            let start = point(sourceAnchor, of: source)
            for targetAnchor in ConnectionAnchor.allCases {
                let end = point(targetAnchor, of: target)
                let distance = hypot(end.x - start.x, end.y - start.y)
                if distance < shortest {
                    shortest = distance
                    best = (sourceAnchor, targetAnchor)
                }
            }
        }

        return best
    }
}
