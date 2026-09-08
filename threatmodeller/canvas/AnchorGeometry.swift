import CoreGraphics
import Foundation

/// Where a connection meets a component.
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a pure value with no shared state.
nonisolated enum ConnectionAnchor: String, CaseIterable, Equatable {
    case top
    case right
    case bottom
    case left
}

/// The anchor points of a component box, and the pair a link between two
/// boxes uses.
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a pure value with no shared state.
nonisolated enum AnchorGeometry {
    static func point(_ anchor: ConnectionAnchor, of box: ComponentBox) -> CGPoint {
        let rect = box.rect
        switch anchor {
        case .top: return CGPoint(x: rect.midX, y: rect.minY)
        case .right: return CGPoint(x: rect.maxX, y: rect.midY)
        case .bottom: return CGPoint(x: rect.midX, y: rect.maxY)
        case .left: return CGPoint(x: rect.minX, y: rect.midY)
        }
    }

    /// The anchor pair with the shortest straight line between the two boxes.
    /// A tie keeps the pair found first in `ConnectionAnchor.allCases` order,
    /// so the same layout always draws the same link.
    static func nearestPair(
        from source: ComponentBox,
        to target: ComponentBox
    ) -> (source: ConnectionAnchor, target: ConnectionAnchor) {
        var best = (source: ConnectionAnchor.top, target: ConnectionAnchor.top)
        var shortest = CGFloat.infinity

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
