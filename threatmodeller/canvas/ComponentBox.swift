import CoreGraphics
import ThreatModelKit

/// The area a component draws in, in model coordinates.
///
/// A component holds one slot, 160 by 72, whatever it draws as. The core owns
/// that size, because zone containment tests the centre of the slot and the
/// core has to know the extent that centre comes from.
///
/// The drawn footprint is smaller or taller than the slot for a process and a
/// store, and it centres on the same point, so a shape change never moves a
/// component and never changes which zone holds it.
///
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a pure value with no shared state.
nonisolated struct ComponentBox: Equatable {
    /// The slot a component occupies, whatever shape it draws as.
    static let slotSize = CGSize(width: Component.size.width, height: Component.size.height)

    let origin: CGPoint
    let shape: DiagramShape

    init(x: Double, y: Double, shape: DiagramShape = .actor) {
        origin = CGPoint(x: x, y: y)
        self.shape = shape
    }

    /// The centre of the slot. `ZoneContainment` tests this point, and every
    /// footprint centres on it.
    var centre: CGPoint {
        CGPoint(x: origin.x + Self.slotSize.width / 2, y: origin.y + Self.slotSize.height / 2)
    }

    /// The footprint the canvas paints. The core owns the rule, because the
    /// generated layout measures the picture it drew.
    var rect: CGRect {
        CGRect(
            Component.footprintRect(
                at: Point(x: origin.x, y: origin.y),
                shape: shape
            )
        )
    }

    /// A process is a circle, so the corners of its bounding square belong to
    /// whatever is behind it, not to the node.
    func contains(_ modelPoint: CGPoint) -> Bool {
        guard shape == .process else { return rect.contains(modelPoint) }

        let dx = (modelPoint.x - rect.midX) / (rect.width / 2)
        let dy = (modelPoint.y - rect.midY) / (rect.height / 2)
        return dx * dx + dy * dy <= 1
    }
}
