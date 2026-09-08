import CoreGraphics
import ThreatModelKit

/// The rectangle a component occupies, in model coordinates.
///
/// The size comes from the core, because zone containment tests a component's
/// centre and the core has to know the extent that centre comes from.
///
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a pure value with no shared state.
nonisolated struct ComponentBox: Equatable {
    static let size = CGSize(width: Component.size.width, height: Component.size.height)

    let origin: CGPoint

    init(x: Double, y: Double) {
        origin = CGPoint(x: x, y: y)
    }

    var rect: CGRect { CGRect(origin: origin, size: Self.size) }

    var centre: CGPoint { CGPoint(x: rect.midX, y: rect.midY) }

    func contains(_ modelPoint: CGPoint) -> Bool { rect.contains(modelPoint) }
}
