import CoreGraphics

/// The rectangle a component occupies, in model coordinates.
///
/// Every component draws at one fixed size, so the rectangle follows from the
/// component's position. The position is the rectangle's top-left corner,
/// which is what `AddComponent` and `MoveComponents` store.
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a pure value with no shared state.
nonisolated struct ComponentBox: Equatable {
    static let size = CGSize(width: 160, height: 72)

    let origin: CGPoint

    init(x: Double, y: Double) {
        origin = CGPoint(x: x, y: y)
    }

    var rect: CGRect { CGRect(origin: origin, size: Self.size) }

    var centre: CGPoint { CGPoint(x: rect.midX, y: rect.midY) }

    func contains(_ modelPoint: CGPoint) -> Bool { rect.contains(modelPoint) }
}
