import CoreGraphics

/// Which components a marquee rectangle selects.
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a pure value with no shared state.
nonisolated enum MarqueeSelection {
    /// A rectangle from the drag's two corners, whichever way the drag went.
    static func rect(from start: CGPoint, to end: CGPoint) -> CGRect {
        CGRect(
            x: min(start.x, end.x),
            y: min(start.y, end.y),
            width: abs(end.x - start.x),
            height: abs(end.y - start.y)
        )
    }

    /// The identifiers of every box the rectangle touches, in the order given.
    /// A box counts when the rectangle overlaps it at all, which is what a user
    /// expects from a lasso.
    static func selected(in rect: CGRect, from boxes: [(id: String, box: ComponentBox)]) -> [String] {
        boxes.filter { rect.intersects($0.box.rect) }.map(\.id)
    }
}
