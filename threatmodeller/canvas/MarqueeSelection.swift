import CoreGraphics

/// Which components a marquee rectangle selects.
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

    /// The identifiers of every zone the rectangle holds whole, in the order
    /// given. A zone counts only when the rectangle covers all of it: a
    /// marquee drawn inside a zone gathers the nodes in that zone, and does
    /// not take the zone itself with them.
    static func selectedZones(in rect: CGRect, from zones: [(id: String, rect: CGRect)]) -> [String] {
        zones.filter { rect.contains($0.rect) }.map(\.id)
    }
}
