import CoreGraphics

/// What area a picture of the selection covers.
///
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a pure value with no shared state.
nonisolated enum SelectionBounds {
    /// The room left around the selected elements in a copied picture.
    static let margin: CGFloat = 24

    /// The rectangle holding every element given, with the margin around it,
    /// or nil when nothing is given.
    static func rect(
        components: [(x: Double, y: Double, width: Double, height: Double)],
        zones: [(x: Double, y: Double, width: Double, height: Double)]
    ) -> CGRect? {
        let rects = (components + zones).map {
            CGRect(x: $0.x, y: $0.y, width: $0.width, height: $0.height)
        }
        guard let first = rects.first else { return nil }
        let whole = rects.dropFirst().reduce(first) { $0.union($1) }
        return whole.insetBy(dx: -margin, dy: -margin)
    }
}
