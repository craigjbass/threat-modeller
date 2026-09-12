import Foundation

/// The curve a flow draws from one component to another.
///
/// The core owns it because the generated layout measures what it drew: a
/// layout that cannot see its own picture cannot improve it. The arrowhead and
/// the click tolerance are drawing, and stay in the delivery mechanism.
public struct FlowCurve: Equatable, Sendable {
    public let start: Point
    public let end: Point
    public let control1: Point
    public let control2: Point

    public init(from start: Point, to end: Point) {
        self.start = start
        self.end = end
        // The horizontal pull grows with the gap, with a floor so a short link
        // still curves and a ceiling so a long one does not loop back.
        let pull = max(30, min(abs(end.x - start.x) * 0.5, 150))
        control1 = Point(x: start.x + pull, y: start.y)
        control2 = Point(x: end.x - pull, y: end.y)
    }

    /// The point at `t`, where 0 is the start and 1 is the end.
    public func point(at t: Double) -> Point {
        let u = 1 - t
        return Point(
            x: u * u * u * start.x + 3 * u * u * t * control1.x
                + 3 * u * t * t * control2.x + t * t * t * end.x,
            y: u * u * u * start.y + 3 * u * u * t * control1.y
                + 3 * u * t * t * control2.y + t * t * t * end.y
        )
    }
}
