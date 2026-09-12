import Foundation

/// The curve a flow draws from one component to another, through however many
/// waypoints it needs to go round a zone it has nothing to do with.
///
/// The core owns it because the generated layout measures what it drew: a
/// layout that cannot see its own picture cannot improve it. The arrowhead and
/// the click tolerance are drawing, and stay in the delivery mechanism.
public struct FlowCurve: Equatable, Sendable {
    /// One cubic piece of the chain.
    public struct Segment: Equatable, Sendable {
        public let start: Point
        public let control1: Point
        public let control2: Point
        public let end: Point

        public init(start: Point, control1: Point, control2: Point, end: Point) {
            self.start = start
            self.control1 = control1
            self.control2 = control2
            self.end = end
        }

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

    public let segments: [Segment]

    public init(from start: Point, to end: Point) {
        self.init(from: start, through: [], to: end)
    }

    /// A flow through waypoints. Each piece pulls sideways the way a single
    /// curve does, and a middle piece aims its controls along the line joining
    /// its neighbours, so a join does not kink.
    public init(from start: Point, through waypoints: [Point], to end: Point) {
        let points = [start] + waypoints + [end]
        var built: [Segment] = []

        for index in 0 ..< points.count - 1 {
            let from = points[index]
            let to = points[index + 1]
            let before = index > 0 ? points[index - 1] : nil
            let after = index + 2 < points.count ? points[index + 2] : nil

            built.append(
                Segment(
                    start: from,
                    control1: Self.control(leaving: from, towards: to, from: before),
                    control2: Self.control(leaving: to, towards: from, from: after),
                    end: to
                )
            )
        }

        segments = built
    }

    /// The control point beside `here`, on the way to `next`.
    ///
    /// With no neighbour the pull is horizontal, the way a single curve has
    /// always drawn. With one, the pull follows the line from that neighbour to
    /// `next`, so the two pieces meeting at `here` leave in the same direction.
    private static func control(
        leaving here: Point,
        towards next: Point,
        from neighbour: Point?
    ) -> Point {
        let pull = max(30, min(abs(next.x - here.x) * 0.5, 150))

        guard let neighbour else {
            return Point(x: here.x + (next.x >= here.x ? pull : -pull), y: here.y)
        }

        let dx = next.x - neighbour.x
        let dy = next.y - neighbour.y
        let length = hypot(dx, dy)
        guard length > 0 else { return here }

        return Point(x: here.x + pull * dx / length, y: here.y + pull * dy / length)
    }

    public var start: Point { segments.first?.start ?? Point(x: 0, y: 0) }
    public var end: Point { segments.last?.end ?? Point(x: 0, y: 0) }
    /// The first piece's controls, so a reader of a straight flow sees what it
    /// always saw.
    public var control1: Point { segments.first?.control1 ?? start }
    public var control2: Point { segments.first?.control2 ?? end }

    /// How many waypoints the flow goes through.
    public var waypointCount: Int { max(0, segments.count - 1) }

    /// The point at `t`, where 0 is the start and 1 is the end. `t` divides
    /// evenly across the pieces, which is enough: every reader samples densely
    /// rather than measuring the length.
    public func point(at t: Double) -> Point {
        guard segments.isEmpty == false else { return Point(x: 0, y: 0) }

        let scaled = min(max(t, 0), 1) * Double(segments.count)
        let index = min(Int(scaled), segments.count - 1)
        return segments[index].point(at: scaled - Double(index))
    }
}
