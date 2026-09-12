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
                    control1: Self.control(
                        leaving: from,
                        towards: to,
                        from: before,
                        routed: waypoints.isEmpty == false
                    ),
                    control2: Self.control(
                        leaving: to,
                        towards: from,
                        from: after,
                        routed: waypoints.isEmpty == false
                    ),
                    end: to
                )
            )
        }

        segments = built
    }

    /// The shortest a turn's control reaches at a join. A turn drawn on a
    /// short control reads as a corner; one drawn on a long control reads as
    /// part of a circle, which is what a reader follows.
    static let turnReach = 90.0

    /// The control point beside `here`, on the way to `next`.
    ///
    /// With no neighbour the pull is horizontal and measured across the gap,
    /// the way a single curve has always drawn. At a join the pull follows the
    /// line from that neighbour to `next`, so the two pieces leave in the same
    /// direction, and it is measured along the leg rather than across it: a
    /// leg straight up the diagram spans no width at all, and a pull taken
    /// from the width alone turned it on the spot.
    private static func control(
        leaving here: Point,
        towards next: Point,
        from neighbour: Point?,
        routed: Bool
    ) -> Point {
        let leg = hypot(next.x - here.x, next.y - here.y)
        // Never past a little under half the leg: two controls that reach past
        // each other curl the piece back inside itself, and the curl has a
        // tighter radius than any corner.
        let pull = min(max(turnReach, min(leg * 0.5, 150)), leg * 0.45)

        // The two ends of a routed flow follow their own leg. Pulling them
        // sideways, the way a straight flow leaves its node, hooked a flow
        // arriving from above into a corner at the arrowhead.
        guard let neighbour else {
            let mostlyLevel = abs(next.x - here.x) >= abs(next.y - here.y)

            // A level flow leaves sideways, the way this canvas has always
            // drawn one. An upright flow leaves along its own line: pulled
            // sideways it hooked out and back on a 27 point radius.
            guard routed || mostlyLevel == false, leg > 0 else {
                let sideways = max(30, min(abs(next.x - here.x) * 0.5, 150))
                return Point(x: here.x + (next.x >= here.x ? sideways : -sideways), y: here.y)
            }
            return Point(
                x: here.x + pull * (next.x - here.x) / leg,
                y: here.y + pull * (next.y - here.y) / leg
            )
        }

        let dx = next.x - neighbour.x
        let dy = next.y - neighbour.y
        let length = hypot(dx, dy)

        // At a hairpin the neighbour sits almost on top of `next`, so the line
        // between them states no direction, or states one pointing back the
        // way the flow came. Either way the control collapses and the curve
        // cusps, so the leg itself is the direction.
        let alongTheLeg = leg > 0
            ? Point(x: (next.x - here.x) / leg, y: (next.y - here.y) / leg)
            : Point(x: 0, y: 0)
        guard length > 0.001 else {
            return Point(x: here.x + pull * alongTheLeg.x, y: here.y + pull * alongTheLeg.y)
        }

        let heading = Point(x: dx / length, y: dy / length)
        let agreement = heading.x * alongTheLeg.x + heading.y * alongTheLeg.y
        let chosen = agreement > 0.1 ? heading : alongTheLeg

        return Point(x: here.x + pull * chosen.x, y: here.y + pull * chosen.y)
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
