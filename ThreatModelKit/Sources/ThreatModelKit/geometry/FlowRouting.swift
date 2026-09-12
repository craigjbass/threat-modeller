import Foundation

/// Takes a flow round a zone it has nothing to do with.
///
/// A flow drawn over a zone rectangle reads as a statement that the flow
/// touches what the zone holds, and it does not. The core owns the rule, and
/// the canvas and the generated layout both call it, so the picture the layout
/// measured is the picture the canvas draws. Nothing is stored.
public enum FlowRouting {
    /// How far outside a zone a detour passes.
    public static let clearance = 24.0
    /// How many detours one flow may take. A flow that is still over a zone
    /// after this keeps what it has, and the layout counts the fault.
    ///
    /// Four. Two is not enough to clear a zone a flow meets end on, and the
    /// two-way choice below is what stops a flow going back and forth.
    public static let mostWaypoints = 4
    /// How many points along the flow are tested for entering a zone.
    public static let steps = 96
    /// The shortest leg a detour may leave.
    ///
    /// Two detours closer together than this leave a leg too short to turn
    /// on, and the flow kinks between them. Longer than this and a needed
    /// detour gets thinned away, which is worse: the flow then runs over the
    /// zone it was going round.
    public static let shortestLeg = 70.0

    /// The waypoints that take the flow round every zone it should avoid, in
    /// the order the flow meets them. Empty when the straight flow is already
    /// clear.
    public static func waypoints(
        from start: Point,
        to end: Point,
        avoiding zones: [Rect]
    ) -> [Point] {
        guard zones.isEmpty == false else { return [] }

        var found: [Point] = []

        for _ in 0 ..< mostWaypoints {
            let curve = FlowCurve(from: start, through: found, to: end)
            guard let entered = firstZone(curve, enters: zones) else { break }

            // Both ways round, and the one that leaves the flow in fewer zones
            // and turning less. Always taking the nearer side sent a flow back
            // and forth to the cap, and a reader follows a corner rather than
            // a line.
            let tried = ways(round: entered.zone, at: entered.point, travellingFrom: start, to: end)
                .map { way -> (way: Point, cost: Cost) in
                    (way, cost(of: FlowCurve(from: start, through: found + [way], to: end), zones: zones))
                }
                .sorted { $0.cost < $1.cost }

            guard let best = tried.first else { break }
            found.append(best.way)
        }

        return thinned(found, from: start, to: end)
    }

    /// The waypoints with the crowded ones dropped.
    ///
    /// Two detours close together leave a leg too short to turn on, and the
    /// flow kinks between them however wide the controls reach.
    private static func thinned(_ waypoints: [Point], from start: Point, to end: Point) -> [Point] {
        var kept: [Point] = []
        var last = start

        for waypoint in waypoints {
            guard hypot(waypoint.x - last.x, waypoint.y - last.y) >= shortestLeg else { continue }
            kept.append(waypoint)
            last = waypoint
        }

        // The last leg is as much a leg as any other.
        while let final = kept.last,
              hypot(end.x - final.x, end.y - final.y) < shortestLeg {
            kept.removeLast()
        }

        return kept
    }

    /// How bad a routed flow is: how many zones it still enters, and how far
    /// it turns getting there.
    struct Cost: Comparable {
        let entered: Int
        let turning: Double

        static func < (one: Cost, other: Cost) -> Bool {
            one.entered == other.entered
                ? one.turning < other.turning
                : one.entered < other.entered
        }
    }

    private static func cost(of curve: FlowCurve, zones: [Rect]) -> Cost {
        let points = (0...steps).map { curve.point(at: Double($0) / Double(steps)) }
        return Cost(
            entered: zones.count { zone in points.contains { zone.contains($0) } },
            turning: FlowShape.turning(of: curve)
        )
    }

    /// The first zone the curve enters, and where it entered.
    private static func firstZone(
        _ curve: FlowCurve,
        enters zones: [Rect]
    ) -> (zone: Rect, point: Point)? {
        for step in 0...steps {
            let point = curve.point(at: Double(step) / Double(steps))
            if let zone = zones.first(where: { $0.contains(point) }) {
                return (zone, point)
            }
        }

        return nil
    }

    /// The two points that clear the zone, the nearer side first.
    ///
    /// The way out is across the flow, not along it: a level flow passes over
    /// the top or under the bottom, and an upright flow round the left or the
    /// right. Going round the near side would put the waypoint in front of the
    /// zone and clear nothing.
    private static func ways(
        round zone: Rect,
        at entry: Point,
        travellingFrom start: Point,
        to end: Point
    ) -> [Point] {
        let level = abs(end.x - start.x) >= abs(end.y - start.y)

        if level {
            let alongX = min(max(entry.x, zone.minX), zone.maxX)
            let over = Point(x: alongX, y: zone.minY - clearance)
            let under = Point(x: alongX, y: zone.maxY + clearance)
            return entry.y - zone.minY <= zone.maxY - entry.y ? [over, under] : [under, over]
        }

        let alongY = min(max(entry.y, zone.minY), zone.maxY)
        let left = Point(x: zone.minX - clearance, y: alongY)
        let right = Point(x: zone.maxX + clearance, y: alongY)
        return entry.x - zone.minX <= zone.maxX - entry.x ? [left, right] : [right, left]
    }
}
