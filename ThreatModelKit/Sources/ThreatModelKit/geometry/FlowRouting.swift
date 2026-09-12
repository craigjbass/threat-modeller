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
    public static let mostWaypoints = 4
    /// How many points along the flow are tested for entering a zone.
    public static let steps = 96

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
            found.append(
                waypoint(
                    round: entered.zone,
                    at: entered.point,
                    travellingFrom: start,
                    to: end
                )
            )
        }

        return found
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

    /// The point the flow goes through to clear the zone.
    ///
    /// The way out is across the flow, not along it: a level flow passes over
    /// the top or under the bottom, and an upright flow round the left or the
    /// right. Going round the near side would put the waypoint in front of the
    /// zone and clear nothing.
    private static func waypoint(
        round zone: Rect,
        at entry: Point,
        travellingFrom start: Point,
        to end: Point
    ) -> Point {
        let level = abs(end.x - start.x) >= abs(end.y - start.y)

        if level {
            let alongX = min(max(entry.x, zone.minX), zone.maxX)
            return entry.y - zone.minY <= zone.maxY - entry.y
                ? Point(x: alongX, y: zone.minY - clearance)
                : Point(x: alongX, y: zone.maxY + clearance)
        }

        let alongY = min(max(entry.y, zone.minY), zone.maxY)
        return entry.x - zone.minX <= zone.maxX - entry.x
            ? Point(x: zone.minX - clearance, y: alongY)
            : Point(x: zone.maxX + clearance, y: alongY)
    }
}
