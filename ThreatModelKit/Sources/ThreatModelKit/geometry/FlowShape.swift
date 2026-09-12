import Foundation

/// How easy a flow is to follow.
///
/// A line that turns sharply is read as two lines. A line that crosses another
/// makes a reader stop and work out which is which. A line that runs behind a
/// node looks as though it ends there. None of these is wrong, so none is a
/// fault, but a picture with fewer of them is read faster.
public enum FlowShape {
    /// The tightest a turn may be, in points of radius, and still read as part
    /// of a circle. A quarter turn is fine; a quarter turn on a 10 point
    /// radius is a corner.
    public static let easyRadius = 70.0
    /// How many points along a flow are looked at.
    public static let steps = 32

    /// How far the flow turns from end to end, in radians.
    ///
    /// A straight flow turns nothing, a gentle curve about half a radian, and
    /// a flow that doubles back more than three. Counting the samples that
    /// turn sharply misses a tight corner, because a smoothed join spreads one
    /// corner across several samples; the total does not.
    public static func turning(of curve: FlowCurve) -> Double {
        let points = (0...steps).map { curve.point(at: Double($0) / Double(steps)) }
        var total = 0.0

        for index in 1 ..< points.count - 1 {
            let into = heading(from: points[index - 1], to: points[index])
            let outOf = heading(from: points[index], to: points[index + 1])
            guard let into, let outOf else { continue }
            total += turn(from: into, to: outOf)
        }

        return total
    }

    /// How tightly the flow turns, added up along it.
    ///
    /// Zero where it runs straight or sweeps round a wide radius, and rising
    /// as the radius closes. What a reader minds is the radius, not the angle:
    /// a quarter turn on a wide arc is followed without stopping, and the same
    /// quarter turn on a tight one is a corner.
    public static func tightness(of curve: FlowCurve) -> Double {
        let points = (0...steps).map { curve.point(at: Double($0) / Double(steps)) }
        var total = 0.0

        for index in 1 ..< points.count - 1 {
            let radius = turnRadius(points[index - 1], points[index], points[index + 1])
            total += max(0, 1 - radius / easyRadius)
        }

        return total
    }

    /// The radius of the circle through three points. A straight run has no
    /// circle, and reads as an unbounded radius.
    public static func turnRadius(_ first: Point, _ second: Point, _ third: Point) -> Double {
        let a = hypot(second.x - first.x, second.y - first.y)
        let b = hypot(third.x - second.x, third.y - second.y)
        let c = hypot(third.x - first.x, third.y - first.y)

        let twiceArea = abs(
            (second.x - first.x) * (third.y - first.y)
                - (second.y - first.y) * (third.x - first.x)
        )
        guard twiceArea > 0.000_001 else { return .greatestFiniteMagnitude }

        return a * b * c / (2 * twiceArea)
    }

    /// True when the two flows cross. Sampled coarsely: a pair of flows is
    /// tested against every other pair, and a crossing missed by a few points
    /// changes nothing a reader sees.
    public static func crosses(_ first: FlowCurve, _ second: FlowCurve) -> Bool {
        CurveCrossing.crosses(
            CurveCrossing.samples(of: first, steps: steps),
            CurveCrossing.samples(of: second, steps: steps)
        )
    }

    /// How many of the rectangles the flow passes behind.
    public static func timesBehind(_ curve: FlowCurve, _ rects: [Rect]) -> Int {
        guard rects.isEmpty == false else { return 0 }

        let points = (0...steps).map { curve.point(at: Double($0) / Double(steps)) }
        return rects.count { rect in points.contains { rect.contains($0) } }
    }

    private static func heading(from start: Point, to end: Point) -> Double? {
        let dx = end.x - start.x
        let dy = end.y - start.y
        guard hypot(dx, dy) > 0.001 else { return nil }
        return atan2(dy, dx)
    }

    /// The angle between two headings, never more than half a turn.
    private static func turn(from into: Double, to outOf: Double) -> Double {
        var difference = abs(outOf - into)
        while difference > .pi { difference = 2 * .pi - difference }
        return difference
    }
}
