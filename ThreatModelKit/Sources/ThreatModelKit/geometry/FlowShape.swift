import Foundation

/// How easy a flow is to follow.
///
/// A line that turns sharply is read as two lines. A line that crosses another
/// makes a reader stop and work out which is which. A line that runs behind a
/// node looks as though it ends there. None of these is wrong, so none is a
/// fault, but a picture with fewer of them is read faster.
public enum FlowShape {
    /// How far a flow may turn, in radians, before it stops flowing. A gentle
    /// S bends about half a radian; a quarter turn is the point past which a
    /// reader follows a corner rather than a line.
    public static let turnsFreely = Double.pi / 2
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

    /// How far past a comfortable turn the flow goes. Zero for anything a
    /// reader follows without stopping.
    public static func sharpness(of curve: FlowCurve) -> Double {
        max(0, turning(of: curve) - turnsFreely)
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
