import Foundation

/// Whether two curves on the diagram cross, and where.
///
/// A flow that has nothing to do with a trust boundary must not cross that
/// boundary's curve: a reader takes a crossing for a statement that the
/// boundary applies to the flow, and it does not. The generated layout counts
/// these, and the canvas cuts a gap where one survives.
public enum CurveCrossing {
    /// How many points a curve is sampled at. The gap between two samples on
    /// the longest link a canvas draws is under 60 points, which is finer than
    /// anything the count decides.
    public static let steps = 48

    public static func samples(of curve: FlowCurve, steps: Int = steps) -> [Point] {
        (0...steps).map { curve.point(at: Double($0) / Double(steps)) }
    }

    public static func samples(
        of run: BoundaryCrossings.BoundaryRun,
        steps: Int = steps
    ) -> [Point] {
        (0...steps).map { run.point(at: Double($0) / Double(steps)) }
    }

    /// True when the two open polylines cross.
    public static func crosses(_ first: [Point], _ second: [Point]) -> Bool {
        crossings(first, second).isEmpty == false
    }

    /// Where the two cross, as indices into `first`. An index names the
    /// segment that starts at that point.
    public static func crossings(_ first: [Point], _ second: [Point]) -> [Int] {
        guard first.count > 1, second.count > 1 else { return [] }

        var found: [Int] = []

        for i in 0 ..< first.count - 1 {
            for j in 0 ..< second.count - 1 {
                if segmentsCross(first[i], first[i + 1], second[j], second[j + 1]) {
                    found.append(i)
                    break
                }
            }
        }

        return found
    }

    /// Two segments cross when each straddles the other's line. Touching at an
    /// endpoint is not a crossing: two curves that meet at a shared node are
    /// not one passing through the other.
    private static func segmentsCross(_ a: Point, _ b: Point, _ c: Point, _ d: Point) -> Bool {
        func side(_ origin: Point, _ first: Point, _ second: Point) -> Double {
            (first.x - origin.x) * (second.y - origin.y)
                - (first.y - origin.y) * (second.x - origin.x)
        }

        let first = side(c, d, a)
        let second = side(c, d, b)
        let third = side(a, b, c)
        let fourth = side(a, b, d)

        // A zero means an end point sits on the other segment. Two curves that
        // meet at a shared node are not one passing through the other.
        guard first != 0, second != 0, third != 0, fourth != 0 else { return false }

        return (first > 0) != (second > 0) && (third > 0) != (fourth > 0)
    }

    /// True when the point all but sits on the polyline.
    ///
    /// A crossing test alone misses the case where a sample lands exactly on
    /// the other curve: every determinant is then zero and nothing straddles
    /// anything. A canvas still shows the two touching, so the caller needs to
    /// know.
    public static func touches(_ point: Point, _ polyline: [Point], within reach: Double) -> Bool {
        guard polyline.count > 1 else { return false }

        for index in 0 ..< polyline.count - 1 {
            if distance(from: point, to: polyline[index], polyline[index + 1]) <= reach {
                return true
            }
        }

        return false
    }

    /// The shortest distance from the point to the segment.
    private static func distance(from point: Point, to start: Point, _ end: Point) -> Double {
        let dx = end.x - start.x
        let dy = end.y - start.y
        let lengthSquared = dx * dx + dy * dy

        guard lengthSquared > 0 else {
            return hypot(point.x - start.x, point.y - start.y)
        }

        let along = min(
            1,
            max(0, ((point.x - start.x) * dx + (point.y - start.y) * dy) / lengthSquared)
        )
        let nearest = Point(x: start.x + along * dx, y: start.y + along * dy)
        return hypot(point.x - nearest.x, point.y - nearest.y)
    }
}
