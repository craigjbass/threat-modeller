import CoreGraphics
import Foundation
import SwiftUI
import ThreatModelKit

/// The curve a link draws, and the hit test for clicking it.
///
/// The curve itself is `FlowCurve` in the core, because the generated layout
/// measures the picture it drew. This wrapper adds what only a canvas needs:
/// the arrowhead and how near a click has to be.
///
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a pure value with no shared state.
nonisolated struct ConnectionPath: Equatable {
    /// How far a click may sit from the curve and still select the link, in
    /// model units.
    static let hitTolerance: CGFloat = 8

    let curve: FlowCurve

    init(from start: CGPoint, to end: CGPoint, avoiding zones: [Rect] = []) {
        let from = Point(x: start.x, y: start.y)
        let to = Point(x: end.x, y: end.y)
        curve = FlowCurve(
            from: from,
            through: FlowRouting.waypoints(from: from, to: to, avoiding: zones),
            to: to
        )
    }

    /// The path a canvas strokes, one piece per leg of the flow.
    var drawnPath: Path {
        var built = Path()
        guard let first = curve.segments.first else { return built }

        built.move(to: CGPoint(first.start))
        for segment in curve.segments {
            built.addCurve(
                to: CGPoint(segment.end),
                control1: CGPoint(segment.control1),
                control2: CGPoint(segment.control2)
            )
        }
        return built
    }

    var start: CGPoint { CGPoint(curve.start) }
    var end: CGPoint { CGPoint(curve.end) }
    var control1: CGPoint { CGPoint(curve.control1) }
    var control2: CGPoint { CGPoint(curve.control2) }

    /// The point at `t`, where 0 is the start and 1 is the end.
    func point(at t: CGFloat) -> CGPoint { CGPoint(curve.point(at: t)) }

    /// The shortest distance from the point to the curve, sampled at 40 steps.
    /// Sampling is enough here: the gap between two samples is far smaller than
    /// `hitTolerance` for any link the canvas draws.
    func distance(to modelPoint: CGPoint) -> CGFloat {
        (0...40).reduce(CGFloat.infinity) { shortest, step in
            let sample = point(at: CGFloat(step) / 40)
            return min(shortest, hypot(sample.x - modelPoint.x, sample.y - modelPoint.y))
        }
    }

    func containsClick(at modelPoint: CGPoint) -> Bool {
        distance(to: modelPoint) <= Self.hitTolerance
    }

    /// The three points of the arrowhead at `end`, pointing along the curve's
    /// final direction. The first point is the tip.
    func arrowhead(length: CGFloat = 10, width: CGFloat = 8) -> [CGPoint] {
        let approach = point(at: 0.98)
        let angle = atan2(end.y - approach.y, end.x - approach.x)
        let baseX = end.x - length * cos(angle)
        let baseY = end.y - length * sin(angle)

        return [
            end,
            CGPoint(x: baseX - width / 2 * sin(angle), y: baseY + width / 2 * cos(angle)),
            CGPoint(x: baseX + width / 2 * sin(angle), y: baseY - width / 2 * cos(angle))
        ]
    }
}

nonisolated extension CGPoint {
    /// The core states a diagram point as its own `Point`. A canvas draws in
    /// `CGPoint`, so every reading crosses here rather than in ten call sites.
    init(_ point: Point) {
        self.init(x: point.x, y: point.y)
    }

    var modelPoint: Point { Point(x: x, y: y) }
}

nonisolated extension CGRect {
    init(_ rect: Rect) {
        self.init(
            x: rect.origin.x,
            y: rect.origin.y,
            width: rect.size.width,
            height: rect.size.height
        )
    }

    var modelRect: Rect {
        Rect(x: origin.x, y: origin.y, width: size.width, height: size.height)
    }
}
