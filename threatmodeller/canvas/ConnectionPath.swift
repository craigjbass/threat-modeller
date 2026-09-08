import CoreGraphics
import Foundation

/// The curve a link draws, and the hit test for clicking it.
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a pure value with no shared state.
nonisolated struct ConnectionPath: Equatable {
    /// How far a click may sit from the curve and still select the link, in
    /// model units.
    static let hitTolerance: CGFloat = 8

    let start: CGPoint
    let end: CGPoint
    let control1: CGPoint
    let control2: CGPoint

    init(from start: CGPoint, to end: CGPoint) {
        self.start = start
        self.end = end
        // The horizontal pull grows with the gap, with a floor so a short link
        // still curves and a ceiling so a long one does not loop back.
        let pull = max(30, min(abs(end.x - start.x) * 0.5, 150))
        control1 = CGPoint(x: start.x + pull, y: start.y)
        control2 = CGPoint(x: end.x - pull, y: end.y)
    }

    /// The point at `t`, where 0 is the start and 1 is the end.
    func point(at t: CGFloat) -> CGPoint {
        let u = 1 - t
        return CGPoint(
            x: u * u * u * start.x + 3 * u * u * t * control1.x
                + 3 * u * t * t * control2.x + t * t * t * end.x,
            y: u * u * u * start.y + 3 * u * u * t * control1.y
                + 3 * u * t * t * control2.y + t * t * t * end.y
        )
    }

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
