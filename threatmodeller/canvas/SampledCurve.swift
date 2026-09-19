import CoreGraphics
import Foundation

/// A curve the canvas draws, and how near a point sits to it.
///
/// A flow draws one curve and a `mitigates` edge draws another. A click on
/// either asks the same question, so both read the answer from here.
nonisolated protocol SampledCurve {
    /// The point at `t`, where 0 is the start and 1 is the end.
    func point(at t: CGFloat) -> CGPoint
}

nonisolated extension SampledCurve {
    static var sampleSteps: Int { 40 }

    /// The shortest distance from the point to the curve, in model units.
    func distance(to modelPoint: CGPoint) -> CGFloat {
        (0...Self.sampleSteps).reduce(CGFloat.infinity) { shortest, step in
            let sample = point(at: CGFloat(step) / CGFloat(Self.sampleSteps))
            return min(shortest, hypot(sample.x - modelPoint.x, sample.y - modelPoint.y))
        }
    }

    /// True while the point sits `reach` model units from the curve or nearer.
    ///
    /// A caller states `reach` in model units. A caller that draws the
    /// diagram at a zoom takes the reach it wants on screen and divides it by
    /// the zoom, so a click keeps one reach on screen at every zoom.
    func isWithin(_ reach: CGFloat, of modelPoint: CGPoint) -> Bool {
        distance(to: modelPoint) <= reach
    }
}
