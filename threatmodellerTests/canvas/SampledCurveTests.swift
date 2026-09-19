import CoreGraphics
import Testing
@testable import threatmodeller

/// The distance from a point to a curve, which every curve the canvas draws
/// reads from one place.
struct SampledCurveTests {
    private let link = ConnectionPath(from: CGPoint(x: 0, y: 0), to: CGPoint(x: 300, y: 180))

    /// The distance from the point to the curve, taken from one hundred
    /// samples for every step the shared function takes.
    private func trueDistance<Curve: SampledCurve>(from point: CGPoint, to curve: Curve) -> CGFloat {
        let steps = Curve.sampleSteps * 100
        return (0...steps).reduce(CGFloat.infinity) { shortest, step in
            let sample = curve.point(at: CGFloat(step) / CGFloat(steps))
            return min(shortest, hypot(sample.x - point.x, sample.y - point.y))
        }
    }

    /// The longest gap between two samples the shared function takes.
    private func longestGap<Curve: SampledCurve>(of curve: Curve) -> CGFloat {
        let steps = Curve.sampleSteps
        return (1...steps).reduce(CGFloat.zero) { longest, step in
            let before = curve.point(at: CGFloat(step - 1) / CGFloat(steps))
            let after = curve.point(at: CGFloat(step) / CGFloat(steps))
            return max(longest, hypot(after.x - before.x, after.y - before.y))
        }
    }

    @Test func givesNoDistanceForAPointOnTheCurve() {
        #expect(link.distance(to: link.point(at: 0.5)) == 0)
    }

    @Test func staysWithinHalfASampleGapOfTheTrueDistanceForACurveTheCanvasDraws() {
        let asked = CGPoint(x: 120, y: 120)
        let sampled = link.distance(to: asked)
        let truth = trueDistance(from: asked, to: link)

        #expect(sampled >= truth)
        #expect(sampled - truth <= longestGap(of: link) / 2)
    }

    @Test func staysWithinHalfASampleGapOfTheTrueDistanceForAPointBesideTheCurve() {
        let asked = CGPoint(x: 150, y: 40)
        let sampled = link.distance(to: asked)
        let truth = trueDistance(from: asked, to: link)

        #expect(sampled >= truth)
        #expect(sampled - truth <= longestGap(of: link) / 2)
    }

    @Test func holdsAPointInsideTheReachAndNoPointOutsideIt() {
        let on = link.point(at: 0.25)
        let beside = CGPoint(x: on.x, y: on.y + 20)

        #expect(link.isWithin(4, of: on))
        #expect(link.isWithin(4, of: beside) == false)
        #expect(link.isWithin(30, of: beside))
    }
}
