import CoreGraphics
import Foundation
import SwiftUI
import ThreatModelKit

/// One `mitigates` edge as the canvas draws it.
///
/// A flow draws a thin cubic curve with an arrowhead, in the risk colour.
/// This draws a thick bowed curve with a shield on it and no arrowhead, so a
/// reader tells one mark from the other. The bow moves the mark off the
/// straight line between the two boxes, so a flow between the same pair and
/// this mark never lie on each other.
///
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a pure value with no shared state.
nonisolated struct MitigatesMark: Equatable {
    /// The component that lowers the threat.
    let sourceComponentId: String
    /// The component the threat is lowered on.
    let targetComponentId: String
    /// True while the team would run this and does not run it today.
    let isAssumed: Bool
    let start: CGPoint
    let end: CGPoint
    /// The control point of the quadratic curve, off the straight line.
    let control: CGPoint

    /// The point at `t`, where 0 is the start and 1 is the end.
    func point(at t: CGFloat) -> CGPoint {
        let rest = 1 - t
        return CGPoint(
            x: rest * rest * start.x + 2 * rest * t * control.x + t * t * end.x,
            y: rest * rest * start.y + 2 * rest * t * control.y + t * t * end.y
        )
    }

    /// The middle of the curve, which is where the shield sits.
    var apex: CGPoint { point(at: 0.5) }

    /// The dash the curve is stroked with. An assumed edge is drawn broken,
    /// the way an assumed guard chip is drawn broken at a boundary.
    var dash: [CGFloat] { isAssumed ? [6, 4] : [] }

    /// An adopted edge lowers the score today, so its shield is filled. An
    /// assumed one leaves the shield hollow.
    var isShieldFilled: Bool { isAssumed == false }

    /// Where the shield is drawn, centred on the middle of the curve.
    var shieldRect: CGRect {
        CGRect(
            x: apex.x - MitigatesGeometry.shieldSize.width / 2,
            y: apex.y - MitigatesGeometry.shieldSize.height / 2,
            width: MitigatesGeometry.shieldSize.width,
            height: MitigatesGeometry.shieldSize.height
        )
    }

    /// The curve a canvas strokes.
    var drawnPath: Path {
        var built = Path()
        built.move(to: start)
        built.addQuadCurve(to: end, control: control)
        return built
    }

    /// The shield: a flat top, two straight sides and a point at the bottom.
    var shieldPath: Path {
        let box = shieldRect
        let shoulder = box.minY + box.height * 0.55

        var built = Path()
        built.move(to: CGPoint(x: box.minX, y: box.minY))
        built.addLine(to: CGPoint(x: box.maxX, y: box.minY))
        built.addLine(to: CGPoint(x: box.maxX, y: shoulder))
        built.addQuadCurve(
            to: CGPoint(x: box.midX, y: box.maxY),
            control: CGPoint(x: box.maxX, y: box.maxY)
        )
        built.addQuadCurve(
            to: CGPoint(x: box.minX, y: shoulder),
            control: CGPoint(x: box.minX, y: box.maxY)
        )
        built.closeSubpath()
        return built
    }

    /// The shortest distance from the point to the curve, sampled at 40
    /// steps. The gap between two samples is far smaller than the tolerance
    /// for any mark the canvas draws.
    func distance(to modelPoint: CGPoint) -> CGFloat {
        (0...40).reduce(CGFloat.infinity) { shortest, step in
            let sample = point(at: CGFloat(step) / 40)
            return min(shortest, hypot(sample.x - modelPoint.x, sample.y - modelPoint.y))
        }
    }

    /// True when a click at this point hits the mark. The shield is the part
    /// a reader aims at, so it counts as the mark as well.
    func containsClick(
        at modelPoint: CGPoint,
        within reach: CGFloat = MitigatesGeometry.hitTolerance
    ) -> Bool {
        shieldRect.contains(modelPoint) || distance(to: modelPoint) <= reach
    }
}

/// Every mitigates mark the canvas draws, and what a click on one hits.
///
/// The layer and the hit test both read this, so the mark is drawn where it
/// is clicked.
///
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this is a pure value computation with no shared state.
nonisolated struct MitigatesGeometry {
    /// How far off the straight line the control point sits, in model units.
    static let bow: CGFloat = 34
    /// How far a click may sit from the curve and still select the edge, in
    /// model units.
    static let hitTolerance: CGFloat = 8
    /// How big the shield on the middle of the curve is.
    static let shieldSize = CGSize(width: 18, height: 20)

    /// The marks in drawing order, one for each edge whose two ends this
    /// build places.
    let marks: [MitigatesMark]

    static func of(
        mitigations: [ViewedMitigation],
        boxes: [String: ComponentBox]
    ) -> MitigatesGeometry {
        var built: [MitigatesMark] = []

        for edge in mitigations {
            guard edge.sourceComponentId != edge.targetComponentId,
                  let protector = boxes[edge.sourceComponentId],
                  let protected = boxes[edge.targetComponentId] else { continue }

            let anchors = AnchorGeometry.nearestPair(
                from: protector.rect.modelRect,
                to: protected.rect.modelRect
            )
            let start = CGPoint(AnchorGeometry.point(anchors.source, of: protector.rect.modelRect))
            let end = CGPoint(AnchorGeometry.point(anchors.target, of: protected.rect.modelRect))
            guard let control = control(from: start, to: end) else { continue }

            built.append(
                MitigatesMark(
                    sourceComponentId: edge.sourceComponentId,
                    targetComponentId: edge.targetComponentId,
                    isAssumed: edge.status == MitigationStatus.assumed.rawValue,
                    start: start,
                    end: end,
                    control: control
                )
            )
        }

        return MitigatesGeometry(marks: built)
    }

    /// The control point that bows the curve off the straight line, or nil
    /// when the two ends sit on the same point.
    private static func control(from start: CGPoint, to end: CGPoint) -> CGPoint? {
        let across = end.x - start.x
        let down = end.y - start.y
        let length = hypot(across, down)
        guard length > 0 else { return nil }

        return CGPoint(
            x: (start.x + end.x) / 2 + down / length * bow,
            y: (start.y + end.y) / 2 - across / length * bow
        )
    }

    /// The edge under the point, or nil. A later mark wins, because it is
    /// drawn on top.
    ///
    /// `within` is how far from the curve a click still counts, in model
    /// units. A caller that draws at a zoom divides by that zoom, so the
    /// reach on screen is the same however far out the diagram is.
    func mark(
        under modelPoint: CGPoint,
        within reach: CGFloat = hitTolerance
    ) -> MitigatesMark? {
        marks.last { $0.containsClick(at: modelPoint, within: reach) }
    }

    /// The two selected components in the order an edge between them holds:
    /// the protector first.
    ///
    /// The bar under the canvas reads "X lowers threats on Y", and the edge
    /// holds the direction. Without this the bar names the pair in model
    /// order, which reverses the sentence and hides the edge the pair holds.
    static func ordered(
        _ both: [ViewedComponent],
        mitigations: [ViewedMitigation]
    ) -> (source: ViewedComponent, target: ViewedComponent)? {
        guard both.count == 2 else { return nil }
        let first = both[0]
        let second = both[1]

        let reversed = mitigations.contains {
            $0.sourceComponentId == second.id && $0.targetComponentId == first.id
        }
        return reversed ? (source: second, target: first) : (source: first, target: second)
    }
}
