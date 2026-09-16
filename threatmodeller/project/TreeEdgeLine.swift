import CoreGraphics
import Foundation
import SwiftUI

/// Where one join is drawn on the tree canvas, and how near a click has to be
/// to select it.
///
/// The design in
/// `docs/superpowers/specs/2026-09-16-tree-edge-selection-design.md` states
/// the rule: a join draws as a straight line out of the right edge of the
/// node it leaves and into the left edge of the node it feeds. The tolerance
/// is `ConnectionPath.hitTolerance`, the one the architecture canvas states
/// for a flow, so a click selects a join the way it selects a flow.
///
/// The canvas strokes `drawnPath` and takes `hitPath` as its content shape,
/// so the picture and the hit region come from one place.
///
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a pure value with no shared state.
nonisolated struct TreeEdgeLine: Equatable, Identifiable {
    /// How long each barb of the head is.
    static let headLength: CGFloat = 10

    let edge: TreeGraph.Edge
    let start: CGPoint
    let end: CGPoint

    var id: String { edge.id }

    /// The shortest distance from one point to the line.
    func distance(to point: CGPoint) -> CGFloat {
        let run = CGSize(width: end.x - start.x, height: end.y - start.y)
        let lengthSquared = run.width * run.width + run.height * run.height
        guard lengthSquared > 0 else { return hypot(point.x - start.x, point.y - start.y) }
        let along = ((point.x - start.x) * run.width + (point.y - start.y) * run.height) / lengthSquared
        let held = min(max(along, 0), 1)
        let near = CGPoint(x: start.x + held * run.width, y: start.y + held * run.height)
        return hypot(point.x - near.x, point.y - near.y)
    }

    /// True when a click at the point selects this join.
    func containsClick(at point: CGPoint) -> Bool {
        distance(to: point) <= ConnectionPath.hitTolerance
    }

    /// The path the canvas strokes: the line, then the two barbs of the head
    /// that state what feeds what.
    var drawnPath: Path {
        var built = Path()
        built.move(to: start)
        built.addLine(to: end)

        let angle = atan2(end.y - start.y, end.x - start.x)
        for turn in [angle + .pi * 0.85, angle - .pi * 0.85] {
            built.move(to: end)
            built.addLine(to: CGPoint(
                x: end.x + Self.headLength * cos(turn),
                y: end.y + Self.headLength * sin(turn)
            ))
        }
        return built
    }

    /// The region a click selects the join in: the line, widened by the
    /// tolerance on both sides.
    var hitPath: Path {
        var line = Path()
        line.move(to: start)
        line.addLine(to: end)
        return line.strokedPath(
            StrokeStyle(lineWidth: ConnectionPath.hitTolerance * 2, lineCap: .round)
        )
    }
}
