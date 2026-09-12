import Foundation
import SwiftUI
import ThreatModelKit

/// One place where a flow crosses a trust boundary.
///
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a pure value with no shared state.
nonisolated struct BoundaryCrossing: Equatable {
    /// Where the flow meets the boundary, in model coordinates.
    let point: CGPoint
    /// The flow's tangent there. The mark draws across it, at a right angle.
    let angle: CGFloat
    /// The kind of the zone whose edge the flow crosses: public or private.
    /// The zone being entered when the flow enters one, else the zone it
    /// leaves.
    let networkZoneId: String
}

/// Finds where a flow crosses a trust boundary.
///
/// OWASP Threat Dragon draws a trust boundary as a dotted curve across the
/// flow it separates. This application does not model such a curve, because a
/// curve holds no members and scores nothing. It does not need to: a zone
/// already states which components it holds, so the crossing is where the
/// flow's own curve leaves one zone rectangle and enters another.
///
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one holds no state at all.
nonisolated enum BoundaryCrossings {
    /// How long the mark is. It has to read as a boundary beside a 104 point
    /// node, not as a tick on the line.
    static let length: CGFloat = 96
    /// How far the mark bows, so it draws as a curve rather than a straight
    /// line.
    static let bow: CGFloat = 18
    /// How many points along the flow are tested. The gap between two samples
    /// is under three points on the longest link a canvas draws, which is
    /// finer than the mark is wide.
    static let steps = 200

    static func of(
        _ connection: ViewedConnection,
        path: ConnectionPath,
        components: [String: ViewedComponent],
        zones: [ViewedZone]
    ) -> [BoundaryCrossing] {
        let sourceZoneId = components[connection.sourceComponentId]?.zoneId
        let targetZoneId = components[connection.targetComponentId]?.zoneId
        guard sourceZoneId != targetZoneId else { return [] }

        var found: [BoundaryCrossing] = []
        var held = zone(holding: path.point(at: 0), in: zones)

        for step in 1...steps {
            let t = CGFloat(step) / CGFloat(steps)
            let point = path.point(at: t)
            let entered = zone(holding: point, in: zones)
            guard entered?.id != held?.id else { continue }

            let before = path.point(at: CGFloat(step - 1) / CGFloat(steps))
            found.append(
                BoundaryCrossing(
                    point: CGPoint(x: (before.x + point.x) / 2, y: (before.y + point.y) / 2),
                    angle: atan2(point.y - before.y, point.x - before.x),
                    networkZoneId: (entered ?? held)?.networkZoneId ?? "private"
                )
            )
            held = entered
        }

        return found
    }

    /// The zone a point belongs to, by the rule the core uses: the zone's
    /// rectangle with the header band removed, and a later zone wins.
    private static func zone(holding point: CGPoint, in zones: [ViewedZone]) -> ViewedZone? {
        zones.last { ZoneBox(zone: $0).contentRect.contains(point) }
    }

    /// The mark itself: a bow across the flow, centred on the crossing.
    static func mark(for crossing: BoundaryCrossing) -> Path {
        let across = crossing.angle + .pi / 2
        let half = length / 2
        let start = CGPoint(
            x: crossing.point.x - half * cos(across),
            y: crossing.point.y - half * sin(across)
        )
        let end = CGPoint(
            x: crossing.point.x + half * cos(across),
            y: crossing.point.y + half * sin(across)
        )
        // The control point sits off to one side along the flow, so the mark
        // bows rather than running straight.
        let control = CGPoint(
            x: crossing.point.x + bow * cos(crossing.angle),
            y: crossing.point.y + bow * sin(crossing.angle)
        )

        var path = Path()
        path.move(to: start)
        path.addQuadCurve(to: end, control: control)
        return path
    }
}
