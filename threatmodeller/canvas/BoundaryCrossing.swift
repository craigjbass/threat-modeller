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
    /// The zone whose edge the flow crosses. The zone being entered when the
    /// flow enters one, else the zone it leaves.
    let zoneId: String
    /// That zone's kind: public or private.
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
    /// The shortest a boundary curve may be. One flow through it still has to
    /// read as a boundary beside a 104 point node, not as a tick on the line.
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
                    zoneId: (entered ?? held)?.id ?? "",
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

    /// How far apart two crossings of one boundary may sit and still belong to
    /// the same run. Beyond this the boundary draws twice, because one curve
    /// across the gap would claim canvas it does not cross.
    static let together: CGFloat = 200

    /// The blank the run leaves past the outermost flow it crosses, so the
    /// curve reaches beyond every arrow through it.
    static let overhang: CGFloat = 34

    /// One crossing with what the flow through it carries.
    nonisolated struct MarkedCrossing: Equatable {
        let crossing: BoundaryCrossing
        /// What guards the flow there: the components on the far end of it and
        /// on the flow itself.
        let guards: [EdgeGuard]
        /// Threats on that flow no control answers.
        let openCount: Int

        /// Two crossings belong to the same boundary when they cross the same
        /// zone and the same set of components guards them.
        var boundaryKey: String {
            let names = guards.map { "\($0.label)\($0.isAssumed ? "~" : "")" }.joined(separator: "+")
            return "\(crossing.zoneId)|\(names)"
        }
    }

    /// One dotted curve for each boundary: one zone edge, one set of guards,
    /// one run of flows through it.
    nonisolated struct BoundaryRun: Equatable {
        let zoneId: String
        let networkZoneId: String
        let guards: [EdgeGuard]
        /// Threats no control answers, across every flow through this run.
        let openCount: Int
        /// How many flows pass through the curve.
        let flowCount: Int
        let start: CGPoint
        let end: CGPoint
        let control: CGPoint

        var curve: Path {
            var path = Path()
            path.move(to: start)
            path.addQuadCurve(to: end, control: control)
            return path
        }
    }

    /// Turns every crossing on the canvas into the boundaries a reader sees.
    ///
    /// Crossings of one zone that the same components guard, and that sit near
    /// each other, make one run: one curve, long enough that every arrow in
    /// the run passes through it, and one set of chips. Eight flows through
    /// one guarded edge then draw one boundary rather than eight.
    static func runs(_ marked: [MarkedCrossing]) -> [BoundaryRun] {
        var order: [String] = []
        var grouped: [String: [MarkedCrossing]] = [:]

        for one in marked {
            let key = one.boundaryKey
            if grouped[key] == nil { order.append(key) }
            grouped[key, default: []].append(one)
        }

        return order.flatMap { key in
            clusters(of: grouped[key] ?? []).map(run(of:))
        }
    }

    /// Crossings that share a boundary but sit far apart on it are separate
    /// runs. A crossing joins a cluster when it is within `together` of any
    /// crossing already in it.
    private static func clusters(of marked: [MarkedCrossing]) -> [[MarkedCrossing]] {
        var built: [[MarkedCrossing]] = []

        for one in marked {
            let joined = built.firstIndex { cluster in
                cluster.contains { held in
                    hypot(
                        held.crossing.point.x - one.crossing.point.x,
                        held.crossing.point.y - one.crossing.point.y
                    ) <= together
                }
            }

            if let joined {
                built[joined].append(one)
            } else {
                built.append([one])
            }
        }

        return built
    }

    /// The curve one cluster draws: across the flows, long enough to reach
    /// past the outermost of them.
    private static func run(of cluster: [MarkedCrossing]) -> BoundaryRun {
        let points = cluster.map(\.crossing.point)
        let centre = CGPoint(
            x: points.map(\.x).reduce(0, +) / CGFloat(points.count),
            y: points.map(\.y).reduce(0, +) / CGFloat(points.count)
        )
        // The mean flow direction, taken as a vector so two nearly opposite
        // angles do not average to a right angle.
        let angles = cluster.map(\.crossing.angle)
        let along = atan2(
            angles.map(sin).reduce(0, +) / CGFloat(angles.count),
            angles.map(cos).reduce(0, +) / CGFloat(angles.count)
        )
        let across = along + .pi / 2

        let reach = points.map { point in
            abs((point.x - centre.x) * cos(across) + (point.y - centre.y) * sin(across))
        }
        let half = max((reach.max() ?? 0) + overhang, length / 2)

        return BoundaryRun(
            zoneId: cluster[0].crossing.zoneId,
            networkZoneId: cluster[0].crossing.networkZoneId,
            guards: cluster[0].guards,
            openCount: cluster.map(\.openCount).reduce(0, +),
            flowCount: cluster.count,
            start: CGPoint(x: centre.x - half * cos(across), y: centre.y - half * sin(across)),
            end: CGPoint(x: centre.x + half * cos(across), y: centre.y + half * sin(across)),
            control: CGPoint(x: centre.x - bow * cos(along), y: centre.y - bow * sin(along))
        )
    }
}
