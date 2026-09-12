import Foundation

/// A zone as the geometry sees it: a rectangle and what kind of zone it is.
public struct BoundaryZone: Equatable, Sendable {
    public let id: String
    public let networkZoneId: String
    public let rect: Rect

    public init(id: String, networkZoneId: String, rect: Rect) {
        self.id = id
        self.networkZoneId = networkZoneId
        self.rect = rect
    }
}

/// One place where a flow crosses a trust boundary.
public struct BoundaryCrossing: Equatable, Sendable {
    /// Where the flow meets the boundary.
    public let point: Point
    /// The flow's tangent there. The mark draws across it, at a right angle.
    public let angle: Double
    /// The zone whose edge the flow crosses. The zone being entered when the
    /// flow enters one, else the zone it leaves.
    public let zoneId: String
    /// That zone's kind: public or private.
    public let networkZoneId: String

    public init(point: Point, angle: Double, zoneId: String, networkZoneId: String) {
        self.point = point
        self.angle = angle
        self.zoneId = zoneId
        self.networkZoneId = networkZoneId
    }
}

/// Finds where a flow crosses a trust boundary, and groups the crossings into
/// the boundaries a reader sees.
///
/// OWASP Threat Dragon draws a trust boundary as a dotted curve across the
/// flows it separates. This application does not model such a curve, because a
/// curve holds no members and scores nothing. It does not need to: a zone
/// already states which components it holds, so the crossing is where the
/// flow's own curve leaves one zone rectangle and enters another.
public enum BoundaryCrossings {
    /// The shortest a boundary curve may be. One flow through it still has to
    /// read as a boundary beside a 104 point node, not as a tick on the line.
    public static let length = 96.0
    /// How far the curve bows.
    public static let bow = 18.0
    /// How far apart two crossings of one boundary may sit and still belong to
    /// the same run. Beyond this the boundary draws twice, because one curve
    /// across the gap would claim canvas it does not cross.
    public static let together = 200.0
    /// The blank the run leaves past the outermost flow it crosses, so the
    /// curve reaches beyond every arrow through it.
    public static let overhang = 34.0
    /// How many points along the flow are tested.
    public static let steps = 200

    /// One crossing with what the flow through it carries.
    public struct MarkedCrossing: Equatable, Sendable {
        /// The flow that crosses there.
        public let connectionId: String
        public let crossing: BoundaryCrossing
        /// What guards the flow there.
        public let guards: [EdgeGuard]
        /// Threats on that flow no control answers.
        public let openCount: Int

        public init(
            connectionId: String,
            crossing: BoundaryCrossing,
            guards: [EdgeGuard],
            openCount: Int
        ) {
            self.connectionId = connectionId
            self.crossing = crossing
            self.guards = guards
            self.openCount = openCount
        }

        /// Two crossings belong to the same boundary when they cross the same
        /// zone and the same set of components guards them.
        public var boundaryKey: String {
            let names = guards.map { "\($0.label)\($0.isAssumed ? "~" : "")" }.joined(separator: "+")
            return "\(crossing.zoneId)|\(names)"
        }
    }

    /// One dotted curve for each boundary: one zone edge, one set of guards,
    /// one run of flows through it.
    public struct BoundaryRun: Equatable, Sendable {
        public let zoneId: String
        public let networkZoneId: String
        public let guards: [EdgeGuard]
        /// Threats no control answers, across every flow through this run.
        public let openCount: Int
        /// The flows that pass through the curve. Every other flow on the
        /// canvas is unrelated to it and must not cross it.
        public let connectionIds: [String]
        public let start: Point
        public let end: Point
        public let control: Point

        public init(
            zoneId: String,
            networkZoneId: String,
            guards: [EdgeGuard],
            openCount: Int,
            connectionIds: [String],
            start: Point,
            end: Point,
            control: Point
        ) {
            self.zoneId = zoneId
            self.networkZoneId = networkZoneId
            self.guards = guards
            self.openCount = openCount
            self.connectionIds = connectionIds
            self.start = start
            self.end = end
            self.control = control
        }

        /// How many flows pass through the curve.
        public var flowCount: Int { connectionIds.count }

        /// The point at `t` on the bow, where 0 is the start and 1 is the end.
        public func point(at t: Double) -> Point {
            let u = 1 - t
            return Point(
                x: u * u * start.x + 2 * u * t * control.x + t * t * end.x,
                y: u * u * start.y + 2 * u * t * control.y + t * t * end.y
            )
        }
    }

    /// Every place the flow crosses a zone edge.
    ///
    /// A flow whose two ends sit in the same zone crosses nothing: a curve that
    /// bulges outside its own zone and back is not a boundary crossing.
    public static func of(
        connectionId: String,
        sourceZoneId: String?,
        targetZoneId: String?,
        curve: FlowCurve,
        zones: [BoundaryZone]
    ) -> [BoundaryCrossing] {
        guard sourceZoneId != targetZoneId else { return [] }

        var found: [BoundaryCrossing] = []
        var held = zone(holding: curve.point(at: 0), in: zones)

        for step in 1...steps {
            let t = Double(step) / Double(steps)
            let point = curve.point(at: t)
            let entered = zone(holding: point, in: zones)
            guard entered?.id != held?.id else { continue }

            let before = curve.point(at: Double(step - 1) / Double(steps))
            found.append(
                BoundaryCrossing(
                    point: Point(x: (before.x + point.x) / 2, y: (before.y + point.y) / 2),
                    angle: atan2(point.y - before.y, point.x - before.x),
                    zoneId: (entered ?? held)?.id ?? "",
                    networkZoneId: (entered ?? held)?.networkZoneId ?? "private"
                )
            )
            held = entered
        }

        return found
    }

    /// The zone a point belongs to, by the rule the assessment uses: the zone's
    /// rectangle with the header band removed, and a later zone wins.
    private static func zone(holding point: Point, in zones: [BoundaryZone]) -> BoundaryZone? {
        zones.last { $0.rect.insetFromTop(by: ZoneContainment.headerHeight).contains(point) }
    }

    /// One dotted curve for each boundary.
    ///
    /// Crossings of one zone that the same components guard, and that sit near
    /// each other, make one run: one curve, long enough that every arrow in
    /// the run passes through it, and one set of chips.
    public static func runs(_ marked: [MarkedCrossing]) -> [BoundaryRun] {
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
        let centre = Point(
            x: points.map(\.x).reduce(0, +) / Double(points.count),
            y: points.map(\.y).reduce(0, +) / Double(points.count)
        )
        // The mean flow direction, taken as a vector so two nearly opposite
        // angles do not average to a right angle.
        let angles = cluster.map(\.crossing.angle)
        let along = atan2(
            angles.map(sin).reduce(0, +) / Double(angles.count),
            angles.map(cos).reduce(0, +) / Double(angles.count)
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
            connectionIds: cluster.map(\.connectionId),
            start: Point(x: centre.x - half * cos(across), y: centre.y - half * sin(across)),
            end: Point(x: centre.x + half * cos(across), y: centre.y + half * sin(across)),
            control: Point(x: centre.x - bow * cos(along), y: centre.y - bow * sin(along))
        )
    }
}
