import Foundation

/// A label that has left its flow and sits in free canvas, joined to it by a
/// leader.
///
/// A flow's description is prose, and prose on a line is either cut or covers
/// the diagram. A callout carries the whole of it, and the empty parts of a
/// diagram are where it goes.
public struct Callout: Equatable, Sendable {
    /// The flow this label belongs to.
    public let connectionId: String
    /// The whole text. Nothing here is cut.
    public let text: String
    /// Where the box sits.
    public let rect: Rect
    /// The point on the flow the leader reaches.
    public let anchor: Point

    public init(connectionId: String, text: String, rect: Rect, anchor: Point) {
        self.connectionId = connectionId
        self.text = text
        self.rect = rect
        self.anchor = anchor
    }
}

/// Puts every callout somewhere the diagram is empty.
///
/// The core places them because the generated layout scores what it drew, and
/// the canvas draws what the layout scored. Both call this, so neither can
/// disagree, and nothing is stored.
public enum CalloutPlacement {
    /// Every callout is the same width, because a column of boxes of one width
    /// reads as a set and a ragged one reads as clutter.
    public static let width = 190.0
    /// About how many characters fit on a line at that width.
    public static let charactersPerLine = 30
    public static let lineHeight = 14.0
    public static let padding = 10.0
    /// How far a box may sit from the flow it labels.
    public static let reaches = [90.0, 150.0, 230.0, 320.0]
    /// How many ways out from the flow are tried, round the clock.
    public static let directions = 16
    /// Where along a flow the leader may touch it. The ends are left out: a
    /// dot on a node's edge says nothing about which flow it means.
    public static let anchors = [0.35, 0.42, 0.5, 0.58, 0.65]
    /// How far from every other flow the leader should touch down.
    public static let clearOfOtherFlows = 18.0
    /// The blank two boxes keep between them. Boxes that merely miss each
    /// other read as one block of text.
    public static let breathingRoom = 30.0

    /// What a box of this text measures.
    public static func size(of text: String) -> Size {
        let lines = max(1, Int((Double(text.count) / Double(charactersPerLine)).rounded(.up)))
        return Size(width: width, height: Double(lines) * lineHeight + padding)
    }

    /// A place for every flow that has something to say.
    ///
    /// Flows are placed in the order given, and each one avoids the nodes, the
    /// boxes already placed, and the flows themselves. The order is fixed, so
    /// the same diagram places the same way every time.
    public static func place(
        _ labels: [(connectionId: String, text: String, curve: FlowCurve)],
        nodes: [Rect],
        zoneHeaders: [Rect] = [],
        boundaryChips: [Rect] = [],
        flows: [[Point]],
        flowsById: [String: [Point]] = [:]
    ) -> [Callout] {
        var placed: [Callout] = []

        for label in labels where label.text.isEmpty == false {
            let others = flowsById.isEmpty
                ? flows
                : flowsById.filter { $0.key != label.connectionId }.map(\.value)
            let anchor = anchor(on: label.curve, clearOf: others)
            let box = size(of: label.text)
            let rect = bestRect(
                for: box,
                from: anchor,
                nodes: nodes + zoneHeaders,
                chips: boundaryChips,
                flows: flows,
                taken: placed
            )
            placed.append(
                Callout(
                    connectionId: label.connectionId,
                    text: label.text,
                    rect: rect,
                    anchor: anchor
                )
            )
        }

        return placed
    }

    /// Where the leader touches the flow.
    ///
    /// The middle of a flow is often where several of them run together, and a
    /// dot there says nothing about which one the label is for. The leader
    /// touches down where the flow is furthest from every other.
    static func anchor(on curve: FlowCurve, clearOf others: [[Point]]) -> Point {
        guard others.isEmpty == false else { return curve.point(at: 0.5) }

        var best = curve.point(at: 0.5)
        var clearest = -Double.greatestFiniteMagnitude

        for t in anchors {
            let point = curve.point(at: t)
            let room = others
                .map { nearest(point, to: $0) }
                .min() ?? Double.greatestFiniteMagnitude

            if room > clearest {
                clearest = room
                best = point
            }
            // Far enough from everything else; no need to look further.
            if room >= clearOfOtherFlows { return point }
        }

        return best
    }

    /// The shortest distance from the point to the polyline.
    public static func nearest(_ point: Point, to polyline: [Point]) -> Double {
        guard polyline.count > 1 else { return .greatestFiniteMagnitude }

        var shortest = Double.greatestFiniteMagnitude
        for index in 0 ..< polyline.count - 1 {
            shortest = min(shortest, distance(from: point, to: polyline[index], polyline[index + 1]))
        }
        return shortest
    }

    private static func distance(from point: Point, to start: Point, _ end: Point) -> Double {
        let dx = end.x - start.x
        let dy = end.y - start.y
        let lengthSquared = dx * dx + dy * dy
        guard lengthSquared > 0 else { return hypot(point.x - start.x, point.y - start.y) }

        let along = min(1, max(0, ((point.x - start.x) * dx + (point.y - start.y) * dy) / lengthSquared))
        return hypot(point.x - (start.x + along * dx), point.y - (start.y + along * dy))
    }

    /// What a box covering something costs. A node or a zone's own name hidden
    /// under a label is the worst of it; a box on top of another box is nearly as bad; a box over a
    /// flow only makes the flow harder to follow.
    static let costOfANode = 1000.0
    static let costOfABox = 800.0
    /// What a box sitting inside another's blank costs. Well under an overlap,
    /// so a crowded diagram still places every label, and well over the reach,
    /// so a box moves out rather than crowding.
    static let costOfCrowding = 220.0
    static let costOfAFlow = 40.0

    private static func bestRect(
        for box: Size,
        from anchor: Point,
        nodes: [Rect],
        chips: [Rect],
        flows: [[Point]],
        taken: [Callout]
    ) -> Rect {
        var best = Rect(origin: anchor, size: box)
        var lowest = Double.greatestFiniteMagnitude

        for reach in reaches {
            for step in 0 ..< directions {
                let angle = 2 * Double.pi * Double(step) / Double(directions)
                let centre = Point(
                    x: anchor.x + reach * cos(angle),
                    y: anchor.y + reach * sin(angle)
                )
                let rect = Rect(
                    x: centre.x - box.width / 2,
                    y: centre.y - box.height / 2,
                    width: box.width,
                    height: box.height
                )
                let cost = cost(
                    of: rect,
                    from: anchor,
                    nodes: nodes,
                    chips: chips,
                    flows: flows,
                    taken: taken
                )

                if cost < lowest {
                    lowest = cost
                    best = rect
                }
            }
        }

        return best
    }

    private static func cost(
        of rect: Rect,
        from anchor: Point,
        nodes: [Rect],
        chips: [Rect],
        flows: [[Point]],
        taken: [Callout]
    ) -> Double {
        var total = 0.0

        total += costOfANode * Double(nodes.count { overlap(rect, $0) })
        // A chip naming what guards a boundary is a label like any other, and
        // two labels touching read as one.
        total += costOfABox * Double(chips.count { overlap(rect, $0) })
        total += costOfCrowding
            * Double(chips.count { overlap(rect, $0) == false && crowds(rect, $0) })
        total += costOfABox * Double(taken.count { overlap(rect, $0.rect) })
        total += costOfCrowding
            * Double(taken.count { overlap(rect, $0.rect) == false && crowds(rect, $0.rect) })
        total += costOfAFlow * Double(flows.count { flow in flow.contains { rect.contains($0) } })
        // The nearer the flow, the easier the leader is to follow.
        total += hypot(rect.minX + rect.size.width / 2 - anchor.x,
                       rect.minY + rect.size.height / 2 - anchor.y) / 10

        return total
    }

    /// True when the two sit closer than the blank they should keep.
    public static func crowds(_ one: Rect, _ other: Rect) -> Bool {
        overlap(
            Rect(
                x: one.minX - breathingRoom,
                y: one.minY - breathingRoom,
                width: one.size.width + breathingRoom * 2,
                height: one.size.height + breathingRoom * 2
            ),
            other
        )
    }

    public static func overlap(_ one: Rect, _ other: Rect) -> Bool {
        one.minX < other.maxX && other.minX < one.maxX
            && one.minY < other.maxY && other.minY < one.maxY
    }
}
