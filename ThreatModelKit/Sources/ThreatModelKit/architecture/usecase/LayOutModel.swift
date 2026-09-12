import Foundation

public protocol LayOutModelUseCase {
    func execute(_ request: LayOutModelRequest) -> LayOutModelResponse
}

public struct LayOutModelRequest: Equatable, Sendable {
    public let source: ArchitectureSource
    /// Component id to resolved shape id. A component the map does not name
    /// draws as a process, the way the derivation treats an unknown
    /// technology. The caller resolves it, because the layout holds no
    /// catalogue and must not gain one.
    public let shapes: [String: String]

    public init(source: ArchitectureSource, shapes: [String: String] = [:]) {
        self.source = source
        self.shapes = shapes
    }
}

public struct LaidOutComponent: Equatable, Sendable {
    public let id: String
    public let x: Double
    public let y: Double

    public init(id: String, x: Double, y: Double) {
        self.id = id
        self.x = x
        self.y = y
    }
}

public struct LaidOutZone: Equatable, Sendable {
    public let id: String
    public let x: Double
    public let y: Double
    public let width: Double
    public let height: Double

    public init(id: String, x: Double, y: Double, width: Double, height: Double) {
        self.id = id
        self.x = x
        self.y = y
        self.width = width
        self.height = height
    }
}

public struct LayOutModelResponse: Equatable, Sendable {
    public let components: [LaidOutComponent]
    public let zones: [LaidOutZone]
    /// What the layout could not clear, how far it had to route round, and how
    /// big the picture is.
    public let fitness: LayoutFitness

    public init(
        components: [LaidOutComponent],
        zones: [LaidOutZone],
        fitness: LayoutFitness = LayoutFitness(
            brokenBoundaries: 0,
            flowsOverUnrelatedZones: 0,
            waypoints: 0,
            width: 0,
            height: 0
        )
    ) {
        self.components = components
        self.zones = zones
        self.fitness = fitness
    }

    /// Breaks the gaps had to cut in a trust boundary.
    public var brokenBoundaries: Int { fitness.brokenBoundaries }
    /// Flows that run over a zone they have nothing to do with.
    public var flowsOverUnrelatedZones: Int { fitness.flowsOverUnrelatedZones }
}

/// Places a diagram from declaration order alone.
///
/// The same source always draws the same picture. There is no force-directed
/// placement and no crossing minimisation: a user who wants a tidier diagram
/// reorders their declarations.
public struct LayOutModel: LayOutModelUseCase {
    /// The size the canvas draws a node at.
    static let nodeWidth = 160.0
    static let nodeHeight = 72.0
    static let columnGap = 60.0
    /// A row leaves room for the tallest footprint, which is the process
    /// circle. That circle passes the 160 by 72 slot by 16 points above and 16
    /// below, so a gap of 48 would leave two circles 16 points apart.
    public static let rowGap = 72.0
    /// A zone pads its contents, and reserves a header band the containment
    /// rule already needs: a component's centre must sit below it.
    static let zonePadding = 40.0
    static let zoneHeader = 40.0
    static let zoneGap = 60.0
    /// A row of zones wraps once it would pass this width.
    ///
    /// A wide, short diagram reads badly: a flow runs the whole width, and its
    /// label crosses everything between its two ends. Wrapping sooner squares
    /// the picture up and keeps a flow short.
    static let rowWidth = 1400.0

    /// How much wider each pass places things.
    static let widenBy = 1.35
    /// How many times the whole list of techniques runs.
    static let rounds = 4
    /// How many passes the widening runs before it gives up. A model that
    /// cannot be separated still returns, and says what survives.
    static let passes = 6

    public init() {}

    /// Places, measures its own picture, and tries one technique after
    /// another until each is exhausted.
    ///
    /// A flow that crosses a boundary it does not pass through, or runs over a
    /// zone it has nothing to do with, reads as a statement the model does not
    /// make. Each technique offers a short list of candidates for one setting;
    /// the lowest-scoring is kept and the loop moves on. It never goes back, so
    /// it always finishes, and nothing about it is random.
    public func execute(_ request: LayOutModelRequest) -> LayOutModelResponse {
        var plan = LayoutPlan(
            spacing: LayoutSpacing(
                columnGap: Self.columnGap,
                rowGap: Self.rowGap,
                zoneGap: Self.zoneGap
            ),
            rowWidth: Self.rowWidth
        )
        var best = placeAndScore(request, plan: plan)

        // The list runs more than once, because one technique's gain can let
        // an earlier one improve again. A round that gains nothing ends the
        // search, and the rounds are capped, so it always finishes.
        for _ in 0 ..< Self.rounds {
            let before = best.fitness.score

            for technique in Self.techniques {
                var chosen = plan
                var chosenScore = best.fitness.score

                for candidate in technique.candidates(plan) {
                    let scored = placeAndScore(request, plan: candidate)
                    guard scored.fitness.score < chosenScore else { continue }
                    chosen = candidate
                    chosenScore = scored.fitness.score
                    best = scored
                }

                plan = chosen
            }

            if best.fitness.score >= before { break }
        }

        return best
    }

    /// The techniques, cheapest first. Widening changes no relationship at
    /// all. The wrap width changes the shape but no order. The band placement
    /// moves what sits outside every zone. The order inside a zone moves
    /// components within one box. Nothing later undoes anything earlier.
    static let techniques: [LayoutTechnique] = [
        LayoutTechnique(name: "widen") { plan in
            (1 ... 5).map { step in
                var wider = plan
                wider.spacing = plan.spacing.widened(by: pow(Self.widenBy, Double(step)))
                return wider
            }
        },
        LayoutTechnique(name: "wrap width") { plan in
            [1000.0, 1400.0, 1900.0, 2600.0]
                .filter { $0 != plan.rowWidth }
                .map { width in
                    var wrapped = plan
                    wrapped.rowWidth = width
                    return wrapped
                }
        },
        LayoutTechnique(name: "loose placement") { plan in
            LoosePlacement.allCases
                .filter { $0 != plan.loose }
                .map { rule in
                    var placed = plan
                    placed.loose = rule
                    return placed
                }
        },
        LayoutTechnique(name: "component order") { plan in
            ComponentOrder.allCases
                .filter { $0 != plan.componentOrder }
                .map { order in
                    var sorted = plan
                    sorted.componentOrder = order
                    return sorted
                }
        },
        LayoutTechnique(name: "zone grid") { plan in
            GridShape.allCases
                .filter { $0 != plan.grid }
                .map { grid in
                    var shaped = plan
                    shaped.grid = grid
                    return shaped
                }
        },
        LayoutTechnique(name: "band side") { plan in
            BandSide.allCases
                .filter { $0 != plan.band }
                .map { side in
                    var moved = plan
                    moved.band = side
                    return moved
                }
        },
        LayoutTechnique(name: "zone padding") { plan in
            [40.0, 70.0, 110.0]
                .filter { $0 != plan.zonePadding }
                .map { padding in
                    var padded = plan
                    padded.zonePadding = padding
                    return padded
                }
        }
    ]

    private func placeAndScore(
        _ request: LayOutModelRequest,
        plan: LayoutPlan
    ) -> LayOutModelResponse {
        let placed = place(request, plan: plan)
        return LayOutModelResponse(
            components: placed.components,
            zones: placed.zones,
            fitness: Self.fitness(of: placed, in: request)
        )
    }

    private func place(
        _ request: LayOutModelRequest,
        plan: LayoutPlan
    ) -> LayOutModelResponse {
        let spacing = plan.spacing
        var components: [LaidOutComponent] = []
        var zones: [LaidOutZone] = []

        // A component declared outside every zone goes in a band across the
        // top. The band is placed last, above the zone each of its components
        // talks to most, so its flows do not run over a zone they have nothing
        // to do with.
        let loose = request.source.components
        let bandHeight = loose.isEmpty ? 0 : Self.nodeHeight + spacing.rowGap * 2
        var y = plan.band == .above ? plan.zonePadding + bandHeight : plan.zonePadding
        var x = plan.zonePadding
        var lowest = y
        var tallestInRow = 0.0

        for zone in request.source.zones {
            var size = Self.size(
                ofZoneHolding: zone.components.count,
                spacing: spacing,
                grid: plan.grid,
                zonePadding: plan.zonePadding
            )
            // A zone states its name in a band across its top, so it is at
            // least as wide as the name. A zone holding one component is
            // narrower than a name of forty characters, and the name ran out
            // of the box.
            size.width = max(size.width, Self.width(ofName: zone.name ?? zone.id))

            if x > plan.zonePadding && x + size.width > plan.rowWidth {
                x = plan.zonePadding
                y += tallestInRow + spacing.zoneGap
                tallestInRow = 0
            }

            zones.append(
                LaidOutZone(id: zone.id, x: x, y: y, width: size.width, height: size.height)
            )
            components += Self.place(
                Self.ordered(zone.components, by: plan.componentOrder, in: request),
                inZoneAt: x,
                y,
                spacing: spacing,
                grid: plan.grid,
                zonePadding: plan.zonePadding
            )

            x += size.width + spacing.zoneGap
            tallestInRow = max(tallestInRow, size.height)
            lowest = max(lowest, y + size.height)
        }

        components = Self.placeLoose(
            loose,
            above: zones,
            in: request,
            plan: plan,
            // With no zone to sit below, above and below are the same place.
            y: plan.band == .above || zones.isEmpty
                ? plan.zonePadding
                : lowest + spacing.rowGap
        ) + components

        return LayOutModelResponse(components: components, zones: zones)
    }

    /// About how wide a character is in the band a zone states its name in.
    static let nameCharacterWidth = 7.4

    /// How wide a zone has to be to state this name.
    public static func width(ofName name: String) -> Double {
        Double(name.count) * nameCharacterWidth + 40
    }

    /// A grid `ceil(sqrt(n))` columns wide, so four components make a square.
    static func columns(for count: Int, grid: GridShape = .square) -> Int {
        grid.columns(for: count)
    }

    static func size(
        ofZoneHolding count: Int,
        spacing: LayoutSpacing,
        grid: GridShape = .square,
        zonePadding: Double = LayOutModel.zonePadding
    ) -> (width: Double, height: Double) {
        // A zone that holds nothing still gets one cell, so it stays visible
        // and selectable.
        let cells = max(1, count)
        let columns = Self.columns(for: cells, grid: grid)
        let rows = Int((Double(cells) / Double(columns)).rounded(.up))

        return (
            width: Double(columns) * nodeWidth
                + Double(columns - 1) * spacing.columnGap
                + zonePadding * 2,
            height: zoneHeader
                + Double(rows) * nodeHeight
                + Double(rows - 1) * spacing.rowGap
                + zonePadding * 2
        )
    }

    private static func place(
        _ components: [SourceComponent],
        inZoneAt zoneX: Double,
        _ zoneY: Double,
        spacing: LayoutSpacing,
        grid: GridShape,
        zonePadding: Double
    ) -> [LaidOutComponent] {
        let columns = Self.columns(for: max(1, components.count), grid: grid)

        return components.enumerated().map { index, component in
            let column = index % columns
            let row = index / columns
            return LaidOutComponent(
                id: component.id,
                x: zoneX + zonePadding + Double(column) * (nodeWidth + spacing.columnGap),
                y: zoneY + zoneHeader + zonePadding + Double(row) * (nodeHeight + spacing.rowGap)
            )
        }
    }

    // MARK: measuring the picture it drew

    /// What is wrong with the picture, how far it had to route round, and how
    /// big it is. A flow must not cross a boundary it does not pass through,
    /// and must not run over a zone it has nothing to do with: a reader takes
    /// either for a statement the model does not make.
    static func fitness(
        of placed: LayOutModelResponse,
        in request: LayOutModelRequest
    ) -> LayoutFitness {
        let routed = curves(of: placed, in: request)
        var width = 0.0
        var height = 0.0

        for component in placed.components {
            width = max(width, component.x + nodeWidth)
            height = max(height, component.y + nodeHeight)
        }
        for zone in placed.zones {
            width = max(width, zone.x + zone.width)
            height = max(height, zone.y + zone.height)
        }

        let shape = readability(of: placed, in: request, curves: routed)
        let labels = callouts(of: placed, in: request, curves: routed)

        return LayoutFitness(
            brokenBoundaries: brokenBoundaries(of: placed, in: request, curves: routed),
            boundariesOverNodes: boundariesOverNodes(of: placed, in: request, curves: routed),
            flowsOverUnrelatedZones: flowsOverUnrelatedZones(of: placed, in: request, curves: routed),
            waypoints: routed.values.map(\.waypointCount).reduce(0, +),
            tightness: shape.tightness,
            flowCrossings: shape.crossings,
            flowsSharingAPath: shape.shared,
            flowsBehindNodes: shape.behindNodes,
            crowdedCallouts: labels.crowded,
            calloutReach: labels.reach,
            width: width,
            height: height
        )
    }

    /// How easy the flows are to follow: how far they turn past comfortable,
    /// how many pairs cross, and how often one runs behind a node.
    ///
    /// Two flows that share an end are not counted as crossing: they meet at a
    /// node, which a reader reads as one picture rather than two lines.
    static func readability(
        of placed: LayOutModelResponse,
        in request: LayOutModelRequest,
        curves: [String: FlowCurve]
    ) -> (tightness: Double, crossings: Int, shared: Int, behindNodes: Int) {
        let footprints = footprints(of: placed, in: request)
        var tightness = 0.0
        var behindNodes = 0

        for flow in request.source.flows {
            guard let curve = curves["\(flow.sourceId)->\(flow.targetId)"] else { continue }
            tightness += FlowShape.tightness(of: curve)
            behindNodes += FlowShape.timesBehind(
                curve,
                footprints
                    .filter { $0.key != flow.sourceId && $0.key != flow.targetId }
                    .map(\.value)
            )
        }

        var crossings = 0
        var shared = 0
        let flows = request.source.flows

        for first in flows.indices {
            for second in (first + 1) ..< flows.count {
                let one = flows[first]
                let other = flows[second]
                guard one.sourceId != other.sourceId,
                      one.sourceId != other.targetId,
                      one.targetId != other.sourceId,
                      one.targetId != other.targetId else { continue }
                guard let oneCurve = curves["\(one.sourceId)->\(one.targetId)"],
                      let otherCurve = curves["\(other.sourceId)->\(other.targetId)"]
                else { continue }

                if FlowShape.crosses(oneCurve, otherCurve) { crossings += 1 }
                if FlowShape.shareAPath(oneCurve, otherCurve) { shared += 1 }
            }
        }

        return (tightness, crossings, shared, behindNodes)
    }

    /// Where every label goes, and how well it went.
    ///
    /// A label with nowhere clear covers a node or another label. The layout
    /// spreads to make room, because a diagram whose labels cover it says less
    /// than one that leaves space for them.
    static func callouts(
        of placed: LayOutModelResponse,
        in request: LayOutModelRequest,
        curves: [String: FlowCurve]
    ) -> (crowded: Int, reach: Double) {
        let nodes = Array(footprints(of: placed, in: request).values)
        // A zone states its name in a band across its top. A label over that
        // band hides which zone a reader is looking at.
        let headers = placed.zones.map {
            Rect(x: $0.x, y: $0.y, width: $0.width, height: ZoneContainment.headerHeight)
        }
        let flows = curves.values.map { CurveCrossing.samples(of: $0) }
        let chips = boundaryChips(of: placed, in: request, curves: curves, headers: headers)

        let labels = request.source.flows.compactMap {
            flow -> (connectionId: String, text: String, curve: FlowCurve)? in
            let id = "\(flow.sourceId)->\(flow.targetId)"
            guard let curve = curves[id] else { return nil }
            let text = flow.description ?? flow.kind
            return (id, text, curve)
        }

        let put = CalloutPlacement.place(
            labels,
            nodes: nodes,
            zoneHeaders: headers,
            boundaryChips: chips,
            flows: flows
        )
        var crowded = 0
        var reach = 0.0

        for (index, callout) in put.enumerated() {
            let centre = Point(
                x: callout.rect.minX + callout.rect.size.width / 2,
                y: callout.rect.minY + callout.rect.size.height / 2
            )
            reach += hypot(centre.x - callout.anchor.x, centre.y - callout.anchor.y)

            if (nodes + headers + chips).contains(where: { CalloutPlacement.overlap(callout.rect, $0) }) {
                crowded += 1
                continue
            }
            if put.prefix(index).contains(where: { CalloutPlacement.crowds(callout.rect, $0.rect) }) {
                crowded += 1
            }
        }

        return (crowded, reach)
    }

    /// Where the chips naming each boundary's guards sit.
    ///
    /// The layout reads the guards from the source, so the names are the
    /// component ids rather than what the catalogue calls them. The width is
    /// close enough to keep a label off them, which is what this is for.
    static func boundaryChips(
        of placed: LayOutModelResponse,
        in request: LayOutModelRequest,
        curves: [String: FlowCurve],
        headers: [Rect]
    ) -> [Rect] {
        let zones = placed.zones.map {
            BoundaryZone(
                id: $0.id,
                networkZoneId: "private",
                rect: Rect(x: $0.x, y: $0.y, width: $0.width, height: $0.height)
            )
        }
        let zoneOf = zoneOfEachComponent(in: request)
        var marked: [BoundaryCrossings.MarkedCrossing] = []

        for flow in request.source.flows {
            let id = "\(flow.sourceId)->\(flow.targetId)"
            guard let curve = curves[id] else { continue }

            marked += BoundaryCrossings.of(
                connectionId: id,
                sourceZoneId: zoneOf[flow.sourceId],
                targetZoneId: zoneOf[flow.targetId],
                curve: curve,
                zones: zones
            ).map {
                BoundaryCrossings.MarkedCrossing(
                    connectionId: id,
                    crossing: $0,
                    guards: guards(of: flow, in: request.source),
                    openCount: 0
                )
            }
        }

        return BoundaryCrossings.runs(marked).flatMap { run in
            BoundaryChips.rects(
                of: run,
                texts: run.guards.prefix(2).map(\.label),
                zoneHeaders: headers
            )
        }
    }

    /// Every flow's curve, routed round the zones it has nothing to do with,
    /// keyed by flow. The canvas builds the same curves from the same rule, so
    /// the picture the layout measured is the picture a reader sees.
    static func curves(
        of placed: LayOutModelResponse,
        in request: LayOutModelRequest
    ) -> [String: FlowCurve] {
        let footprints = footprints(of: placed, in: request)
        let zoneOf = zoneOfEachComponent(in: request)
        var built: [String: FlowCurve] = [:]

        for flow in request.source.flows {
            guard let source = footprints[flow.sourceId],
                  let target = footprints[flow.targetId] else { continue }

            let avoid = placed.zones
                .filter { $0.id != zoneOf[flow.sourceId] && $0.id != zoneOf[flow.targetId] }
                .map { Rect(x: $0.x, y: $0.y, width: $0.width, height: $0.height) }
            let anchors = AnchorGeometry.nearestPair(from: source, to: target, avoiding: avoid)
            let start = AnchorGeometry.point(anchors.source, of: source)
            let end = AnchorGeometry.point(anchors.target, of: target)

            built["\(flow.sourceId)->\(flow.targetId)"] = FlowCurve(
                from: start,
                through: FlowRouting.waypoints(from: start, to: end, avoiding: avoid),
                to: end
            )
        }

        return built
    }

    /// How many flows cross a trust boundary they do not pass through.
    /// Every boundary this picture draws.
    static func boundaries(
        of placed: LayOutModelResponse,
        in request: LayOutModelRequest,
        curves: [String: FlowCurve]
    ) -> [BoundaryCrossings.BoundaryRun] {
        let zones = placed.zones.map {
            BoundaryZone(
                id: $0.id,
                // The layout knows nothing of a zone's kind, and the count does
                // not depend on it.
                networkZoneId: "private",
                rect: Rect(x: $0.x, y: $0.y, width: $0.width, height: $0.height)
            )
        }
        let zoneOf = Self.zoneOfEachComponent(in: request)

        var marked: [BoundaryCrossings.MarkedCrossing] = []

        for flow in request.source.flows {
            let id = "\(flow.sourceId)->\(flow.targetId)"
            guard let curve = curves[id] else { continue }

            marked += BoundaryCrossings.of(
                connectionId: id,
                sourceZoneId: zoneOf[flow.sourceId],
                targetZoneId: zoneOf[flow.targetId],
                curve: curve,
                zones: zones
            ).map {
                BoundaryCrossings.MarkedCrossing(
                    connectionId: id,
                    crossing: $0,
                    guards: Self.guards(of: flow, in: request.source),
                    openCount: 0
                )
            }
        }

        return BoundaryCrossings.runs(marked)
    }

    /// How badly the gaps break the boundaries this picture draws.
    static func brokenBoundaries(
        of placed: LayOutModelResponse,
        in request: LayOutModelRequest,
        curves: [String: FlowCurve]
    ) -> Int {
        let sampled = curves.mapValues { CurveCrossing.samples(of: $0) }

        return boundaries(of: placed, in: request, curves: curves).reduce(0) { total, run in
            total + BoundaryCrossings.breaks(
                of: run,
                avoiding: sampled
                    .filter { run.connectionIds.contains($0.key) == false }
                    .map(\.value)
            )
        }
    }

    /// How many boundaries are drawn over a node.
    ///
    /// A boundary across a node reads as though the node is cut in two, and
    /// the boundary belongs between things rather than through one.
    static func boundariesOverNodes(
        of placed: LayOutModelResponse,
        in request: LayOutModelRequest,
        curves: [String: FlowCurve]
    ) -> Int {
        let nodes = Array(footprints(of: placed, in: request).values)
        guard nodes.isEmpty == false else { return 0 }

        return boundaries(of: placed, in: request, curves: curves).reduce(0) { total, run in
            let points = CurveCrossing.samples(of: run)
            return total + nodes.count { node in points.contains { node.contains($0) } }
        }
    }

    /// Everything every component draws, at the shape the caller resolved:
    /// the shape and the chips beneath it. This is what must stay clear.
    private static func footprints(
        of placed: LayOutModelResponse,
        in request: LayOutModelRequest
    ) -> [String: Rect] {
        var built: [String: Rect] = [:]

        for component in placed.components {
            let shape = request.shapes[component.id].flatMap(DiagramShape.init(rawValue:)) ?? .process
            built[component.id] = Component.drawnRect(
                at: Point(x: component.x, y: component.y),
                shape: shape
            )
        }

        return built
    }

    /// Which zone each component is declared in. The layout places a zone's
    /// components inside it, so the declaration is the answer.
    private static func zoneOfEachComponent(in request: LayOutModelRequest) -> [String: String] {
        var built: [String: String] = [:]

        for zone in request.source.zones {
            for component in zone.components { built[component.id] = zone.id }
        }

        return built
    }

    /// What the layout groups a boundary by.
    ///
    /// No assessment exists when the layout runs, so it reads the `mitigates`
    /// edges of the source: whatever guards the component a flow arrives at
    /// guards the crossing. It is an approximation of what the canvas groups
    /// by, and it errs towards more runs, which is the safe direction for a
    /// layout whose job is to leave room.
    private static func guards(
        of flow: SourceFlow,
        in source: ArchitectureSource
    ) -> [EdgeGuard] {
        source.mitigates
            .filter { $0.targetId == flow.targetId }
            .map { EdgeGuard(label: $0.sourceId, isAssumed: $0.status == "assumed") }
            .sorted { $0.label < $1.label }
    }

    // MARK: the band across the top

    /// Places every component declared outside a zone above the zone it talks
    /// to most, so its flows do not run over a zone they have nothing to do
    /// with. A component that talks to no zone keeps the place declaration
    /// order gives it.
    ///
    /// Two components wanting the same place are pushed right in turn, so none
    /// overlaps and the same source always draws the same picture.
    static func placeLoose(
        _ loose: [SourceComponent],
        above zones: [LaidOutZone],
        in request: LayOutModelRequest,
        plan: LayoutPlan,
        y: Double
    ) -> [LaidOutComponent] {
        guard loose.isEmpty == false else { return [] }

        let zoneOf = zoneOfEachComponent(in: request)
        var wanted: [(id: String, x: Double, index: Int)] = []

        for (index, component) in loose.enumerated() {
            let inOrder = plan.zonePadding + Double(index) * (nodeWidth + plan.spacing.columnGap)
            let ranked = connectedZones(of: component.id, in: request, zoneOf: zoneOf)
            let zoneId: String?

            switch plan.loose {
            case .aboveMostConnected: zoneId = ranked.first
            case .aboveSecondConnected: zoneId = ranked.count > 1 ? ranked[1] : ranked.first
            case .inDeclarationOrder: zoneId = nil
            }

            let above = zones.first { $0.id == zoneId }.map { $0.x + $0.width / 2 - nodeWidth / 2 }
            wanted.append((component.id, above ?? inOrder, index))
        }

        var placed: [LaidOutComponent] = []
        var nextFree = -Double.greatestFiniteMagnitude

        for entry in wanted.sorted(by: { $0.x == $1.x ? $0.index < $1.index : $0.x < $1.x }) {
            let x = max(entry.x, nextFree)
            placed.append(LaidOutComponent(id: entry.id, x: x, y: y))
            nextFree = x + nodeWidth + plan.spacing.columnGap
        }

        // Declaration order is what the rest of the response is in.
        let byId = Dictionary(uniqueKeysWithValues: placed.map { ($0.id, $0) })
        return loose.compactMap { byId[$0.id] }
    }

    /// The zones this component has flows with, most first. A tie keeps the
    /// zone declared first, so the answer never depends on dictionary order.
    private static func connectedZones(
        of componentId: String,
        in request: LayOutModelRequest,
        zoneOf: [String: String]
    ) -> [String] {
        var tally: [String: Int] = [:]

        for flow in request.source.flows {
            let other: String?
            if flow.sourceId == componentId {
                other = flow.targetId
            } else if flow.targetId == componentId {
                other = flow.sourceId
            } else {
                continue
            }

            guard let other, let zoneId = zoneOf[other] else { continue }
            tally[zoneId, default: 0] += 1
        }

        return request.source.zones
            .map(\.id)
            .filter { tally[$0] != nil }
            .enumerated()
            .sorted { first, second in
                let one = tally[first.element] ?? 0
                let other = tally[second.element] ?? 0
                return one == other ? first.offset < second.offset : one > other
            }
            .map(\.element)
    }

    /// The order components sit in inside their zone.
    ///
    /// `byConnectedZone` puts a component that talks out of the zone beside
    /// one that talks to the same place, which shortens the flows between two
    /// zones. A tie keeps declaration order.
    static func ordered(
        _ components: [SourceComponent],
        by order: ComponentOrder,
        in request: LayOutModelRequest
    ) -> [SourceComponent] {
        guard order == .byConnectedZone else { return components }

        let zoneOf = zoneOfEachComponent(in: request)
        let rank = Dictionary(
            uniqueKeysWithValues: request.source.zones.enumerated().map { ($0.element.id, $0.offset) }
        )

        return components
            .enumerated()
            .sorted { first, second in
                let one = connectedZones(of: first.element.id, in: request, zoneOf: zoneOf)
                    .first.flatMap { rank[$0] } ?? Int.max
                let other = connectedZones(of: second.element.id, in: request, zoneOf: zoneOf)
                    .first.flatMap { rank[$0] } ?? Int.max
                return one == other ? first.offset < second.offset : one < other
            }
            .map(\.element)
    }

    /// How many flows run over a zone rectangle they have nothing to do with.
    ///
    /// A reader takes a flow over a zone for a statement that the flow touches
    /// what the zone holds, and it does not.
    static func flowsOverUnrelatedZones(
        of placed: LayOutModelResponse,
        in request: LayOutModelRequest,
        curves: [String: FlowCurve]
    ) -> Int {
        let zoneOf = zoneOfEachComponent(in: request)
        var count = 0

        for flow in request.source.flows {
            guard let curve = curves["\(flow.sourceId)->\(flow.targetId)"] else { continue }
            let samples = CurveCrossing.samples(of: curve, steps: 96)

            for zone in placed.zones
            where zone.id != zoneOf[flow.sourceId] && zone.id != zoneOf[flow.targetId] {
                let rect = Rect(x: zone.x, y: zone.y, width: zone.width, height: zone.height)
                if samples.contains(where: { rect.contains($0) }) { count += 1 }
            }
        }

        return count
    }
}
