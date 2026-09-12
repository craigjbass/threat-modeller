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
    /// Flows that still cross a trust boundary they do not pass through. Zero
    /// when the widening cleared them all.
    public let unrelatedCrossings: Int
    /// Flows that still run over a zone rectangle they have nothing to do
    /// with.
    public let flowsOverUnrelatedZones: Int

    public init(
        components: [LaidOutComponent],
        zones: [LaidOutZone],
        unrelatedCrossings: Int = 0,
        flowsOverUnrelatedZones: Int = 0
    ) {
        self.components = components
        self.zones = zones
        self.unrelatedCrossings = unrelatedCrossings
        self.flowsOverUnrelatedZones = flowsOverUnrelatedZones
    }
}

/// How far apart a pass puts things. One pass widens every gap together, so
/// the grid the declaration order describes is the grid the reader sees.
struct LayoutSpacing: Equatable {
    let columnGap: Double
    let rowGap: Double
    let zoneGap: Double

    /// The next pass out.
    func widened(by factor: Double) -> LayoutSpacing {
        LayoutSpacing(
            columnGap: columnGap * factor,
            rowGap: rowGap * factor,
            zoneGap: zoneGap * factor
        )
    }
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
    /// How many passes the widening runs before it gives up. A model that
    /// cannot be separated still returns, and says what survives.
    static let passes = 6

    public init() {}

    /// Places, measures its own picture, and widens until no flow crosses a
    /// trust boundary it does not pass through.
    ///
    /// A flow that crosses an unrelated boundary reads as a statement that the
    /// boundary applies to that flow, and it does not. Widening every gap
    /// together keeps the grid the declaration order describes; moving one
    /// node would make a one-line change to the file move half the diagram.
    public func execute(_ request: LayOutModelRequest) -> LayOutModelResponse {
        var spacing = LayoutSpacing(
            columnGap: Self.columnGap,
            rowGap: Self.rowGap,
            zoneGap: Self.zoneGap
        )
        var best = place(request, spacing: spacing)
        var bestFault = Self.faults(of: best, in: request)

        var pass = 1
        while bestFault.total > 0 && pass < Self.passes {
            spacing = spacing.widened(by: Self.widenBy)
            let wider = place(request, spacing: spacing)
            let fault = Self.faults(of: wider, in: request)
            // A wider pass is kept only when it is no worse, so the loop never
            // hands back a picture worse than one it already had.
            if fault.total <= bestFault.total {
                best = wider
                bestFault = fault
            }
            pass += 1
        }

        return LayOutModelResponse(
            components: best.components,
            zones: best.zones,
            unrelatedCrossings: bestFault.crossings,
            flowsOverUnrelatedZones: bestFault.overZones
        )
    }

    private func place(
        _ request: LayOutModelRequest,
        spacing: LayoutSpacing
    ) -> LayOutModelResponse {
        var components: [LaidOutComponent] = []
        var zones: [LaidOutZone] = []

        // A component declared outside every zone goes in a band across the
        // top. The band is placed last, above the zone each of its components
        // talks to most, so its flows do not run over a zone they have nothing
        // to do with.
        let loose = request.source.components
        let bandHeight = loose.isEmpty ? 0 : Self.nodeHeight + spacing.rowGap * 2
        var y = Self.zonePadding + bandHeight
        var x = Self.zonePadding
        var tallestInRow = 0.0

        for zone in request.source.zones {
            let size = Self.size(ofZoneHolding: zone.components.count, spacing: spacing)

            if x > Self.zonePadding && x + size.width > Self.rowWidth {
                x = Self.zonePadding
                y += tallestInRow + spacing.zoneGap
                tallestInRow = 0
            }

            zones.append(
                LaidOutZone(id: zone.id, x: x, y: y, width: size.width, height: size.height)
            )
            components += Self.place(zone.components, inZoneAt: x, y, spacing: spacing)

            x += size.width + spacing.zoneGap
            tallestInRow = max(tallestInRow, size.height)
        }

        components = Self.placeLoose(
            loose,
            above: zones,
            in: request,
            spacing: spacing,
            y: Self.zonePadding
        ) + components

        return LayOutModelResponse(components: components, zones: zones)
    }

    /// A grid `ceil(sqrt(n))` columns wide, so four components make a square.
    static func columns(for count: Int) -> Int {
        max(1, Int(Double(count).squareRoot().rounded(.up)))
    }

    static func size(
        ofZoneHolding count: Int,
        spacing: LayoutSpacing
    ) -> (width: Double, height: Double) {
        // A zone that holds nothing still gets one cell, so it stays visible
        // and selectable.
        let cells = max(1, count)
        let columns = Self.columns(for: cells)
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
        spacing: LayoutSpacing
    ) -> [LaidOutComponent] {
        let columns = Self.columns(for: max(1, components.count))

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

    /// What is wrong with the picture. A flow must not cross a boundary it
    /// does not pass through, and must not run over a zone it has nothing to
    /// do with: a reader takes either for a statement the model does not make.
    struct LayoutFault: Equatable {
        let crossings: Int
        let overZones: Int

        var total: Int { crossings + overZones }
    }

    static func faults(
        of placed: LayOutModelResponse,
        in request: LayOutModelRequest
    ) -> LayoutFault {
        LayoutFault(
            crossings: unrelatedCrossings(of: placed, in: request),
            overZones: flowsOverUnrelatedZones(of: placed, in: request)
        )
    }

    /// How many flows cross a trust boundary they do not pass through.
    static func unrelatedCrossings(
        of placed: LayOutModelResponse,
        in request: LayOutModelRequest
    ) -> Int {
        let footprints = Self.footprints(of: placed, in: request)
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

        var curves: [String: FlowCurve] = [:]
        var marked: [BoundaryCrossings.MarkedCrossing] = []

        for flow in request.source.flows {
            guard let source = footprints[flow.sourceId],
                  let target = footprints[flow.targetId] else { continue }

            let anchors = AnchorGeometry.nearestPair(from: source, to: target)
            let curve = FlowCurve(
                from: AnchorGeometry.point(anchors.source, of: source),
                to: AnchorGeometry.point(anchors.target, of: target)
            )
            let id = "\(flow.sourceId)->\(flow.targetId)"
            curves[id] = curve

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

        let sampled = curves.mapValues { CurveCrossing.samples(of: $0) }
        var count = 0

        for run in BoundaryCrossings.runs(marked) {
            let curve = CurveCrossing.samples(of: run)
            for (id, flow) in sampled where run.connectionIds.contains(id) == false {
                if CurveCrossing.crosses(curve, flow) { count += 1 }
            }
        }

        return count
    }

    /// Where every component draws, at the shape the caller resolved.
    private static func footprints(
        of placed: LayOutModelResponse,
        in request: LayOutModelRequest
    ) -> [String: Rect] {
        var built: [String: Rect] = [:]

        for component in placed.components {
            let shape = request.shapes[component.id].flatMap(DiagramShape.init(rawValue:)) ?? .process
            built[component.id] = Component.footprintRect(
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
        spacing: LayoutSpacing,
        y: Double
    ) -> [LaidOutComponent] {
        guard loose.isEmpty == false else { return [] }

        let zoneOf = zoneOfEachComponent(in: request)
        var wanted: [(id: String, x: Double, index: Int)] = []

        for (index, component) in loose.enumerated() {
            let zoneId = mostConnectedZone(of: component.id, in: request, zoneOf: zoneOf)
            let above = zones.first { $0.id == zoneId }.map { $0.x + $0.width / 2 - nodeWidth / 2 }
            let inOrder = zonePadding + Double(index) * (nodeWidth + spacing.columnGap)
            wanted.append((component.id, above ?? inOrder, index))
        }

        var placed: [LaidOutComponent] = []
        var nextFree = -Double.greatestFiniteMagnitude

        for entry in wanted.sorted(by: { $0.x == $1.x ? $0.index < $1.index : $0.x < $1.x }) {
            let x = max(entry.x, nextFree)
            placed.append(LaidOutComponent(id: entry.id, x: x, y: y))
            nextFree = x + nodeWidth + spacing.columnGap
        }

        // Declaration order is what the rest of the response is in.
        let byId = Dictionary(uniqueKeysWithValues: placed.map { ($0.id, $0) })
        return loose.compactMap { byId[$0.id] }
    }

    /// The zone this component has most flows with, or nil when it has none.
    /// A tie keeps the zone declared first, so the answer never depends on
    /// dictionary order.
    private static func mostConnectedZone(
        of componentId: String,
        in request: LayOutModelRequest,
        zoneOf: [String: String]
    ) -> String? {
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
            .max { (tally[$0] ?? 0) < (tally[$1] ?? 0) }
    }

    /// How many flows run over a zone rectangle they have nothing to do with.
    ///
    /// A reader takes a flow over a zone for a statement that the flow touches
    /// what the zone holds, and it does not.
    static func flowsOverUnrelatedZones(
        of placed: LayOutModelResponse,
        in request: LayOutModelRequest
    ) -> Int {
        let footprints = footprints(of: placed, in: request)
        let zoneOf = zoneOfEachComponent(in: request)
        var count = 0

        for flow in request.source.flows {
            guard let source = footprints[flow.sourceId],
                  let target = footprints[flow.targetId] else { continue }

            let anchors = AnchorGeometry.nearestPair(from: source, to: target)
            let samples = CurveCrossing.samples(
                of: FlowCurve(
                    from: AnchorGeometry.point(anchors.source, of: source),
                    to: AnchorGeometry.point(anchors.target, of: target)
                ),
                steps: 96
            )

            for zone in placed.zones
            where zone.id != zoneOf[flow.sourceId] && zone.id != zoneOf[flow.targetId] {
                let rect = Rect(x: zone.x, y: zone.y, width: zone.width, height: zone.height)
                if samples.contains(where: { rect.contains($0) }) { count += 1 }
            }
        }

        return count
    }
}
