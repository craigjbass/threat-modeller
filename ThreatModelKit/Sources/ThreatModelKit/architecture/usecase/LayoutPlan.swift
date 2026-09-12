import Foundation

/// How far apart a pass puts things.
public struct LayoutSpacing: Equatable, Sendable {
    public let columnGap: Double
    public let rowGap: Double
    public let zoneGap: Double

    public init(columnGap: Double, rowGap: Double, zoneGap: Double) {
        self.columnGap = columnGap
        self.rowGap = rowGap
        self.zoneGap = zoneGap
    }

    /// The next pass out. One pass widens every gap together, so the grid the
    /// declaration order describes is the grid the reader sees.
    public func widened(by factor: Double) -> LayoutSpacing {
        LayoutSpacing(
            columnGap: columnGap * factor,
            rowGap: rowGap * factor,
            zoneGap: zoneGap * factor
        )
    }
}

/// Where a component declared outside every zone goes.
public enum LoosePlacement: Equatable, Sendable, CaseIterable {
    /// Above the zone it has most flows with.
    case aboveMostConnected
    /// Above the zone it has the second most flows with, which clears the case
    /// where two components crowd one zone.
    case aboveSecondConnected
    /// At the left of the band, in the order the file declares.
    case inDeclarationOrder
}

/// The grid a zone lays its components out on.
public enum GridShape: Equatable, Sendable, CaseIterable {
    /// `ceil(sqrt(n))` columns, so four components make a square.
    case square
    /// One column, so the zone is tall and narrow.
    case oneColumn
    /// Two columns.
    case twoColumns

    public func columns(for count: Int) -> Int {
        switch self {
        case .square: max(1, Int(Double(count).squareRoot().rounded(.up)))
        case .oneColumn: 1
        case .twoColumns: min(2, max(1, count))
        }
    }
}

/// Which side of the zones the band of loose components sits.
public enum BandSide: Equatable, Sendable, CaseIterable {
    case above
    case below
}

/// The order components sit in inside their zone.
public enum ComponentOrder: Equatable, Sendable, CaseIterable {
    /// The order the file declares.
    case declaration
    /// Sorted by the zone each component talks to, so a component that talks
    /// out of the zone sits near the edge it talks through.
    case byConnectedZone
}

/// Everything a placement reads. The same plan on the same source always gives
/// the same layout.
public struct LayoutPlan: Equatable, Sendable {
    public var spacing: LayoutSpacing
    public var rowWidth: Double
    public var loose: LoosePlacement
    public var componentOrder: ComponentOrder
    public var grid: GridShape
    public var band: BandSide
    /// The blank a zone leaves round its contents.
    public var zonePadding: Double

    public init(
        spacing: LayoutSpacing,
        rowWidth: Double,
        loose: LoosePlacement = .aboveMostConnected,
        componentOrder: ComponentOrder = .declaration,
        grid: GridShape = .square,
        band: BandSide = .above,
        zonePadding: Double = 40
    ) {
        self.spacing = spacing
        self.rowWidth = rowWidth
        self.loose = loose
        self.componentOrder = componentOrder
        self.grid = grid
        self.band = band
        self.zonePadding = zonePadding
    }
}

/// What is wrong with a placed layout, and how big it is. Lowest score wins.
///
/// A fault is twenty times a detour, and a detour is worth about 500 points of
/// diagram, so nothing is ever taken for being bigger alone.
public struct LayoutFitness: Equatable, Sendable {
    /// Breaks the gaps had to cut in a trust boundary to keep a flow that has
    /// nothing to do with it from crossing it. A whole boundary reads best, so
    /// this costs, but far less than a fault: the drawing holds the rule
    /// whatever the layout achieves.
    public let brokenBoundaries: Int
    /// Boundaries drawn over a node. A boundary across a node reads as though
    /// the node is cut in two, and a boundary belongs between things rather
    /// than through one.
    public let boundariesOverNodes: Int
    /// Flows that run over a zone rectangle they have nothing to do with, after
    /// routing has done what it can.
    public let flowsOverUnrelatedZones: Int
    /// Detours the routing had to take.
    public let waypoints: Int
    /// How tightly the flows turn, added up. A wide turn reads as part of a
    /// circle and a reader follows it; a tight one is a corner, and a line
    /// with corners is read as several lines.
    public let tightness: Double
    /// Pairs of flows that cross each other.
    public let flowCrossings: Int
    /// Times a flow runs behind a node that is not one of its own ends.
    public let flowsBehindNodes: Int
    /// Labels that could find nowhere clear: they cover a node, or another
    /// label, or sit inside its blank.
    public let crowdedCallouts: Int
    /// How far the labels reach from the flows they name, added up.
    public let calloutReach: Double
    public let width: Double
    public let height: Double

    public init(
        brokenBoundaries: Int,
        boundariesOverNodes: Int = 0,
        flowsOverUnrelatedZones: Int,
        waypoints: Int,
        tightness: Double = 0,
        flowCrossings: Int = 0,
        flowsBehindNodes: Int = 0,
        crowdedCallouts: Int = 0,
        calloutReach: Double = 0,
        width: Double,
        height: Double
    ) {
        self.brokenBoundaries = brokenBoundaries
        self.boundariesOverNodes = boundariesOverNodes
        self.flowsOverUnrelatedZones = flowsOverUnrelatedZones
        self.waypoints = waypoints
        self.tightness = tightness
        self.flowCrossings = flowCrossings
        self.flowsBehindNodes = flowsBehindNodes
        self.crowdedCallouts = crowdedCallouts
        self.calloutReach = calloutReach
        self.width = width
        self.height = height
    }

    public var score: Double {
        100 * Double(flowsOverUnrelatedZones)
            + 25 * Double(brokenBoundaries)
            + 15 * Double(boundariesOverNodes)
            + 5 * Double(waypoints)
            + 4 * tightness
            + 1 * Double(flowCrossings)
            + 1 * Double(flowsBehindNodes)
            + 8 * Double(crowdedCallouts)
            + calloutReach / 500
            + (width + height) / 50
            + lopsidedness
    }

    /// What a picture far from square costs. A reader scrolls a diagram two
    /// and a half times taller than it is wide, and reads a square one.
    ///
    /// A small picture is exempt: a single node is three times wider than it
    /// is tall and nobody minds.
    private var lopsidedness: Double {
        let longer = max(width, height)
        guard longer > 800 else { return 0 }

        let shorter = max(min(width, height), 1)
        return 20 * max(0, longer / shorter - 1.6)
    }
}

/// One way of changing a plan, and the candidates it offers.
///
/// A technique proposes a short, fixed list. The loop takes the lowest-scoring
/// candidate, keeps it, and moves to the next technique, so the search always
/// finishes and nothing about it is random.
public struct LayoutTechnique: Sendable {
    public let name: String
    public let candidates: @Sendable (LayoutPlan) -> [LayoutPlan]

    public init(name: String, candidates: @escaping @Sendable (LayoutPlan) -> [LayoutPlan]) {
        self.name = name
        self.candidates = candidates
    }
}
