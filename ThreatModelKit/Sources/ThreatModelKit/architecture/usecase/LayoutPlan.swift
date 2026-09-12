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

    public init(
        spacing: LayoutSpacing,
        rowWidth: Double,
        loose: LoosePlacement = .aboveMostConnected,
        componentOrder: ComponentOrder = .declaration
    ) {
        self.spacing = spacing
        self.rowWidth = rowWidth
        self.loose = loose
        self.componentOrder = componentOrder
    }
}

/// What is wrong with a placed layout, and how big it is. Lowest score wins.
///
/// A fault is twenty times a detour, and a detour is worth about 500 points of
/// diagram, so nothing is ever taken for being bigger alone.
public struct LayoutFitness: Equatable, Sendable {
    /// Flows that cross a trust boundary they do not pass through.
    public let unrelatedCrossings: Int
    /// Flows that run over a zone rectangle they have nothing to do with, after
    /// routing has done what it can.
    public let flowsOverUnrelatedZones: Int
    /// Detours the routing had to take.
    public let waypoints: Int
    public let width: Double
    public let height: Double

    public init(
        unrelatedCrossings: Int,
        flowsOverUnrelatedZones: Int,
        waypoints: Int,
        width: Double,
        height: Double
    ) {
        self.unrelatedCrossings = unrelatedCrossings
        self.flowsOverUnrelatedZones = flowsOverUnrelatedZones
        self.waypoints = waypoints
        self.width = width
        self.height = height
    }

    public var score: Double {
        100 * Double(unrelatedCrossings)
            + 100 * Double(flowsOverUnrelatedZones)
            + 5 * Double(waypoints)
            + (width + height) / 100
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
