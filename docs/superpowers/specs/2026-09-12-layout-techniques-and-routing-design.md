# A layout that tries one technique after another: design

Date: 2026-09-12. Status: approved in conversation, ready for an implementation
plan.

Scope: the generated layout gains a fitness function, an ordered list of
techniques it applies until each is exhausted, and flow routing that takes a
flow round a zone it has nothing to do with.

## 1. What this fixes

The layout has one lever, uniform widening, and one crude test. Two faults
survive on the ClearanceKit model and no amount of widening removes either,
because both are flows between two zones that are not neighbours.

| # | Fault | Evidence |
| --- | --- | --- |
| 1 | A wider picture that fixes nothing is accepted | the loop takes a pass when `fault.total <= bestFault.total`, so ClearanceKit grew to 1323 by 1552 while the count only fell from 24 to 13 |
| 2 | Widening is the only lever | the wrap width, the band placement and the order inside a zone are all fixed |
| 3 | A flow cannot go round anything | a flow between two zones in different rows runs over whatever sits between them |

## 2. The decisions this design fixes

1. **One fitness function scores a placed layout.** Faults dominate, a detour
   costs a little, and size breaks ties, so nothing is ever accepted for being
   bigger alone.

2. **Techniques run in a fixed order, cheapest first.** Each proposes a short
   list of candidates for one setting. The best is kept and the loop moves on.
   It never goes back, so it always terminates.

3. **Zones stay in declaration order.** Ordering them by what they talk to
   would mean a one-line change to a file moves a zone across the diagram. The
   reader controls the order by writing it.

4. **Routing is derived, never stored.** A flow that would run over a zone it
   has nothing to do with goes round it. The core owns the rule, and the canvas
   and the layout both call it, so neither can disagree and no file format
   changes.

5. **A routed flow is still one curve.** `FlowCurve` becomes a chain of cubic
   segments with the same `point(at:)`, so the crossing detection, the
   sampling, the arrowhead, the click test and the canvas all keep working.

## 3. The fitness

```swift
public struct LayoutFitness: Equatable, Sendable {
    public let unrelatedCrossings: Int
    public let flowsOverUnrelatedZones: Int
    public let waypoints: Int
    public let width: Double
    public let height: Double

    /// Lowest wins.
    public var score: Double {
        100 * Double(unrelatedCrossings)
            + 100 * Double(flowsOverUnrelatedZones)
            + 5 * Double(waypoints)
            + (width + height) / 100
    }
}
```

Every count is taken **after** routing, so `flowsOverUnrelatedZones` is what
routing could not clear rather than what the straight curve would have hit.

The weights say what the design believes: a fault is twenty times a detour, and
a detour is worth about 500 points of diagram.

## 4. The plan a layout is placed from

```swift
public struct LayoutPlan: Equatable, Sendable {
    var spacing: LayoutSpacing
    var rowWidth: Double
    var loose: LoosePlacement
    var componentOrder: ComponentOrder
}

enum LoosePlacement { case aboveMostConnected, aboveSecondConnected, inDeclarationOrder }
enum ComponentOrder { case declaration, byConnectedZone }
```

`place(_:plan:)` builds a layout from a plan and nothing else. The same plan on
the same source always gives the same layout.

## 5. The techniques

Each technique offers candidates for one field of the plan. The loop takes the
lowest-scoring candidate, keeps it, and moves to the next technique. A
technique that improves nothing leaves the plan alone.

| # | Technique | Candidates |
| --- | --- | --- |
| 1 | Widen | the starting gaps, then × 1.35 five times |
| 2 | Wrap width | 1000, 1400, 1900, 2600 |
| 3 | Loose placement | above the most connected zone, above the second, in declaration order |
| 4 | Component order in a zone | declaration order, or sorted by the zone each component talks to |

That is 6 + 4 + 3 + 2 = 15 placements at most, each measured once. There is no
randomness and no restart.

**Why this order.** Widening changes no relationship at all. The wrap width
changes the shape but not any order. The band placement moves components that
sit outside every zone. The order inside a zone moves components within one
box. Nothing later undoes anything earlier.

**Why zone order is not here.** Section 2, decision 3.

## 6. Routing

```swift
public enum FlowRouting {
    /// How far outside a zone a detour passes.
    public static let clearance = 24.0
    /// How many detours one flow may take.
    public static let mostWaypoints = 2

    public static func waypoints(
        from start: Point,
        to end: Point,
        avoiding zones: [Rect]
    ) -> [Point]
}
```

The rule:

1. Build the straight `FlowCurve` from `start` to `end`.
2. Find the first zone in the list the curve enters, by walking the samples.
3. Take the shorter of going over its top edge or under its bottom edge.
4. Put a waypoint on that side, `clearance` beyond the edge, at the x where the
   curve first entered, clamped to the zone's own x range.
5. Rebuild the curve through the waypoints and look again, up to
   `mostWaypoints`.

A flow that still runs over a zone after two waypoints keeps them and is
counted as a fault. Routing is best effort; the fitness states what it could
not clear.

**Which zones a flow avoids.** Every zone that is neither the source's nor the
target's. A flow inside one zone avoids the others.

## 7. `FlowCurve` becomes a chain

```swift
public struct FlowCurve: Equatable, Sendable {
    public struct Segment: Equatable, Sendable {
        public let start: Point
        public let control1: Point
        public let control2: Point
        public let end: Point
    }

    public let segments: [Segment]

    public init(from start: Point, to end: Point)
    public init(from start: Point, through waypoints: [Point], to end: Point)

    public var start: Point { segments.first?.start ?? .zero }
    public var end: Point { segments.last?.end ?? .zero }
    public func point(at t: Double) -> Point
}
```

`point(at:)` divides `t` evenly across the segments, which is enough: every
reader of it samples densely rather than measuring arc length.

The pull rule for a segment is the one the single curve uses today:
`max(30, min(abs(dx) * 0.5, 150))`. A middle segment aims its controls along
the line joining its neighbours, so the joins do not kink.

`control1` and `control2` stay as computed properties reading the first and
last segment, so today's tests and the arrowhead keep working.

## 8. The canvas

`ConnectionPath` builds its curve with the waypoints `FlowRouting` gives, from
the zones the canvas already holds. `ConnectionsLayer` and `CanvasHitTest` pass
those zones in. The drawn path walks `segments` instead of one `addCurve`.

Nothing is stored. The canvas and the layout call the same function on the same
inputs, so the picture the layout measured is the picture the canvas draws.

## 9. What this design does not do

- It does not order zones by what they talk to.
- It does not route round a component, only round a zone.
- It does not store a waypoint in the model file or the architecture language.
- It does not restart an earlier technique after a later one succeeds.

## 10. Testing

Core:

- `LayoutFitnessTests` — a fault outweighs any number of detours; a detour
  outweighs any size; two layouts with equal faults are decided by size.
- `FlowRoutingTests` — a clear flow gets no waypoint; a flow over one zone gets
  one, on the shorter side; a flow over two zones gets two; a flow that cannot
  be cleared keeps two and still reports the zone.
- `FlowCurveTests` — a chain of one segment matches today's curve exactly; a
  chain starts and ends where asked; `point(at:)` is continuous across a join.
- `LayOutModelTests` — each technique improves the model it is meant to; the
  loop is deterministic; a wider layout that fixes nothing is not accepted.

Application:

- `ConnectionPathTests` — a routed path's arrowhead points along its final
  segment; the click test follows a detour.
- A render test drawing a routed flow.

## 11. Files this touches

Create:

- `ThreatModelKit/Sources/ThreatModelKit/geometry/FlowRouting.swift`
- `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/LayoutPlan.swift`
- `ThreatModelKit/Tests/UnitTests/FlowRoutingTests.swift`
- `ThreatModelKit/Tests/UnitTests/LayoutFitnessTests.swift`

Change:

- `geometry/FlowCurve.swift`
- `architecture/usecase/LayOutModel.swift`
- `threatmodeller/canvas/ConnectionPath.swift`, `CanvasHitTest.swift`,
  `ConnectionsLayer.swift`, `ComponentNodeView.swift`
- `threatmodeller/reporting/CanvasPicture.swift`
