# A layout that keeps a flow off a boundary it does not cross: design

Date: 2026-09-12. Status: approved in conversation, ready for an implementation
plan.

Scope: the diagram geometry moves into the core, the generated layout widens
until few flows cross a trust boundary they have nothing to do with, and the
canvas cuts a gap in a boundary wherever one still does.

## 1. What this fixes

A trust boundary draws as a dotted curve across the flows it separates. A flow
that has nothing to do with that boundary must not cross its curve: a reader
takes a crossing for a statement that the boundary applies to that flow, and it
does not.

Measured on `ClearanceKit/threatmodel/clearancekit.arch`: 22 flows, 16 boundary
runs, **24 unrelated intersections**. The worst run is crossed by four flows
that do not pass through it.

| # | Fault | Evidence |
| --- | --- | --- |
| 1 | A boundary curve crosses flows it does not separate | 24 on the ClearanceKit model |
| 2 | The generated layout cannot see the fault | `LayOutModel` places from declaration order and never looks at what it drew |
| 3 | The geometry that could see it is in the wrong target | `ConnectionPath`, `AnchorGeometry`, `ComponentBox` and `BoundaryCrossings` all live in the application, and `LayOutModel` lives in the core |

## 2. The decisions this design fixes

1. **The diagram geometry belongs to the core.** A layout that cannot measure
   what it drew cannot improve it. The bezier, the anchors, the footprint
   rectangle and the boundary runs move to `ThreatModelKit`. Colour, dash,
   chips, the arrowhead and the click tolerance stay in the application.

2. **The layout widens until the picture is clean, or until it gives up.** It
   places, measures, and widens every gap together, up to six passes. It
   reports the number that survives rather than hiding it.

3. **The layout never moves one node on its own.** Widening every gap keeps the
   picture the declaration order describes. Moving one node would make the same
   source draw a different picture depending on what crossed what.

4. **The canvas cuts a gap where a flow still crosses.** Uniform widening
   cannot reach zero: a flow from the top row to the bottom row passes through
   the middle row's boundaries at any spacing. A gap in the dotted curve holds
   the invariant whatever the layout achieved.

5. **The layout groups boundaries from the source, not from the assessment.**
   No assessment exists when the layout runs. The layout's job is to leave
   room; what the canvas groups by stays the truth.

## 3. What moves

A new folder, `ThreatModelKit/Sources/ThreatModelKit/geometry/`.

### 3.1 `AnchorGeometry`

`ConnectionAnchor` and `AnchorGeometry` move as they are, with `CGPoint`
replaced by the core's `Point` and `CGRect` by the core's `Rect`.

```swift
public enum ConnectionAnchor: String, CaseIterable, Equatable, Sendable {
    case top, right, bottom, left
}

public enum AnchorGeometry {
    public static func point(_ anchor: ConnectionAnchor, of rect: Rect) -> Point
    public static func nearestPair(from: Rect, to: Rect)
        -> (source: ConnectionAnchor, target: ConnectionAnchor)
}
```

### 3.2 `FlowCurve`

Today's `ConnectionPath`, without the arrowhead and without the click
tolerance.

```swift
public struct FlowCurve: Equatable, Sendable {
    public let start: Point
    public let end: Point
    public let control1: Point
    public let control2: Point

    public init(from: Point, to: Point)
    public func point(at t: Double) -> Point
}
```

The pull rule is unchanged: `max(30, min(abs(dx) * 0.5, 150))`.

The application's `ConnectionPath` becomes a wrapper holding a `FlowCurve`. It
keeps `arrowhead(length:width:)`, `hitTolerance`, `distance(to:)` and
`containsClick(at:)`, so nothing about selection changes.

### 3.3 The footprint rectangle

`Component` already states `size` and `footprint(for:)`. It gains the
rectangle, so the core can build an anchor without the application's
`ComponentBox`:

```swift
    public static func footprintRect(at position: Point, shape: DiagramShape) -> Rect
```

The centre stays `position + (80, 36)`, as it is today. `ComponentBox` keeps
its name and its API and reads this.

### 3.4 `BoundaryCrossings`

The whole of today's `threatmodeller/canvas/BoundaryCrossing.swift` moves,
except `BoundaryRun.curve`, which builds a SwiftUI `Path` and stays in the
application as an extension.

`BoundaryCrossing`, `MarkedCrossing` and `BoundaryRun` carry `Point` instead of
`CGPoint`. Every constant and every rule is unchanged: `together` 200,
`overhang` 34, `length` 96, `bow` 18.

### 3.5 `CurveCrossing`

New, and the reason the loop can measure anything:

```swift
public enum CurveCrossing {
    /// How many points each curve is sampled at.
    public static let steps = 48

    /// True when the two open curves cross.
    public static func crosses(_ first: [Point], _ second: [Point]) -> Bool

    public static func samples(of curve: FlowCurve, steps: Int = steps) -> [Point]
    public static func samples(of run: BoundaryCrossings.BoundaryRun, steps: Int = steps) -> [Point]
}
```

`crosses` tests every segment pair by the sign of the cross product on both
sides, which is exact for straight segments and close enough for a curve
sampled at 48 points.

## 4. Shapes at layout time

`LayOutModel` has no catalogue and must not gain one: it places from
declaration order and nothing else. The caller resolves the shapes.

```swift
public struct LayOutModelRequest: Equatable, Sendable {
    public let source: ArchitectureSource
    /// Component id to resolved shape id. A component the map does not name
    /// draws as a process, the way the derivation treats an unknown
    /// technology.
    public let shapes: [String: String]
}
```

`ImportArchitecture` holds the catalogue already. It fills the map from
`Component.resolvedShape(providerId:categoryId:)` before it calls the layout.

## 5. Guards at layout time

The assessment does not exist when the layout runs, so the layout derives the
key it groups runs by from the source alone.

For a flow `a -> b`, the layout's guard key is the sorted list of
`"<source id><status marker>"` for every `mitigates` edge whose target is `b`,
where the marker is `~` for an assumed edge and empty for an adopted one.

This is an approximation of what the canvas groups by, which is the assessed
guards: an edge that answered no raised threat is dropped there and kept here.
The layout's job is to leave room, so an approximation that errs towards more
runs is the safe direction.

## 6. The loop

```swift
public struct LayOutModelResponse: Equatable, Sendable {
    public let components: [LaidOutComponent]
    public let zones: [LaidOutZone]
    /// Flows that still cross a boundary run they do not pass through. Zero
    /// when the widening cleared them all.
    public let unrelatedCrossings: Int
}
```

`execute` runs this, and nothing about it is random, so the same source always
draws the same picture:

1. Place at the current spacing, by the rules `LayOutModel` already has.
2. Build a footprint rectangle for every component, from the request's shapes.
3. Build a `FlowCurve` for every flow, from the nearest anchor pair.
4. Find every crossing of every zone rectangle, with the header band removed.
5. Group the crossings into runs by the layout's guard key.
6. Count the flows that cross a run whose `connectionIds` do not hold them.
7. Stop at zero, or after six passes. Otherwise multiply `columnGap`, `rowGap`
   and `zoneGap` by 1.35 and go again.

The starting gaps are the ones the layout has today: `columnGap` 60, `rowGap`
72, `zoneGap` 60. Six passes at 1.35 reach 4.8 times those, which is the widest
picture this design will draw.

**Why every gap and not one node.** Widening keeps the grid the declaration
order describes. Moving one node makes the same source draw a different picture
depending on what crossed what, and a diff of one line in the file would move
half the diagram.

## 7. The backstop

`ConnectionsLayer` draws a run's curve with a gap wherever an unrelated flow
crosses it.

- Sample the run's curve at 48 points.
- For each flow not in `run.connectionIds`, find the sample nearest to a
  crossing with that flow.
- Remove a window of 16 points of curve length either side of it.
- Draw the surviving stretches as separate dotted subpaths.

A run every flow crosses draws nothing, and that is correct: nothing about it
can be stated without a false crossing.

## 8. What this design does not do

- It never moves one node to clear a crossing.
- It never routes a flow round a boundary.
- It does not change which flows cross which zone, or any risk number.
- It does not change what the canvas groups a run by.

## 9. Testing

Core, in `ThreatModelKit/Tests/UnitTests`:

- `AnchorGeometryTests` and `FlowCurveTests` move from the application tests
  and keep their cases.
- `CurveCrossingTests` — two curves that cross; two that do not; two that share
  an endpoint; a curve against itself.
- `LayOutModelTests` — a source with no crossing keeps the starting gaps; a
  source with a crossing widens; the widening stops at six passes; the response
  states the number that survives; the same source lays out the same way twice.
- `ImportArchitectureTests` — the shapes reach the layout, and a store lays out
  at a store's footprint.

Application, in `threatmodellerTests`:

- `ConnectionPathTests` keeps every case, against the wrapper.
- `ComponentBoxTests` keeps every case.
- A render test drawing a run an unrelated flow crosses, so the gap draws.

## 10. Files this touches

Create:

- `ThreatModelKit/Sources/ThreatModelKit/geometry/AnchorGeometry.swift`
- `ThreatModelKit/Sources/ThreatModelKit/geometry/FlowCurve.swift`
- `ThreatModelKit/Sources/ThreatModelKit/geometry/BoundaryCrossings.swift`
- `ThreatModelKit/Sources/ThreatModelKit/geometry/CurveCrossing.swift`
- `ThreatModelKit/Tests/UnitTests/FlowCurveTests.swift`
- `ThreatModelKit/Tests/UnitTests/CurveCrossingTests.swift`
- `ThreatModelKit/Tests/UnitTests/BoundaryCrossingsTests.swift`
- `ThreatModelKit/Tests/UnitTests/AnchorGeometryTests.swift`

Change, core:

- `modelling/domain/Component.swift`
- `architecture/usecase/LayOutModel.swift`
- `architecture/usecase/ImportArchitecture.swift`

Change, application:

- `canvas/AnchorGeometry.swift` and `canvas/BoundaryCrossing.swift` shrink to
  the drawing they still own, or go
- `canvas/ConnectionPath.swift`, `canvas/ComponentBox.swift`,
  `canvas/ConnectionsLayer.swift`, `canvas/CanvasHitTest.swift`
- `threatmodellerTests/canvas/AnchorGeometryTests.swift` and
  `BoundaryCrossingTests.swift` move to the package
