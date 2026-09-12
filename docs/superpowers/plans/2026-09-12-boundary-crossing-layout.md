# Boundary crossing layout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the diagram geometry into the core so the generated layout can widen until few flows cross a trust boundary they do not pass through, and cut a gap in the boundary wherever one still does.

**Architecture:** The anchors, the bezier, the footprint rectangle and the boundary runs move from the application to `ThreatModelKit`. `LayOutModel` then places, measures its own picture, widens every gap, and repeats up to six passes. `ConnectionsLayer` cuts a gap in a run's curve wherever an unrelated flow survives, so the drawn count is zero whatever the layout achieved.

**Tech Stack:** Swift 6, SwiftUI, macOS. Package `ThreatModelKit`. Tests use `swift-testing`.

**Spec:** `docs/superpowers/specs/2026-09-12-boundary-crossing-layout-design.md`

## Global Constraints

- `cd ThreatModelKit && swift test` before every commit.
- After adding a file to the package, run
  `xcodebuild clean -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
  once before the application tests.
- Application tests:
  `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
- Commit with `git -c commit.gpgsign=false commit`.
- The core uses its own `Point`, `Rect` and `Size`. No `CoreGraphics` in `ThreatModelKit`.
- Constants that move keep their values: `together` 200, `overhang` 34, `length` 96, `bow` 18, the bezier pull `max(30, min(abs(dx) * 0.5, 150))`, the centre at `position + (80, 36)`.
- Starting gaps stay `columnGap` 60, `rowGap` 72, `zoneGap` 60. The widening factor is 1.35 and the cap is six passes.

---

### Task 1: `FlowCurve` and the anchors in the core

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/geometry/FlowCurve.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/geometry/AnchorGeometry.swift`
- Create: `ThreatModelKit/Tests/UnitTests/FlowCurveTests.swift`
- Create: `ThreatModelKit/Tests/UnitTests/AnchorGeometryTests.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Component.swift`

**Interfaces:**
- Produces: `FlowCurve`, `ConnectionAnchor`, `AnchorGeometry.point(_:of:)`,
  `AnchorGeometry.nearestPair(from:to:)`, `Component.footprintRect(at:shape:)`.

- [ ] **Step 1: Write the failing tests**

`FlowCurveTests` states the pull rule, the endpoints and `point(at:)` at 0, 0.5
and 1. `AnchorGeometryTests` states the four anchor points of a rectangle and
the nearest pair for a box to the right, the left, above and below, and that a
tie always picks the same pair.

- [ ] **Step 2: Run them and see them fail**

`cd ThreatModelKit && swift test --filter FlowCurveTests`

- [ ] **Step 3: Write `FlowCurve`**

```swift
public struct FlowCurve: Equatable, Sendable {
    public let start: Point
    public let end: Point
    public let control1: Point
    public let control2: Point

    public init(from start: Point, to end: Point) {
        self.start = start
        self.end = end
        let pull = max(30, min(abs(end.x - start.x) * 0.5, 150))
        control1 = Point(x: start.x + pull, y: start.y)
        control2 = Point(x: end.x - pull, y: end.y)
    }

    public func point(at t: Double) -> Point { ... }
}
```

- [ ] **Step 4: Write `AnchorGeometry`, on `Rect`**

- [ ] **Step 5: Add `Component.footprintRect(at:shape:)`**

```swift
    public static func footprintRect(at position: Point, shape: DiagramShape) -> Rect {
        let footprint = footprint(for: shape)
        let centre = Point(x: position.x + size.width / 2, y: position.y + size.height / 2)
        return Rect(
            x: centre.x - footprint.width / 2,
            y: centre.y - footprint.height / 2,
            width: footprint.width,
            height: footprint.height
        )
    }
```

- [ ] **Step 6: Run the package, then commit**

---

### Task 2: `BoundaryCrossings` in the core

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/geometry/BoundaryCrossings.swift`
- Create: `ThreatModelKit/Tests/UnitTests/BoundaryCrossingsTests.swift`

**Interfaces:**
- Consumes: `FlowCurve`, `Rect`, `EdgeGuard`, `ZoneContainment`.
- Produces: `BoundaryCrossing`, `BoundaryCrossings.MarkedCrossing`,
  `BoundaryCrossings.BoundaryRun`, `BoundaryCrossings.of(...)`,
  `BoundaryCrossings.runs(_:)`.

The whole of `threatmodeller/canvas/BoundaryCrossing.swift` moves, with
`CGPoint` becoming `Point`, `hypot` staying, and `BoundaryRun.curve` left
behind. `of` takes plain values rather than the viewed types:

```swift
    public static func of(
        connectionId: String,
        sourceZoneId: String?,
        targetZoneId: String?,
        curve: FlowCurve,
        zones: [BoundaryZone]
    ) -> [BoundaryCrossing]
```

`BoundaryZone` is `(id: String, networkZoneId: String, rect: Rect)`, so the core
needs neither `ViewedZone` nor `ZoneBox`.

The tests move from `threatmodellerTests/canvas/BoundaryCrossingTests.swift`
and keep every case.

---

### Task 3: `CurveCrossing`

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/geometry/CurveCrossing.swift`
- Create: `ThreatModelKit/Tests/UnitTests/CurveCrossingTests.swift`

```swift
public enum CurveCrossing {
    public static let steps = 48

    public static func samples(of curve: FlowCurve, steps: Int = steps) -> [Point]
    public static func samples(of run: BoundaryCrossings.BoundaryRun, steps: Int = steps) -> [Point]
    public static func crosses(_ first: [Point], _ second: [Point]) -> Bool
    /// Where along `first` the two cross, as indices into it.
    public static func crossings(_ first: [Point], _ second: [Point]) -> [Int]
}
```

Tests: two straight curves that cross; two that do not; two that meet only at an
endpoint (not a crossing); the index a crossing reports.

---

### Task 4: The application reads the core geometry

**Files:**
- Modify: `threatmodeller/canvas/ConnectionPath.swift`, `AnchorGeometry.swift`,
  `ComponentBox.swift`, `BoundaryCrossing.swift`, `CanvasHitTest.swift`,
  `ConnectionsLayer.swift`
- Modify: `threatmodellerTests/canvas/*`

`ConnectionPath` wraps a `FlowCurve` and keeps `arrowhead`, `hitTolerance`,
`distance(to:)` and `containsClick(at:)`. The application's `AnchorGeometry` and
`BoundaryCrossing` files go; call sites use the core's. `ComponentBox` reads
`Component.footprintRect`. `BoundaryRun.curve` becomes an application extension.

No behaviour changes in this task. Every existing test must pass unchanged
except for the type names.

---

### Task 5: Shapes reach the layout

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/LayOutModel.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/ImportArchitecture.swift`
- Modify: `ThreatModelKit/Tests/UnitTests/LayOutModelTests.swift`, `ImportArchitectureTests.swift`

`LayOutModelRequest` gains `shapes: [String: String]`, defaulting to empty.
`ImportArchitecture` fills it from the catalogue with
`Component.resolvedShape(providerId:categoryId:)`.

---

### Task 6: The layout measures and widens

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/LayOutModel.swift`
- Modify: `ThreatModelKit/Tests/UnitTests/LayOutModelTests.swift`

`LayOutModelResponse` gains `unrelatedCrossings: Int`. `execute` places at a
spacing, measures, and widens up to six passes. The placement rules move into a
private `place(_:spacing:)`, so the loop calls one function with a different
spacing each pass.

The layout's guard key for a flow `a -> b` is the sorted
`"<mitigates source id><~ when assumed>"` for every edge whose target is `b`.

Tests: a source with no crossing keeps the starting gaps; a source with a
crossing widens; the widening stops at six passes; the response states what
survives; the same source lays out the same way twice.

---

### Task 7: The canvas cuts a gap

**Files:**
- Modify: `threatmodeller/canvas/ConnectionsLayer.swift`
- Modify: `threatmodellerTests/ViewRenderTests.swift`

A run's curve draws as the stretches that no unrelated flow crosses. The window
removed either side of a crossing is 16 points of curve length. A run every
flow crosses draws nothing.

---

### Task 8: Prove it on the real model

**Files:**
- Modify: `threatmodellerTests/ViewRenderTests.swift`

A test builds two zones and three flows, one of which crosses a boundary it
does not pass through, and states that the drawn stretches leave a gap there.
Then render `ClearanceKit` by hand and report the before and after counts.

## Self-review

**Spec coverage.** 3.1 → Task 1. 3.2 → Task 1. 3.3 → Task 1. 3.4 → Task 2.
3.5 → Task 3. 4 → Task 5. 5 → Task 6. 6 → Task 6. 7 → Task 7. 9 → every task.

**Names.** `FlowCurve`, `ConnectionAnchor`, `AnchorGeometry`,
`Component.footprintRect(at:shape:)`, `BoundaryZone`, `BoundaryCrossing`,
`BoundaryCrossings.MarkedCrossing`, `BoundaryCrossings.BoundaryRun`,
`CurveCrossing.crosses`, `CurveCrossing.crossings`,
`LayOutModelRequest.shapes`, `LayOutModelResponse.unrelatedCrossings`.
