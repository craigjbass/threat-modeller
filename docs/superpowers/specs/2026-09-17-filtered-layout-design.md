# A filtered diagram lays the drawn set out

**Status:** decided, 17 September 2026. Issue #156.

## The problem

The tag filter (#127) and Focus (#129) narrow what the canvas draws. The
drawn elements keep the coordinates the full layout gave them. Six
components out of sixty draw as six boxes across a canvas sized for sixty,
with long flows between them.

`ArrangeDiagram` already lays a model out, or a named set inside it, through
`LayOutModel`. `ArrangeDiagram` calls `models.mutate`, so the coordinates it
writes are model state and reach the `.arch` file on save. A filtered layout
must not write the model: the file and the full layout stay as they are.

## The decision

A narrowed set is laid out by a use case that writes no model, and the
result is held as view state on `CanvasState`.

### The subset layout use case

`LayOutSubset` in
`ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/LayOutSubset.swift`.

Collaborators are the three `ArrangeDiagram` takes: `ThreatModelGateway`,
`TechnologyCatalogue`, `LayOutModelUseCase`.

The use case reads `models.current()`, copies the model, and keeps only the
named components and the named zones. It drops the flows and the mitigates
edges whose two ends are not both kept. It builds an `ArchitectureSource`
from that copy with `ArchitectureSourceBuilder.source(from:)`, and runs
`LayOutModel` over that source.

The use case never calls `models.mutate`. There is no model change, no undo
entry, and nothing reaches the `.arch` file.

`ArchitectureSourceBuilder` already writes a component whose zone the model
does not hold as a loose component. So a drawn component whose zone the
subset leaves out lays out loose, and the use case states no extra rule for
it.

| Type | Shape |
| --- | --- |
| `LayOutSubsetRequest` | `componentIds: [String]`, `zoneIds: [String]` |
| `LayOutSubsetResponse` | `.laidOut(components: [LaidOutComponent], zones: [LaidOutZone])` or `.nothingToLayOut` |

An empty request is `.nothingToLayOut`. This is the opposite of
`ArrangeDiagramRequest`, where an empty request means the whole model: a
narrowed set that names nothing draws nothing, so there is nothing to lay
out.

The use case filters `model.components` and `model.zones` in model order,
so the request's own order changes nothing. Two picks of the same set in
either order give the same response.

`LayOutSubset.frameBudget` states the frame budget the timing test reads.

The use case is registered as `layOutSubset()` on `UseCaseFactory`, on
`Dependencies` and on `TestDependencies`, beside `arrangeDiagram()`.

### The narrowed positions

`DrawnDiagram` (`threatmodeller/canvas/TagFilter.swift`) gains
`placed(componentPositions:zoneRects:)`. It returns a new `DrawnDiagram`
whose `ViewedComponent` and `ViewedZone` values carry the narrowed
coordinates. An element the two maps do not name keeps the coordinates it
has.

`ViewedComponent` gains `moved(x:y:)` and `ViewedZone` gains
`moved(x:y:width:height:)` in the kit, so the window does not repeat every
field of those two values.

Every reader of the drawn set already goes through `CanvasState.drawn(in:)`
(#151): `CanvasView`, `CanvasGestures` and `ElementMenu` call it. So the
drawing, the hit test and the menus read the narrowed coordinates with no
change to any of them.

### When the layout runs

`CanvasState` gains one settable collaborator, a `NarrowedDiagramLayouts`
protocol with `var model: ViewThreatModelResponse` and
`func layOutSubset(componentIds:zoneIds:)`. `ThreatModelSession` conforms:
the session holds the canvas snapshot and the use case factory already.
`ProjectWindow` sets the collaborator in the `.onAppear` that sets
`canvas.showStage`.

The layout runs from the four narrowing verbs on `CanvasState`:
`pick(tag:)`, `focus(componentId:)`, `setNeighbourDepth(_:)` and
`clearTagFilter()`.

**Caution: the layout must not run inside `drawn(in:)`.** A SwiftUI view
body reads `drawn(in:)`, and writing observed state from a view body is a
state change during a view update. The verbs write the positions; the body
only reads them.

`CanvasView` calls `CanvasState.layOutNarrowedSetAgain()` from
`.onChange(of: session.revision)`, so an edit made while a filter is on lays
the narrowed set out again.

Every run reads the model's own coordinates, never the coordinates of the
previous run. So a second tag, or a deeper neighbour count, lays the new set
out from the full positions, and the result does not depend on the order of
the picks.

### The fit

`CanvasState` is a `CanvasViewport` already, so it fits itself through
`ViewportGestures(viewport: self).fit(_:)` with a rectangle from
`SelectionBounds.rect(components:zones:)`.

On a narrowing verb the canvas fits the narrowed result. On
`clearTagFilter()` the canvas fits the full model, which is the rectangle
`CanvasGestures.zoomToFit()` builds.

### A drag while a filter is on

A drag on a component while a filter is on writes into the narrowed
positions on `CanvasState`. It calls no use case, so the model does not
move and the `.arch` file does not change.

The move is dropped on the next filter change, because every layout run
starts from the model's own coordinates. The issue names this as the
simpler rule and the default.

A drag while no filter narrows the canvas still moves the model, the way it
always did.

### The size above which a preview shows

The size is 24 drawn elements, where an element is a drawn component or a
drawn zone.

At or below 24 elements the search runs on the main actor inside one frame,
so the canvas draws the result in the frame the person asked for it.

Above 24 elements the search passes one frame. The canvas keeps the
coordinates it is already drawing until the result arrives, so the picture
never goes blank, and #147 replaces the kept coordinates with the re-routing
preview.

Today the canvas holds no constant for the size. `CanvasState
.layOutNarrowedSet()` calls the use case and writes the coordinates only
when the result arrives, so the picture never goes blank at any size, and
the coordinates already drawn stand until then. #147 adds the control that
reads this number.

### The frame budget

One frame at 60 Hz is 0.0167 seconds.

The measurement is `LayOutSubset`, laying six components and two zones out
from the model the timing test imports:

| Build | Measured |
| --- | --- |
| optimised (`swift test -c release`) | 0.0095 seconds |
| debug (`swift test`) | 0.513 seconds |

The shipped application runs an optimised build, and 0.0095 seconds is
inside one frame, so the canvas draws a narrowed set of ten elements in the
frame the person asked for it.

The kit tests run a debug build, where the same search is 54 times slower.
So `LayOutSubset.frameBudget` states 0.0167 seconds in an optimised build
and 3.0 seconds in a debug build. The debug number is the measurement with
room for a slower machine, and for the other tests the kit suite runs beside
this one. `LayOutSubsetTests.laysTenElementsOutInsideTheFrameBudget` reads
the constant, so the test states the budget of the build it runs in.

The size above which a preview shows is 24 elements because the search grows
with the set: the measurement above is eight elements, and a set three times
that size passes one frame even in an optimised build.
