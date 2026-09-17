# The layout preview is the diagram, re-routing

**Status:** decided, 17 September 2026. Issue #147.

## The problem

While a system opens, the window draws `FormingDiagram`: a scaled outline of
where each component sits and how big each zone is. It draws no name, no
icon and no flow. The comment on the view states the reason.
`LayOutModelResponse` holds geometry alone, so the view cannot draw more.

The wanted preview is the real diagram: the drawing the canvas makes, with
icons, names, zones and routed flows, at the coordinates the latest report
gives, fitted to the column on every redraw.

## The decision

The layout search publishes the drawn subject before it starts, the window
samples the reports, and the preview draws the subject at the reported
coordinates through `CanvasPicture`.

### The drawn subject

`LayoutProgress` gains a subject beside its report listener.

| Member | Shape |
| --- | --- |
| `LayoutSubject` | `components: [ViewedComponent]`, `connections: [ViewedConnection]`, `zones: [ViewedZone]` |
| `LayoutProgress.describe(_:)` | the search's caller states the subject |
| `LayoutProgress.subject` | what a listener reads |

A subject holds every field `CanvasPicture` draws: the name, the shape, the
provider, the category, the sensitivity, the zone and the flows. The layout
search knows none of that, so the use case that runs the search states it.

`describe(_:)` runs before the first `report(_:)`, so a listener that hears a
report always has a subject to draw it over.

### Where the subject comes from

`ViewThreatModel.execute` already maps a `ThreatModel` to those three lists.
That mapping moves out of the use case into `ViewedModel`, a value with one
function for each list. `ViewThreatModel` calls it, and so does every caller
that publishes a subject. There is one mapping, so the preview and the
canvas cannot draw a component differently.

`ImportArchitecture` builds the model before it lays the model out.

Today the use case runs `layout.execute` first and passes the positions into
the `Component` initialiser. It cannot build a subject there, because a
subject needs the model and the model does not exist yet. So the order
changes: the use case builds every component at the origin and every zone at
a rectangle of nothing, states the subject, runs the search, and then writes
the positions and the rectangles into the built model. `Component.position`
and `Zone.rect` are both settable, which is how `ArrangeDiagram` moves an
element already.

The compile path passes no layout. With no layout there is nothing to write
back, so a component keeps the origin and a zone keeps a rectangle of
nothing, which is what that path read before.

`ArrangeDiagram` states the subject the same way, from the model it already
holds. So **Lay Out** on an open system draws the same preview as opening a
system does.

Both use cases take `progress: LayoutProgress? = nil`. Only
`threatmodeller/Dependencies.swift` passes one. `TestDependencies` and
`CommandLineDependencies` pass none and are unchanged.

### The sampling rule

`LayoutPreviewSampler` is the window's side of the reports. It is one named
type, so the filtered layout of #156 draws its own preview through the same
sampler.

The rule is a fixed interval: the preview redraws at most once every
`LayoutPreviewSampler.redrawInterval`, and the last report is always drawn.

`receive(_:)` runs on the search's own thread. It takes a lock, writes the
newest report, reads two times, and returns. It never draws and never waits
for the window. When the interval has passed it calls a notification that
enqueues a redraw on the main actor and returns at once. So the search
stores and forgets, and the sampling happens on the window's side.

`drawTheLast()` runs after the search returns. It draws the newest report
whether the interval has passed or not, so the preview ends on the final
plan.

The window reads `LayoutPreviewSampler.latest` when the redraw runs, rather
than a value carried on the notification. Two redraws enqueued in either
order then both read the newest report, so the final plan cannot be
overtaken by an earlier one.

### The number

`LayoutPreviewSampler.redrawInterval` is 0.1 seconds.

The measurement is `LayOutModel` over a sixty-component sample: six zones of
ten components, a chain of flows inside each zone and one flow between
neighbouring zones.

| Build | Search | Reports | Span | Gaps |
| --- | --- | --- | --- | --- |
| optimised (`swift test -c release`) | 0.585 s | 5 | 0.359 s | 0.015, 0.015, 0.166, 0.164 |
| debug (`swift test`) | 46.6 s | 5 | 28.6 s | 1.18 to 13.19 |

The shipped application runs an optimised build. There the five reports
arrive at 0, 0.015, 0.029, 0.195 and 0.359 seconds. A 0.1 second interval
draws the first, the fourth and the fifth: three redraws of the sixty
component picture in 0.359 seconds, and the last plan is one of the three.
The two reports 15 milliseconds apart are the burst the rule drops, and the
plan they carry is superseded 14 milliseconds later.

0.1 seconds caps the window at ten redraws a second. A redraw of sixty nodes
and their routed flows is the most expensive thing the preview does, and ten
a second leaves the column answering while the search runs.

A shorter interval gains nothing on this sample: the search itself reports
only five times, and three of the five already reach the screen. A longer
interval would drop the fourth report, which is the one that shows the
picture settling.

### The search never waits

The same measurement states the margin. The search with a listener attached
takes 0.5844 seconds; the search with no listener takes 0.5850 seconds. The
difference is under one per cent, because `receive(_:)` is a lock and two
comparisons.

`LayoutPreviewTimingTests` states the margin as twenty-five per cent of the
search with no listener. The measured difference is under one per cent, and
the rest is room for a slower machine and for the other tests the suite runs
beside it. A preview that drew on the search's thread would multiply the
search time rather than add a quarter to it, so the margin still catches
one.

### The size above which a preview shows

`LayOutSubset.previewAboveElements` is 24, where an element is a drawn
component or a drawn zone.
`docs/superpowers/specs/2026-09-17-filtered-layout-design.md` states the
number and states that #147 adds the constant that holds it. This issue adds
it, and the sampler reads it.

At or below 24 elements the search finishes inside one frame, so there is
nothing to preview: the canvas draws the result in the frame the person
asked for it.

### The fit

`FormingDiagram` loses its drawing and keeps the fit alone. It becomes one
function: the rectangle a layout report covers, measured through
`SelectionBounds.rect` with `Component.size` for a component, which is
exactly how `CanvasGestures.zoomToFit` measures the model.

`FormingPicture` fits that rectangle with
`CanvasTransform.fitting(_:in:)`, the call `ViewportGestures.fit(_:)` makes.
So the preview's transform equals the transform Zoom to Fit gives for the
same layout in the same column, and the picture does not move at the
hand-over.

The fit runs on every redraw, so a plan that widens the picture still fits
the column.

### The preview interacts with nothing

`FormingPicture` draws `CanvasPicture`, which takes no `CanvasState`, draws
no selection and carries no gesture. There is no panel, no drag and no
selection until the load ends and `CanvasView` takes over.

### What a preview needs before it draws

The preview draws only when the window holds both a subject and a report. A
search that has reported nothing yet draws the progress spinner, which is
what the window drew before any report arrived.
