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
| `LayoutProgress.reportInterval` | how often the window's sampler turns reports into a redraw, at most |

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
The interval is `LayoutProgress.reportInterval`. The search reports every
plan it scores, which arrives far faster than the interval on a real search,
so the sampler is what decides which reports become a redraw.

A report the window has not drawn yet is replaced, not queued. `receive(_:)`
writes the newest report over the one before it, and asks for a redraw only
when the interval has passed. The redraw reads the newest report when it
runs.

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

### Every scored plan is reported

**Decided 18 September 2026. Issue #249. Revised 19 September 2026. Issue
#271.**

The search reports every plan it scores, in the order it scores them: the
first plan, then each candidate of each technique in each round, whether or
not the candidate beats the best so far. A large model scores many candidates
between two improvements, so reporting improvements alone left the preview
still for most of the search, then jumping.

The search still returns the best plan. A reported candidate that loses does
not change the result, and the search reports the winner once more as its
last report, so the last report a listener hears always equals the plan
`execute` returns.

The sampler, not the search, decides which reports become a redraw. Scoring a
candidate is the whole cost of the search, so a report beside it costs
nothing, and a search with no listener reports to nobody.

### The number

`LayoutProgress.reportInterval` is 0.0625 seconds, one sixteenth of a
second. `LayoutPreviewSampler.redrawInterval` reads it, so this one number
sets both how often the search reported a report under the two-trigger rule
and how often the sampler redraws under the every-plan rule that replaced it.

The number is a whole binary fraction, so a clock that steps by the interval
lands on the interval and the rate does not drift by a rounding error. 0.05
and 0.1 both fall a little short of themselves once a clock has added them
up a few times.

The measurement is `LayOutModel` over two samples, in an optimised build
(`swift test -c release`), under the two-trigger rule the table's "Reports"
column names. The every-plan rule reports far more than this column states,
because it reports every candidate the search scores, not only an
improvement or a clock tick. The "Frames" columns still hold: a redraw is the
sampler's decision, sampled at the same interval either way.

| Sample | Search | Reports | Improved plans | Frames before | Frames after |
| --- | --- | --- | --- | --- | --- |
| sixty components, six zones of ten | 0.60 s | 12 | 5 | 4 | 9 |
| two hundred components, twenty zones of ten | 8.8 s | 39 | 6 | 7 | 40 |

"Frames before" is the improving reports sampled at the old 0.1 second
interval, plus the last. "Frames after" is every report sampled at 0.0625
seconds, plus the last. Both counts come from one run, because the improving
reports are the subset of the reports whose plan beats the plan before, and
the clock trigger adds under one per cent to the search.

On the two-hundred-component sample the six improved plans arrive at 0.17,
0.34, 0.50, 2.81, 5.40 and 5.71 seconds. Two gaps of over two seconds hold
one frame each. The clock trigger fills both: the search scores a candidate
every 170 to 310 milliseconds, which is slower than the interval, so the
preview redraws on every candidate and draws 40 frames.

On the sixty-component sample a candidate takes about 8 milliseconds, which
is faster than the interval, so the interval sets the rate: the reports
arrive 63 to 76 milliseconds apart and the preview draws 9 frames in 0.57
seconds.

0.0625 seconds caps the window at sixteen redraws a second. A redraw of sixty
nodes and their routed flows is the most expensive thing the preview does,
and the canvas draws nothing else while the load runs, so sixteen a second
leaves the column answering.

A longer interval draws fewer frames on the sixty-component sample, where
the interval sets the rate. A shorter interval draws more there, up to one
frame for each candidate, and draws no more on the larger sample, where the
candidate rate already sets the rate. Sixteen frames a second fills the
two-second gaps the larger sample holds, and asks the window for no redraw
the person cannot read.

### The search never waits

The same measurement states the margin. On the sixty-component sample the
search with a listener attached takes 0.6015 seconds; the search with no
listener takes 0.6048 seconds. The difference is under one per cent, because
a report is one call on the search's side, and `receive(_:)` is a lock and
two comparisons on the window's side.

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
