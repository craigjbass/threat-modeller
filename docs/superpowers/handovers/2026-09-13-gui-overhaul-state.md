# Hand-over: graphical interface overhaul, state

Written 2026-09-13. Replaces `2026-09-13-gui-overhaul-handover.md`, which is on
`origin/gui-overhaul-handover` and is wrong in three places. This document says
where each place is wrong.

## The split

| Piece | Name | State |
| --- | --- | --- |
| A | Canvas viewport | Done, commit `4df0e02` |
| B | Layout faults | Done, commit `6c728b3` |
| C | Project lifecycle | Done, commit `be7ac5b` |
| D | Feature parity | Not started |
| E | Analyst flow | Not started, and not specified |
| F | Opening a large model | Not started. New; see below |

One request arrived after the split and is done: a `.arch` or a `.controls`
file opens the project that holds it, commit `5579fb3`.

Nothing is pushed. Four commits sit on local `main`.

## What the old hand-over got wrong

**The screenshot blocker is permanent, and it is cleared another way.** Both
permissions a screen capture needs are refused:

```
$ swift -e 'import CoreGraphics; import ApplicationServices; print(CGPreflightScreenCaptureAccess(), AXIsProcessTrusted())'
false false
```

Xcode's own MCP server renders a `#Preview` instead, and needs neither.
`docs/TESTING.md` states how. `threatmodeller/LayoutPreviews.swift` holds the
previews, and `threatmodellerTests/HostedDrawing.swift` does the same for a
test.

**The pathway panel measurements.** The panel is 411 points tall at 380 wide,
not 398; 398 is its height at 420 wide. "The threat list is squeezed to 0"
holds only below 618 points of column height at 300 wide, or 532 at 380.

**Piece D is four features, not five.** `reduces_risk_by` is already reachable:
`ZonePanel` has a Reduce risk switch and a slider that writes
`riskReductionPercent`, and `ZoneView` draws the figure.

## Piece D: what is left, and what it costs

`likelihood`, assumptions, `mitigates` and `stale threat` are read from files
and written by nothing:

| Feature | Read by | Written by |
| --- | --- | --- |
| `likelihood` | `ApplyControlAnswers` | nothing |
| assumptions | `ImportArchitecture` | nothing |
| `mitigates` | `ImportArchitecture` | nothing |
| `stale threat`, a `SeverityDecision` | `ApplyControlAnswers` | nothing |

There are 78 use cases and none of them writes any of the four. Every other
control writes through one, so each feature needs a use case, the source
builder or the controls compiler to write it back to the file, a control in
the interface, and tests at each level.

## Piece E: what is missing

The user asked for "a dedicated flow: architecture, then threats, then
controls". Nothing in the code states what that route is. It needs a design in
chat before any code.

## Piece F: opening a large model

**What the user reported.** Opening a large model is slow, it shows no
progress, and the interface stops answering while it loads.

**What the code does.** `ProjectSession` is `@MainActor`, and every path
through it is synchronous: `grep` for `Task {`, `async`, `await`,
`DispatchQueue` and `detach` in `threatmodeller/project/ProjectSession.swift`
finds nothing. So `open(root:)` holds the main actor from the first file read
to the last score.

`open(root:)` runs, in order: `openProject`, `loadLibraries`, then `choose`,
which reaches `ThreatModelSession.refresh()`. `refresh()` then runs
`listTechnologies`, `viewThreatModel`, `assessThreatModel`,
`ElementRiskRollup.byElement`, `EdgeGuards.byElement`, `summariseRisk` and
`listPathwayMitigations`, one after another.

**What the user sees while that runs.** Nothing. `ProjectWindow` draws the
columns, the empty-project offer, or `ContentUnavailableView`. There is no
loading state: `grep` for `ProgressView`, `isLoading` and `loading` in
`ProjectWindow.swift` and `WorkflowBar.swift` finds nothing.

**Where the time goes.** The user profiled it. The layout optimiser is the
cost, not the threat assessment. Total wall is about 3.04 seconds.

```
2.62 s  86.2%  LayOutModel.fitness(of:in:)
1.42 s  46.7%    LayOutModel.brokenBoundaries(of:in:curves:)
1.41 s  46.3%      BoundaryCrossings.breaks -> BoundaryCrossings.stretches
840 ms  27.7%        CurveCrossing.touches -> CurveCrossing.distance
472 ms  15.5%          hypot
147 ms   4.8%          DYLD-STUB$$hypot
562 ms  18.5%        CurveCrossing.crossings -> segmentsCross
402 ms  13.2%    LayOutModel.curves(of:in:)
355 ms  11.7%      FlowRouting.curves
256 ms   8.4%        FlowShape.shareAPath -> CurveCrossing.touches -> distance
393 ms  12.9%    LayOutModel.readability(of:in:curves:)
217 ms   7.1%      FlowShape.shareAPath -> CurveCrossing.touches -> distance
148 ms   4.9%      FlowShape.crosses -> CurveCrossing.crossings
381 ms  12.5%    LayOutModel.callouts(of:in:curves:)
360 ms  11.9%      CalloutPlacement.place
290 ms   9.6%        CalloutPlacement.bestRect -> cost
203 ms   6.7%          closure #6 -> Sequence.contains(where:)
140 ms   4.6%            Array._getElement, through IndexingIterator
```

**The one primitive that dominates.** `CurveCrossing.distance(from:to:_:)`
appears under four separate callers: `stretches` at 840ms, `FlowRouting.curves`
at 242ms, `readability` at 198ms and `CalloutPlacement` at 56ms. Adding the
`hypot` and `DYLD-STUB$$hypot` lines beneath all of them comes to about 903ms,
which is 30% of the whole load.

**Nothing needs that square root.** `CurveCrossing.touches(_:_:within:)` only
ever asks `distance(...) <= reach`, at `CurveCrossing.swift:81`, and
`distance` calls `hypot` on both of its branches, at `:96` and `:104`. A
squared distance compared against `reach * reach` answers the same question,
because both sides are never negative. `CalloutPlacement.nearest(_:to:)` ranks
distances and picks the smallest, so it holds there too.

**Why `fitness` runs so often.** `LayOutModel.execute` runs up to `rounds = 4`
rounds. Each round tries eight techniques, each offering two to five candidate
plans, and every candidate calls `placeAndScore`, which calls `fitness`. That
is about 80 whole scoring passes for one layout.

**When it runs.** `LayOutModel` is wired into `importArchitecture` and
`compileControls`, at `threatmodeller/Dependencies.swift:111` and `:132`. Both
run when a project opens, and again every time the watcher reports a file
change. So editing a file re-runs the whole search.

**What to do, in order.**

1. Drop `hypot`. Compare squared distances in `CurveCrossing.distance` and in
   `CalloutPlacement.distance`. It is local, the geometry is already covered by
   tests, and the profile says it is about 30% of the load.
2. Look at `CalloutPlacement.cost` closure #6. It spends 140ms, 4.6%, inside
   `Array._getElement` reached through `IndexingIterator`, which is array
   indexing and reference counting rather than work. A `contains(where:)` over
   a large array, run per candidate rectangle.
3. Run the search less. 80 scoring passes for a picture nobody asked to be
   optimal is the shape of the fault. A model above some size could take the
   first plan, or the rounds could stop on a time budget rather than on
   `rounds = 4`.
4. Move it off the main actor. `ProjectSession` is `@MainActor` and every path
   through it is synchronous, so the interface cannot answer while any of this
   runs. This alone makes nothing faster; it stops the window freezing.
5. Say what it is doing. The stages are named already, so a progress line can
   name the stage and the round it is on.
6. Draw the diagram as it arrives. The user asked for sampled snapshots of the
   part-optimised diagram. `placeAndScore` is the point to sample from, because
   it already holds a placed model each time it scores.

Items 1 to 3 make it stop being slow. Item 4 stops the freeze. Items 5 and 6
are what the user asked to see, and neither helps while the main actor is held.

**A measurement note.** Do not measure this through Xcode's `RunCodeSnippet`.
It launches the whole application; one attempt ran seven minutes and printed
nothing. Time `LayOutModel` in the package instead, where it lives.
