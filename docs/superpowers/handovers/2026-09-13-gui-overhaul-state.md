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
| D | Feature parity | Done, commit `a07177e`, with the four use case commits before it |
| E | Analyst flow | Done, commits `1dc9bd7` and `133f31f` |
| F | Opening a large model | Not started. New; see below |

One request arrived after the split and is done: a `.arch` or a `.controls`
file opens the project that holds it, commit `5579fb3`.

Nothing is pushed. Twenty-seven commits sit on local `main`.

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

## Piece D: what was written

Each of the four features now has a use case, a method on
`ThreatModelSession` or `ProjectSession`, and a control in the interface:

| Feature | Use case | Control |
| --- | --- | --- |
| assumptions | `SetAssumption`, `RemoveAssumption` | `AssumptionsPanel` |
| `mitigates` | `SetMitigatesEdge`, `RemoveMitigatesEdge` | `MitigatesPanel`, `MitigatesSheet` |
| `likelihood` | `SetLikelihoodFinding`, `RemoveLikelihoodFinding` | `LikelihoodSheet` |
| `stale threat` | `ListStaleAnswers`, `RemoveStaleAnswer` | `StaleAnswersPanel` |

`threatmodellerTests/ReachingEveryFeatureTests.swift` proves each one is
reachable through the session.

**One fault this found.** Every caller built the key a finding is stored
under. `CompensatingControlSheet` built `"\(threatId)@\(sourceId)"` by hand,
and a new caller used `overrideKey`, which is `"technologyId::threatId"`. The
finding was written under a key the assessment never reads, and the score did
not move. `AssessedThreat` now carries `threatKey`, minted by the core, and
every caller reads it.

## Piece E: the three stages

`WorkStage` states the three: Architecture, Threats, Controls. The control is
a segmented picker at the left of the workflow bar, and `ProjectColumns`
draws the columns of the stage:

| Stage | Columns |
| --- | --- |
| Architecture | palette, diagram, what the system takes on trust |
| Threats | diagram, threat list with a likelihood row on each card |
| Controls | the threat list alone, stale answers at the top |

A stage is a view of one model, not a mode. Every stage keeps the system
picker, Synchronise, Generate Report and Auto Sync, and nothing is locked.

`threatmodellerTests/AnalystFlowTests.swift` measures the columns of each
stage in a real window, and draws each new view.

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

**What was done, in order.**

1. `CurveCrossing` compares squared distances rather than taking a square root.
   Commit `e4cb6d0`. Release, 12 components and 11 flows: 0.069 s to 0.051 s.
2. A callout skips a flow it cannot be covering, by the box around that flow.
   Commit `7f9fae3`. 0.051 s to 0.030 s.
3. The search scores each plan once. Commit `890d4db`. The picture does not
   change; 60 components went 1.827 s to 1.255 s.
4. The layout runs off the main actor, so the window keeps answering.
   Commit `09c03f9`, on the groundwork in `88669f3`.
5. The window says which of four stages a load is on. Commit `09c03f9`.
6. The window draws the diagram forming, from every plan that beats the best
   so far. Commit `8305def`.

**What the cost curve looks like now**, release build, after items 1 to 3:

    10 components  0.040 s
    20 components  0.191 s
    30 components  0.488 s
    40 components  0.805 s
    60 components  2.047 s

It still grows faster than the model does. The next thing to measure is why
`brokenBoundaries` costs what it does now that `hypot` is gone.

**Two faults found after the six items, commit `ceca1ed`.**

The window drew nothing while a model opened, because `Dependencies` declared
`layoutProgress` as `LayoutProgress` and `UseCaseFactory` requires
`LayoutProgress?`. A non-optional stored property does not satisfy an optional
requirement, so the root used the default of nil and no listener attached. The
compiler said nothing.

Dragging a node beachballed. The chain: the drag ends, `move` writes the
positions, `refresh` rescores, the model reports a change, the timer writes,
and the write merges the answers through `CompileControls`, which re-imports
the architecture, and importing lays the diagram out. Every edit ran a whole
layout search on the main actor. The assessment is not the cost: 2ms at sixty
components in release, and summarising another 2ms.

`save` is async now and runs off the main actor.

**The layout on the save path is still waste.** Compiling controls never draws
a diagram, so the search it runs is thrown away. It cannot simply be skipped:
`ImportArchitecture` takes every zone's rectangle from the layout, and zone
membership is derived from geometry, so a compile with no layout would answer
for the wrong zones. Removing it needs zone membership to come from the source
nesting, which the `.arch` file already states, rather than from coordinates.
That is the next change worth making, and it removes the cost rather than
moving it.

**A measurement note.** Do not measure this through Xcode's `RunCodeSnippet`.
It launches the whole application; one attempt ran seven minutes and printed
nothing. Time `LayOutModel` in the package instead, where it lives.

## What is left

1. **Nothing is pushed.** Twenty-seven commits sit on local `main`, and the
   hand-over on `origin/gui-overhaul-handover` is still the stale one.
2. **The layout on the save path is still waste.** See above. Removing it
   needs zone membership from the source nesting.
3. **`brokenBoundaries` has not been measured again** since `hypot` went.
