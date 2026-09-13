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
cost, not the threat assessment:

```
2.62 s  86.2%  specialized static LayOutModel.fitness(of:in:)
1.42 s  46.7%    static LayOutModel.brokenBoundaries(of:in:curves:)
402 ms  13.2%    static LayOutModel.curves(of:in:)
393 ms  12.9%    static LayOutModel.readability(of:in:curves:)
381 ms  12.5%    static LayOutModel.callouts(of:in:curves:)
```

**Why `fitness` runs so often.** `LayOutModel.execute` runs up to `rounds = 4`
rounds. Each round tries eight techniques, each offering two to five candidate
plans, and every candidate calls `placeAndScore`, which calls `fitness`. That
is about 80 whole scoring passes for one layout.

**Why each pass is expensive.** `readability(of:in:curves:)` compares every
flow against every other, at `LayOutModel.swift:446-447`, so a pass is O(flows
squared). `brokenBoundaries` costs more than twice what `readability` costs and
is the single largest line in the profile.

**When it runs.** `LayOutModel` is wired into `importArchitecture` and
`compileControls`, at `threatmodeller/Dependencies.swift:111` and `:132`. Both
run when a project opens, and again every time the watcher reports a file
change. So editing a file re-runs the whole search.

**What to consider, in order.**

1. Run it less. 80 scoring passes for a picture nobody has asked to be optimal
   is the fault. A model above some size could take the first plan, or the
   rounds could stop on a time budget rather than on `rounds = 4`.
2. Make a pass cheaper. `brokenBoundaries` is 46.7% on its own, and
   `readability` is quadratic in the flow count.
3. Move it off the main actor. `ProjectSession` is `@MainActor` and every path
   through it is synchronous, so the interface cannot answer while any of this
   runs. This alone does not make it faster; it stops the window freezing.
4. Say what it is doing. The stages are named already, so a progress line can
   name the stage and the round it is on.
5. Draw the diagram as it arrives. The user asked for sampled snapshots of the
   part-optimised diagram. `placeAndScore` is the point a snapshot can be taken
   from, because it already holds a placed model.

Items 4 and 5 are what the user asked to see. Neither helps while the main
actor is held, so item 3 comes first of those three; items 1 and 2 are what
make it stop being slow at all.

**A measurement note.** Do not measure this through Xcode's `RunCodeSnippet`.
It launches the whole application; one attempt ran seven minutes and printed
nothing. Time `LayOutModel` in the package instead, where it lives.
