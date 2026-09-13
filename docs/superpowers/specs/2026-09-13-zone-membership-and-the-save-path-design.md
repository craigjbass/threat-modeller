# Zone membership from the source, and the layout off the save path: design

Written 2026-09-13. This carries forward the two undelivered items of the
graphical interface overhaul. Everything else in that work is merged to
`origin/main`.

## 1. What this fixes

Saving a model runs a whole layout search and throws the picture away.

`CompileControls` merges a person's answers into the `.controls` file. To know
which threats a system raises, it imports the architecture:
`CompileControls.swift:49` builds an `ImportArchitecture` and gives it the
real `LayOutModel` (`threatmodeller/Dependencies.swift:168`). Importing lays
the whole diagram out. Compiling controls never draws a diagram, so every
point of that search is waste.

It is not a small cost. A sixty component model lays out in 1.255 s in a
release build, and the save path runs on every edit: the drag ends, `move`
writes the positions, `refresh` rescores, the auto-save timer fires, and the
write compiles the controls. That is what made dragging a node beachball, and
`save` was made asynchronous to keep the window answering. The cost is still
paid; it is only paid off the main actor.

## 2. Why the layout cannot simply be dropped

`ImportArchitecture` takes each zone's rectangle from the layout
(`ImportArchitecture.swift:102`), and **zone membership is derived from those
rectangles**. `ZoneContainment.zone(holding:in:)` answers which zone holds a
component by testing the component's centre against every zone rectangle,
with the name band excluded.

Six readers ask it:

| Reader | Why it asks |
| --- | --- |
| `ThreatResolver:197` | a zone lowers the risk of what it holds |
| `ViewThreatModel:262` | the canvas draws which zone a node sits in |
| `BuildThreatModelReport:53` | the report groups by zone |
| `AttackPaths:39` | a component in a public zone is reachable |
| `ArchitectureSourceBuilder:21` | the writer nests each component in its zone |
| `BoundaryCrossings:186` | a flow crossing a boundary, on the diagram |

An import with no layout gives every zone a rectangle of nothing, so every
component falls outside every zone, and the compile answers for the wrong
zones. The scores would be wrong, quietly.

## 3. The decision

**The `.arch` file already states membership, and it is the truth.** A
component is written inside the zone block that holds it:

```
zone "internet" {
  kind = "public"

  component "registry" {
    technology = "package-registry"
  }
}
```

`SourceZone.components` carries that nesting. The import throws it away and
re-derives the same fact from coordinates it had to run a layout search to
get.

So: **a component carries the zone that holds it. Geometry decides membership
only when a person moves something, never when a model is read.**

## 4. What changes

**`Component` gains `zoneId: ZoneId?`.** `ImportArchitecture` sets it from
`SourceZone.components`, with no layout involved.

**The canvas sets it when a person moves something.** A drag that ends inside
a zone rectangle puts the component in that zone; a drag that ends outside
every zone takes it out of the one it was in. A zone that is moved or resized
re-takes the components its new rectangle holds and releases the rest. This
is the one place `ZoneContainment` still decides, and it decides once, at the
moment of the edit, rather than on every read.

**Every reader reads the field.** `ThreatResolver`, `ViewThreatModel`,
`BuildThreatModelReport`, `AttackPaths` and `ArchitectureSourceBuilder` read
`component.zoneId`. `BoundaryCrossings` keeps testing geometry: it asks where
a curve crosses a rectangle, which is a question about the picture, not about
membership.

**A document written before this states no field.** `ThreatModelCodec` is at
format version 6 and reads 1 to 6. Version 7 writes the field; a document at
6 or below has it filled in on read by `ZoneContainment`, from the
coordinates that document already holds. Nothing a person saved changes
meaning.

**`CompileControls` imports with no layout.** `ImportArchitecture` takes the
layout as an option. With none, every component keeps the position the source
states, or the origin, and every zone gets a rectangle of nothing. The
membership, the threats and the scores are all the same as before, because
none of them reads a rectangle any more.

## 5. What this design does not do

It does not change what a layout draws, or when the canvas runs one. Opening
a project still lays the diagram out, because a person is about to look at
it.

It does not remove `ZoneContainment`. Dragging a node into a zone is a
geometric question and stays one.

It does not make a zone's rectangle authoritative for anything else. A zone
still draws where the layout puts it.

## 6. What it should cost

Measured on the save path, release build, sixty components: the layout is
1.255 s of it today and should be zero afterwards. Dragging a node should
stop costing a layout search at all.

## 7. The other undelivered item: `brokenBoundaries`

The layout search is still slower than the model it draws:

    10 components  0.040 s
    20 components  0.191 s
    30 components  0.488 s
    40 components  0.805 s
    60 components  2.047 s

The last profile of it, before the square root came out of
`CurveCrossing`, put `brokenBoundaries` at 1.42 s of a 3.04 s load, 46.7%,
nearly all of it under `BoundaryCrossings.stretches`. Three changes have
landed since (squared distances, a callout that skips a flow it cannot cover,
and scoring each plan once), and nothing has profiled it again. Measure it
before changing it. `docs/TESTING.md` states how, and warns not to measure
through Xcode's `RunCodeSnippet`.

## 8. Testing

- An import with no layout puts each component in the zone the source nests
  it in, and scores the same as an import with one.
- A document at format version 6 reads back with the same membership it had,
  filled in from its coordinates.
- A drag that ends inside a zone puts the component in it; a drag that ends
  outside takes it out.
- A zone that is resized over a component takes it, and one resized off a
  component releases it.
- The writer nests each component in the zone the field states.
- `CompileControls` answers the same threats with no layout as with one. This
  is the test that states the point of the change.

## 9. Files this touches

| File | Change |
| --- | --- |
| `modelling/domain/Component.swift` | `zoneId` |
| `architecture/usecase/ImportArchitecture.swift` | sets it from the nesting; the layout becomes optional |
| `architecture/usecase/CompileControls.swift` | imports with no layout |
| `assessment/domain/ThreatResolver.swift` | reads the field |
| `modelling/usecase/ViewThreatModel.swift` | reads the field |
| `reporting/usecase/BuildThreatModelReport.swift` | reads the field |
| `reporting/domain/AttackPaths.swift` | reads the field |
| `architecture/domain/ArchitectureSourceBuilder.swift` | reads the field |
| `modelling/usecase/MoveComponents.swift`, `ResizeZone.swift` | set it on an edit |
| `FileGateways/ThreatModelCodec.swift`, `DocumentJSON.swift` | format version 7 |
| `threatmodeller/Dependencies.swift` | the compile path takes no layout |
