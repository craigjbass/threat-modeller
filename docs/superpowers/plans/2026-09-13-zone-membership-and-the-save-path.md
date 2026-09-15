# Zone Membership and the Save Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Take the layout search off the save path. Saving a model runs a whole layout and throws the picture away, because zone membership is derived from the rectangles that search produces.

**Architecture:** A component carries the zone that holds it. `ImportArchitecture` sets the field from the nesting the `.arch` file already states. Geometry decides membership only when a person drags a node or resizes a zone. `CompileControls` then imports with no layout.

**Tech Stack:** Swift 6, the `ThreatModelKit` local package, the `Testing` framework (`import Testing`, `@Test`, `#expect`), and the hand-written `ArchitectureDSL` parser and writer.

**Spec:** `docs/superpowers/specs/2026-09-13-zone-membership-and-the-save-path-design.md`

## Global Constraints

- Write every comment, commit message and document in the project's plain register: short common words, active voice, present tense, one word for one meaning. No idioms, no metaphors, no vague verbs ("handles", "deals with", "takes care of").
- Test first. Write the failing test, run it, see it fail for the stated reason, then write the code.
- Every new property on an existing public struct takes a default value in the initialiser. The initialisers have many call sites in the tests, and a new required parameter breaks all of them.
- A document a person already saved never changes meaning. A format the codec reads today it still reads afterwards.
- Run the package tests with `cd ThreatModelKit && swift test`. Filter with `--filter <SuiteName>`.
- Run the application tests with `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`. After adding a file to `ThreatModelKit`, run a clean first.
- Measure in a release build, in the package. `docs/TESTING.md` states how, and why not to measure through Xcode's `RunCodeSnippet`.
- Commit after every task.

---

## File structure

| File | Responsibility |
| --- | --- |
| `modelling/domain/Component.swift` | `zoneId`, the zone that holds this component |
| `architecture/usecase/ImportArchitecture.swift` | sets `zoneId` from the source nesting; the layout becomes optional |
| `architecture/usecase/CompileControls.swift` | imports with no layout |
| `assessment/domain/ThreatResolver.swift` | reads `zoneId` |
| `modelling/usecase/ViewThreatModel.swift` | reads `zoneId` |
| `reporting/usecase/BuildThreatModelReport.swift` | reads `zoneId` |
| `reporting/domain/AttackPaths.swift` | reads `zoneId` |
| `architecture/domain/ArchitectureSourceBuilder.swift` | nests each component by `zoneId` |
| `modelling/usecase/MoveComponents.swift` | a drag sets `zoneId` |
| `modelling/usecase/ResizeZone.swift` | a resize takes and releases components |
| `FileGateways/ThreatModelCodec.swift` | format version 7, and fills the field in for 1 to 6 |
| `threatmodeller/Dependencies.swift` | the compile path takes no layout |

---

## Task 0: measure what the save path costs today

- [ ] Write a probe under `ThreatModelKit/Tests/UnitTests/` that builds a sixty component `.arch` source, reads it with `HclArchitectureSource`, and times `CompileControls.execute`. Record the figure here.
- [ ] Time `LayOutModel().execute` alone on the same source, so the share the layout takes is known.
- [ ] Run both with `swift test -c release --filter <the probe>`.
- [ ] Keep the probe until Task 8, then remove it. A printed timing on every test run is noise.

**Write the two figures into this file before going on.** Every later claim about what was saved is measured against them.

**Measured on 2026-09-15**, release build, sixty components in one zone with
fifty-nine flows, the fixture catalogue:

| What | Time |
| --- | --- |
| `CompileControls.execute` | 0.512 s |
| `LayOutModel.execute` alone | 0.502 s |

The layout is 98 percent of the compile.

**After the change**, same machine, same source, release build:

| What | Time |
| --- | --- |
| `CompileControls.execute` | 0.010 s |

The compile runs no layout, and takes 2 percent of what it took.

## Task 1: a component carries its zone

- [ ] Test: a `Component` built with a `zoneId` keeps it.
- [ ] Add `zoneId: ZoneId?` to `Component`, defaulted to nil in the initialiser.

## Task 2: the import reads the nesting

- [ ] Test: an architecture that nests two components in a zone and leaves a third outside imports with the first two carrying that zone's id and the third carrying nil.
- [ ] Test: the same architecture scores the same as it does today.
- [ ] `ImportArchitecture` sets `zoneId` from `SourceZone.components`.

## Task 3: every reader reads the field

Do these one at a time, each with its own failing test first. A reader that still derives membership from geometry gives the wrong answer once the layout goes.

- [ ] `ThreatResolver`: a zone lowers the risk of the components the field names, wherever they sit.
- [ ] `ViewThreatModel`: `ViewedComponent.zoneId` comes from the field.
- [ ] `BuildThreatModelReport`: the report groups by the field.
- [ ] `AttackPaths`: a component in a public zone is reachable by the field.
- [ ] `ArchitectureSourceBuilder`: the writer nests by the field.
- [ ] Leave `BoundaryCrossings` alone. It asks where a curve crosses a rectangle, which is a question about the picture.

## Task 4: geometry decides on an edit

- [ ] Test: a drag that ends inside a zone puts the component in that zone.
- [ ] Test: a drag that ends outside every zone takes the component out of the one it was in.
- [ ] Test: a zone resized over a component takes it; a zone resized off a component releases it.
- [ ] Test: a component added to the canvas inside a zone rectangle joins that zone.
- [ ] `MoveComponents`, `ResizeZone` and `AddComponent` set the field through `ZoneContainment`.

## Task 5: an older document keeps its meaning

- [ ] Test: a document at format version 6, holding a component inside a zone rectangle, reads back with that component in that zone.
- [ ] `ThreatModelCodec` writes format version 7 with the field, and fills the field in from `ZoneContainment` when it reads 1 to 6.

## Task 6: the import takes no layout

- [ ] Test: an import with no layout puts each component in the zone the source nests it in, and raises the same threats with the same scores as an import with one.
- [ ] `ImportArchitecture` takes `LayOutModelUseCase?`. With none, a component keeps the position the source states or the origin, and a zone gets a rectangle of nothing.

## Task 7: the save path stops laying out

- [ ] Test: `CompileControls` answers the same threats and writes the same controls file with no layout as with one. This is the test that states the point of the change.
- [ ] `CompileControls` takes no layout, and `Dependencies` stops giving it one.
- [ ] Run the probe from Task 0 again. Write the new figure here beside the old one.

## Task 8: what the application does

- [ ] Test: dragging a node in `ThreatModelSession` and letting the auto-save run writes the files and never lays the diagram out.
- [ ] Remove the probe.
- [ ] Update `docs/superpowers/specs/2026-09-13-zone-membership-and-the-save-path-design.md` section 6 with the measured figures.

## Task 9: profile `brokenBoundaries` again

This is the second undelivered item and it stands on its own. Do it after Task 8, or in a separate run.

- [ ] Measure `LayOutModel` in a release build at 10, 20, 30, 40 and 60 components, and compare with the curve in section 7 of the spec.
- [ ] Profile one sixty component layout and record where the time now goes.
- [ ] Report the finding before changing anything. The last profile is stale: it was taken before squared distances, before a callout skipped a flow it cannot cover, and before the search scored each plan once.
