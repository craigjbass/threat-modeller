# Merging two components into one

**Status:** decided, 16 September 2026.

## The problem

A model often holds two components that are one thing: two imports of the
same service, or two people who drew the same store under two names. Nothing
in the window joins them. A person deletes one component and draws every
flow of that component again by hand, and every answer written against the
deleted component goes stale in the controls file.

## The decision

### The verb

`ElementMenu.component` holds a `Merge…` row when two or more components are
selected. The row is absent when fewer than two components are selected. The
row opens `MergeSheet`. The sheet states what the merge will do, lets the
person pick which component stays and which value stays for each attribute
the sources differ in, and runs `MergeComponents` once.

A user block is not a component. A selection that holds a user shows no
`Merge…` row.

### The survivor

The survivor is the component the person picks in the sheet's Keep picker.
The picker starts on the selected component that comes first in the model,
which is the component the file declares first. Every other selected
component is a source.

The survivor keeps its identifier, its position and its `threats` setting.
The sources leave the model.

### The attributes

The sheet shows one row for each attribute below in which the sources and
the survivor do not all state one value. A row lists each distinct value
once, with the component that states it. The row starts on the survivor's
value. An attribute every component agrees on shows no row and keeps its
value.

| Attribute | What a row shows |
| --- | --- |
| technology | the technology's name |
| shape | `Actor`, `Process`, `Store` or `From the technology` |
| name | the name the canvas draws |
| sensitivity | the classification's label |
| `runs_as` | the privilege's label |
| `holds` | the asset ids, joined with commas, or `Nothing` |
| zone | the zone's name, or `No zone` |
| `status` | `Live` or `Proposed` |
| `tags` | the tags, joined with commas, or `None` |
| `provided_by` | the third party's name, or `Nobody` |

The sheet resolves every value before it runs the use case, so
`MergeComponentsRequest` carries the resolved attributes and the use case
decides nothing about them. The request states `sensitivity`, `runsAs`,
`status`, `holds` and `tags` the way `SetComponentPropertiesRequest` states
them, and the use case refuses a word the vocabulary does not hold with the
same responses.

The survivor's `asset` blocks stay. A source's `asset` block whose name the
survivor does not hold joins the survivor, in source order.

### The flows

Every flow of every source moves to the survivor: an end that names a source
now names the survivor. Three rules follow.

1. A flow whose two ends both become the survivor is dropped. That is a flow
   between two sources, or between a source and the survivor.
2. A moved flow that now runs between the same pair, in the same direction,
   as a flow already in the model joins into that flow. The flow that stays
   is the one first in model order. The flow that stays keeps its identifier,
   its kind and its description, and takes the union of the two `carries`
   lists and the two `tags` lists, in first-seen order.
3. Every other flow stays as it is, with its identifier.

A moved flow whose identifier reads `<source>-><target>`, which is the
identifier an import mints, takes the identifier of its new pair. Every
answer keyed `<threat>@connection:<old id>` follows it, in the model and in
the controls file. When the flow joins another, the flow that stays keeps
its own answers and the moved flow's answers under a key the stayed flow
already holds are dropped and named in the response.

The answers of a dropped flow are dropped, in the model and in the controls
file, and the response names them.

`ConnectComponents` refuses a self link and a duplicate pair. The merge
keeps both rules, so a merged model is one `ConnectComponents` could have
built.

The response names the dropped flow identifiers and the identifiers of the
flows that joined into another, so the canvas drops those rows from its
selection.

### The mitigates edges

An edge whose end names a source now names the survivor. An edge whose two
ends both become the survivor is dropped. Two edges that now run between the
same pair join: the edge first in model order stays and takes the threat ids
the other names that it does not, in first-seen order.

### The users

A `reaches` entry that names a source now names the survivor. A `reaches`
list that then names the survivor twice names it once.

### The answers in the model

Every answer keyed on a source is re-keyed on the survivor.

| Map on `ThreatModel` | Key shape | Rewrite |
| --- | --- | --- |
| `controlStatuses`, `controlProofs` | `node:<id>:…` | the prefix |
| `severityOverrides` | `node:<id>::…` | the prefix |
| `compensatingControls`, `recommendations`, `likelihoodFindings`, `severityDecisions`, `impactOverrides`, `acceptedRisks`, `plannedWork` | `<threat>@component:<id>` | the suffix |

A key the survivor already holds wins. The source's value under that key is
dropped and the response names it, as `<threat>@component:<source id>`,
sorted.

After the rewrite, an answer on the survivor whose threat the resolved
technology does not raise is dropped, and the response names it, the way
`ChangeComponentTechnology` drops one. A technology the lookup does not find
is refused, so the merge never guesses what a component raises.

The window reports the dropped answers once, in the diagnostics list, the
way it reports a technology change.

### The attack trees

A goal or a step whose `sourceKind` is `component` and whose `sourceId`
names a source now names the survivor. A goal or a step whose `sourceKind`
is `flow` and whose `sourceId` names a flow that moved now names the moved
flow's pair, as `<source>-><target>`. A step that names a dropped flow stays
as it is and binds to nothing, the way a step naming a deleted element does.

The rewrite runs on `model.attackTrees` and on every `.attacktree` file of
the system, through `AttackTreeSourceGateway.write`, which is the one writer
of that language. A file whose trees the rewrite does not change is not
written.

### The controls file

`MergeComponents` rewrites every `.controls` file of the system through
`ControlsSourceGateway.write`, which is the one writer of that language.

A stanza `threat "<t>" on component "<source>"` becomes
`threat "<t>" on component "<survivor>"`, with every block inside it: the
control answers and their evidence, the likelihood finding, the severity
decision, the impacts, the compensating controls and the recommendations. A
stanza whose key the survivor already holds, in any file of the system, is
dropped whole, and the response names it.

A moved stanza whose threat the resolved technology does not raise is
dropped, and the response names it. The stanza would go stale on the next
compile, and a merge creates no stale answer.

The use case writes the files before it changes the model. A write that
fails leaves the model as it was and answers `cannotWrite`. Every other
block of every file is written back unchanged, and a file the rewrite does
not change is not written.

A model that belongs to no project, the document window's model, states no
root. The use case then changes the model alone.

The governance file is not rewritten. The next save compiles it from the
rewritten controls file, the way every save does.

### One undoable change

The model change is one `mutate`, labelled `Merge Components`, so one Undo
puts every component, every flow, every edge and every answer back in the
model.

The files are not in the model's history, so the use case answers with the
bytes of every file it read before the rewrite and the bytes after it. The
session keeps the pair. An Undo whose label is `Merge Components` writes the
bytes from before the rewrite back through `RestoreFileSnapshots`; a Redo of
the same label writes the bytes from after. The save that follows compiles
the restored model against the restored files, so the files after an Undo
equal the files before the merge.

`RestoreFileSnapshots` writes a snapshot's text to its path, and deletes the
path when the snapshot read no file. It is the one way the window puts bytes
into a file it did not compile.

A reload from disk builds a new session and drops the kept pairs. An Undo of
a merge after a reload puts the model back and leaves the files, the way an
Undo after a severity decision does today.

### Where the code sits

| File | What it holds |
| --- | --- |
| `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/MergeComponents.swift` | the use case, the request, the response |
| `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/RestoreFileSnapshots.swift` | the file restore for Undo and Redo |
| `threatmodeller/canvas/MergeDraft.swift` | the sheet's value: the survivor, the differences, the picks, the request |
| `threatmodeller/canvas/MergeSheet.swift` | the sheet |
| `threatmodeller/canvas/ElementMenu.swift` | the `Merge…` row |
| `threatmodeller/ThreatModelSession.swift` | `mergeComponents`, the kept file pairs, the Undo and Redo hooks |
