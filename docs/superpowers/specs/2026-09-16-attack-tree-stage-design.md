# Attack trees as a stage after Architecture

**Status:** decided, 16 September 2026.

## What this replaces

`2026-09-15-attack-tree-editor-design.md` decided a sheet on the Threats
stage, and `2026-09-15-attack-tree-canvas-design.md` kept that sheet and drew
the canvas inside it. This design replaces the **Where it sits** section of
both: a tree is drawn on a stage of its own, not in a sheet. Everything else
in the canvas design stands: what a person draws, the graph-to-tree rules
and their refusals, when the file is written, the derived layout, the score
while it is drawn, and the use cases.

## The problem

A sheet blocks the window. It holds no sidebar, so the trees, the elements
and the selected node all share the front of one modal. It gives the tree
canvas none of the room and none of the controls the architecture canvas
has: no pan, no zoom, no marquee, no undo, no context menu on open canvas
and no Zoom to Fit. `WorkStage` holds three cases, and the tree editor opens
from a toolbar button beside them.

## The decision

### The fourth stage

`WorkStage` gains `attackTrees`, in this order:

| Stage | Label | Symbol | View menu key |
| --- | --- | --- | --- |
| `architecture` | Architecture | `square.on.square` | Cmd+1 |
| `attackTrees` | Attack Trees | `point.topleft.down.to.point.bottomright.curvepath` | Cmd+2 |
| `threats` | Threats | `shield` | Cmd+3 |
| `controls` | Controls | `checklist` | Cmd+4 |

Attack Trees sits after Architecture because a tree names elements the
architecture states, and before Threats because a tree raises the score the
threat list reads. The workflow panel lists the four the way it lists three
today: one segmented control, `WorkStage.allCases` in order. The View menu
keys follow the stage order, so the two stages after Attack Trees move one
key along.

### The columns

The stage draws three columns in a `NavigationSplitView`, the shape the
Architecture stage has:

| Column | View | Width |
| --- | --- | --- |
| sidebar | `TreeSidebar` | min 220, ideal 260 |
| content | `TreeCanvas` with the workflow panel floating over it | min `ProjectColumns.minimumDiagramWidth`, ideal 700 |
| detail | `TreeSelectionPanel` | min 280, ideal 360, max 480 |

The content column keeps the same room under the canvas for the floating
panel that the diagram column keeps, so nothing the canvas draws hides
under the panel. `project.paletteColumns` drives the sidebar's visibility on
this stage too: *Show or Hide Palette*, Control-Command-S and the split
view's own button collapse the left sidebar of whichever stage is drawn.

### The left sidebar: the trees and the elements

`TreeSidebar` holds two lists, one above the other:

- **This system's trees.** One row per tree the `.attacktree` file states:
  its name, its goal, and what the assessment says about it (open with the
  score move, closed, stale, or not bound). Picking a row opens that tree on
  the canvas. **Add Tree** starts a new, empty tree. A system with no tree
  says so.
- **This system's elements.** The two junctions, **ALL OF** and **ANY OF**,
  then every component, flow and zone the `.arch` file states with the
  number of threats the model raises on it. Each row is draggable; the drop
  lands on the canvas at the pointer, in model coordinates.

### The right sidebar: the selected node

`TreeSelectionPanel` reads the tree canvas's selection:

- **One node selected.** The threat the node names, the element it is on,
  and the score: the step's state from `BoundAttackTree.steps` (open,
  closed, unbound, or not written yet). Below them, **Set as Goal** for a
  step that is not the goal, and **Delete**. A junction states its kind
  and what feeds it.
- **A pending element selected.** The element and the threats the model
  raises on it, one button each; picking one makes the node a step. An
  element that raises no threat says so.
- **Nothing selected.** The tree in front: its name, description and
  *Raises risk by* fields, the bound score or the refusal, and **Delete
  Tree**. These fields write through the same path as a change on the
  canvas.
- **No tree in front.** "Pick a tree, or add one."

### What the tree canvas shares with the architecture canvas, and how

The share is a viewport and its gestures, not the architecture state.
`CanvasState` stays the architecture's own: it selects components, zones and
connections, and a tree canvas selects none of those.

A new protocol `CanvasViewport` states what both canvases hold: `transform`,
`visibleSize`, `isPanning`, `lastPanTranslation` and `marquee`. `CanvasState`
and the new `TreeCanvasState` conform. A new `ViewportGestures` struct reads
one `CanvasViewport` and carries the gesture rules that do not depend on
what is drawn. `CanvasGestures` calls it for those rules rather than holding
its own copy, so one rule moves both canvases.

| Gesture | Architecture canvas | Tree canvas | Shared through |
| --- | --- | --- | --- |
| pan | plain drag on the background; two finger scroll | the same | `ViewportGestures.panDragChanged`, `.scroll`, `CanvasTransform.panned` |
| zoom | pinch; Zoom In, Zoom Out, Actual Size on the panel, the View menu and the keys | the same | `ViewportGestures.zoom`, `.zoomAStep`, `.zoomToActualSize`, `CanvasTransform` |
| Zoom to Fit | fits every component and zone | fits every node | `ViewportGestures.fit(_:)` over `SelectionBounds.rect`; each canvas states its own rectangle |
| Zoom to Selection | fits the selected elements | fits the selected nodes | the same |
| marquee | shift-drag on the background selects the components it touches | shift-drag selects the nodes it touches | `ViewportGestures.marqueeDragChanged`, `MarqueeSelection.rect`; each canvas hit tests its own rectangles |
| drag | a drag on a node moves the selection by the model distance | a drag on a node moves every selected node by the model distance and holds it there | `CanvasTransform.modelDistance`; the tree canvas keeps the hold in `TreeCanvasState.held` |
| join | a drag from an anchor handle draws a flow | a drag from the node's join handle draws an edge | the gesture shape: a handle, a preview line, a hit test at the end |
| context menu | `ElementMenu` rows drawn by `ElementMenuView` | `TreeMenu` rows drawn by `ElementMenuView` | `ElementMenu.Row` and `ElementMenuView` |
| Delete, Escape | remove the selection; cancel the drag or clear the selection | the same | the key handlers on each canvas view, one line each |
| drop | a technology drops at the pointer in model coordinates | an element or a junction drops at the pointer in model coordinates | `CanvasTransform.modelPoint` |

**Undo.** The architecture canvas undoes through `UndoLastChange`, which
walks the in-memory model's history. A tree is not in that model: it lives
in a project file and every valid change writes it at once. So the tree
stage keeps its own history. `TreeEditor` records the graph before each
change and Edit ▸ Undo and Redo route to it while the Attack Trees stage is
drawn, through a focused value, the way the zoom items route to the canvas
in front. An undo restores the graph and writes the restored tree through
`WriteAttackTree`, so the file follows the picture. The menu item names the
change it takes back, as it does for the architecture.

**Context menu on a node:** Set as Goal (a step that is not the goal), Cut
the Outgoing Join (a node that feeds one), Delete. **On a pending element:**
one item per threat the model raises on it, then Delete. **On open canvas:**
Select All, Zoom to Fit, Lay Out Tree. Lay Out Tree clears every hold, so
the derived layout is drawn again.

### Where the tree is held

`TreeEditor` is an observable the window owns beside `CanvasState`, so the
tree in front and its history survive a change of stage. It holds the graph,
the pending elements, the tree's name, description and *raises risk by*, the
refusal or the last written tree, and the history. Every change goes through
one method that records history, converts the graph and writes through
`ProjectSession.saveAttackTree` when the graph is a tree. Choosing another
system closes the tree in front.

`TreeCanvasState` is the tree canvas's own `CanvasState`: the viewport, the
selected node ids, the held offsets, the join in flight and the drop point.
It calls no use case.

### What happens to the sheet

`AttackTreeSheet` is deleted, with its toolbar button and its `Meta` struct.
`TreeDraft` moves to its own file: the canvas reads its key rule, and the
tests that state the key stand. `TreeCanvas` is drawn again on the viewport
transform instead of a `ScrollView`, so it pans and zooms the way the
diagram does. `TreeGraph` and the refusals do not change.

## What is not wanted

- No new file format, and no coordinates in `.attacktree`.
- No editing of the architecture from this stage.
- No change to the threats stage or the controls stage beyond the stage
  order and the View menu keys.

## Tests

- `WorkStage.allCases` lists the four stages in order and the new one is
  labelled Attack Trees.
- The Attack Trees stage draws three columns, measured in a window the way
  `AnalystFlowTests` measures the other stages.
- `ViewportGestures`: a plain drag pans by the step since the last change,
  a shift-drag holds the marquee corners, a scroll pans by the delta, a zoom
  step keeps the middle, a fit puts the rectangle in the middle. The
  existing `CanvasGestureTests` stay green through `CanvasGestures`.
- `TreeCanvasGestures`: a plain click selects one node, a shift-click adds
  one, a marquee selects the nodes it touches, a node drag holds every
  selected node by the model distance, a join drag from the handle makes an
  edge, a drop at a view point lands at the model point, Delete removes the
  selection, Zoom to Fit fits every node.
- `TreeEditor`: a change that yields a tree writes it, a change that does
  not states the refusal and writes nothing, an undo restores the graph and
  writes it, a redo puts the change back, Add Tree starts an empty graph,
  Delete Tree removes the file's tree, and choosing another system closes
  the tree.
- The window has no `attack-trees` toolbar item and no sheet.
- `WindowLayoutTests`, `TreeGraphTests` and `AttackTreeEditorFlowTests`
  stay green.

## Order of work

1. `CanvasViewport` and `ViewportGestures`; `CanvasState` conforms and
   `CanvasGestures` delegates. Tests for the shared rules.
2. `TreeCanvasState` and `TreeCanvasGestures`, with their tests.
3. `TreeEditor`, with its tests. `TreeDraft` moves to its own file.
4. `WorkStage.attackTrees`; `TreeSidebar`, `TreeSelectionPanel`, the
   redrawn `TreeCanvas`, `TreeMenu`; the stage's columns in
   `ProjectColumns`; the zoom control on `WorkflowPanel`; the View menu
   keys and the Undo routing in `ThreatModelCommands`. The column test.
5. Delete `AttackTreeSheet` and the toolbar button. The README states the
   stage.
