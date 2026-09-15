# Drawing an attack tree in the window

**Status:** decided, 15 September 2026.

## What this replaces

`2026-09-15-attack-tree-editor-design.md` decided a form: pickers and a flat
step list in a sheet. A tree is a shape — a route through the system — and a
form states the shape nowhere. This design replaces that one's **What a
person does** table and the outline column. Everything else in it stands:
the sheet on the threats stage, the tree list beside it, the use cases
(`ListAttackTreeSources`, `WriteAttackTree`, `RemoveAttackTree`), the one
writer, and the refusals the parser already states.

## The decision

### Where it sits

The sheet keeps its two columns. The left column lists the trees as before.
The front column becomes a canvas, one per tree, empty for a new tree. A
third, narrow column beside the canvas lists what the `.arch` file states —
each component, flow and zone — with the number of threats the model raises
on it.

### What a person draws

- **A node.** Dragging an element from the list onto the canvas makes a node.
  The node offers the threats this model raises on that element, and picking
  one makes the node a **step**. An element that raises no threat says
  "raises no threat" and becomes no step: it cannot be joined and it is not
  written.
- **An edge.** Dragging from one node to another joins them, the way a flow
  is drawn on the architecture canvas. `A → B` states that A feeds B: A is
  under B in the file.
- **The goal.** Exactly one node is the goal, set from the node's menu, and
  drawn so a reader tells it from a step at a glance: the goal takes a
  doubled border and the word **goal**. Setting a different node as the goal
  moves the mark. The goal is written as the `goal` statement, not as a step.
- **A junction.** `all_of` and `any_of` are nodes of their own, dropped from
  the same list, labelled **ALL** and **ANY**. A junction of its own, not a
  switch on an edge, because the conjunction belongs to one parent and an
  edge belongs to two nodes; because junctions nest (`any_of` holding
  `all_of`), which a switch on an edge cannot state without inventing nodes
  the person never drew; and because a junction node maps one-to-one to the
  block the file states.

### The graph becomes the tree, or is refused

The node that feeds the goal is the root. The conversion walks the edges and
refuses, with the node named, a graph that is not a tree:

| The graph holds | The refusal |
| --- | --- |
| a cycle | `the route through "<node>" comes back to itself` |
| a node with two outgoing edges | `"<node>" feeds two nodes; a step sits under one` |
| a node with no route to the goal | `"<node>" reaches no goal` |
| two nodes feeding the goal | `two nodes feed the goal; one root feeds it` |
| a junction with nothing feeding it | `the <all_of/any_of> holds nothing` |
| a node feeding a step | `"<node>" feeds a step; a step sits under an all_of or an any_of` |
| nothing feeding the goal | `the tree holds no steps` |
| a junction set as the goal | `the goal names a threat; an all_of or an any_of is not one` |
| no goal set | `the tree states no goal` |

Each refusal mirrors the parser's own rule in `docs/LANGUAGE.md` section 7.6,
so the canvas and a hand-written file refuse the same shapes. A step holds no
children in the grammar — steps are leaves — so a route of two steps is drawn
as both steps feeding one `all_of`, the way the language's own example nests
them.

### When it writes

Every change that yields a valid tree writes at once through
`WriteAttackTree` — there is no Save button to forget. A change that yields
an invalid graph writes nothing and shows the refusal above the canvas; the
person keeps drawing until the graph is a tree again. The window never calls
`AttackTreeWriter` itself, so a tree drawn here and the same tree written by
`threatmodeller format` are the same bytes, and the round-trip test states
it.

### Where a node sits

Node positions are not in the `.attacktree` file and are not written into
it. The canvas lays the picture out from the tree each time, the way
`LayOutModel` lays out an architecture: the goal at the right, each depth one
column to its left, siblings stacked. Derived layout, because the file states
the model and nothing about the drawing: two machines draw the same picture
from the same file, and a review diff stays about the route, never about
coordinates. While a person drags a node the drag holds on screen; the next
open lays it out again.

### The score, while it is drawn

Each written change rescores the model, and the canvas reads
`AssessThreatModelResponse.attackTrees` back: every step states open or
closed on its node, and the tree states its score beside the canvas. An
unwritten (refused) graph states the refusal instead of a score.

### What is reused

`CanvasTransform` for pan and zoom, and the gesture shape of
`CanvasGestures`, behind a small `TreeCanvasState` of the tree canvas's own.
`CanvasState` is not reused: it states architecture selection — components,
zones, connections — and a tree canvas selects none of those.

## What is not wanted

- No new file format, and no coordinates in `.attacktree`.
- No editing of the architecture from this canvas. A tree names elements the
  architecture states; it does not create them.

## Tests

- The conversion refuses each shape in the table above, one test per row.
- A drop makes a step, and an element raising no threat makes none.
- A join makes an edge, and the edge writes the nesting the file states.
- A drawn tree and the same tree through `threatmodeller format` are the
  same bytes.
- An acceptance test draws a tree, the model rescores, and the report states
  the tree.
