# A join is an element: the handle, the menu and the selected edge

**Status:** decided, 16 September 2026.

## The problem

Issue #136 states three faults on the Attack Trees stage.

- The join handle is a 9 by 9 point circle. At the default zoom the target is
  smaller than the pointer's own hot spot. A drag that starts one point off
  moves the node.
- The edges draw as one `Path` with hit testing off. A click on an edge
  selects nothing, Delete removes nothing, and no context menu opens.
- **Cut the Outgoing Join** cuts every edge leaving one node. A person who
  wants one edge gone from a junction that feeds several loses all of them.

## The decision

### An edge is a selected thing, named `TreeGraph.Edge`

`TreeCanvasState` holds two selections: the nodes and pending elements it
already held, and the edges. `TreeGraph.Edge` is the type of both the model
and the selection, so no second name for one thing exists. The type gains
`Hashable` and `Identifiable`; its id is `<from>-><to>`.

The node selection becomes an ordered list, `selectedInOrder`. The order
states what **Join** joins: the first selected node feeds the second.
`selectedIds` stays a `Set<String>`, read from the list.

### Where an edge is drawn, and how near a click has to be

`TreeEdgeLine` holds the two points one edge draws between, the path the
canvas strokes, the path a click is tested against, and the distance from a
point to the line. The tolerance is `ConnectionPath.hitTolerance`, the one
the architecture canvas states for a flow, so a click selects a join the way
it selects a flow.

`TreeCanvasGestures.line(of:)` builds one. The view strokes
`TreeEdgeLine.drawnPath` and takes `TreeEdgeLine.hitPath` as its content
shape, so the picture and the hit region cannot drift.

### The join handle

The handle draws at 9 points, as it did. Its hit region is
`TreeLayout.joinHandleHit` (24) points square on screen at every zoom, so in
model units the side is `24 / min(zoom, 1)`.

One gesture on the node decides what a drag is.
`TreeCanvasGestures.dragChanged(on:from:to:by:)` reads the point the drag
started at: a drag that starts inside `joinHandleRect(of:)` joins, and every
other drag moves the selection. The handle draws with hit testing off, so no
child gesture races the node's own.

The node's frame grows by the handle's reach on the left and the right, so
the whole hit region sits inside the view that reads the drag.

### The menus

- **Join to…** on a node names every join the graph offers it.
  `TreeGraph.canJoin(from:to:)` states what the grammar allows: the goal
  feeds nothing, every other node feeds one node, a step holds nothing under
  it except the goal, one root feeds the goal, and no route comes back.
  `TreeGraph.joinsOffered(for:)` offers the joins the node may feed, and the
  joins it may take. A step may take nothing, so a step is offered what it
  can feed. A junction may take many, so a junction is offered the nodes that
  can feed it as well.
- **Join** on the background menu, with exactly two nodes selected, joins the
  first selected to the second.
- **Cut the Outgoing Join** stays one row for a node that feeds one node. A
  node that feeds several gets a submenu of the same title, one row per edge
  named by its far end, then **Cut every Outgoing Join**.
- The menu on an edge holds **Cut this Join** and **Delete**.

### One change, one writer

Every action calls a `TreeEditor` verb, and every verb is one `change`, so
one undo takes it back. `join` writes what the drag-join writes, because it
is the same method. `cut(_:)` removes one edge; `remove(_:edges:)` removes
the whole selection as one change.

## Tests

- The rows of **Join to…** name every node a step can feed and no other.
- A menu join and a drag join write the same bytes.
- A join drag that starts 10 points from the handle's centre draws the edge
  and moves no node.
- A click 4 points off an edge selects the edge; Delete removes that edge
  alone.
- A junction that feeds three nodes cuts one from the submenu, and two stand.
- `ViewRenderTests` draws a selected edge differently from an unselected one.
- Undo after each action restores the tree.
