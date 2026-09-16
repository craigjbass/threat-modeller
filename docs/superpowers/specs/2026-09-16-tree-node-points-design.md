# Where a tree node sits: a stored point, not an offset

**Status:** decided, 16 September 2026.

## What this replaces

`2026-09-16-attack-tree-stage-design.md` states two lines this design
replaces:

- the drag row of the shared gesture table: "the tree canvas keeps the hold
  in `TreeCanvasState.held`";
- the context menu line: "Lay Out Tree clears every hold, so the derived
  layout is drawn again".

Everything else in that design stands. `TreeGraph.positions` does not
change: the layout function is the same function, called at fewer times.

## The problem

A node's drawn point is a derived layout plus a held offset:
`TreeCanvasGestures.position(of:)` reads `laidOut[id]`, then adds
`canvas.held[id]` and the drag in flight. `laidOut` comes from
`TreeGraph.positions`, which reads the graph. A join, a cut, a delete, a
Set as Goal and a threat pick all change the graph, so every node's base
point moves. A node a person placed by hand keeps an offset from a base
that is now somewhere else, so the node jumps on X and Y. The person did
not drag that node.

## The decision

### A node holds its own point

Each node holds one point, in model units, for the centre of the node. The
point is the whole answer to "where does this node sit". Nothing is added
to it but the drag in flight.

A new type `TreeLayout` holds the points by node id, and the metrics the
canvas draws with:

| Member | What it is |
| --- | --- |
| `points` | the point of each node, by id |
| `point(of:)` | the point of one node, or nil |
| `place(_:at:)` | puts one node at one point |
| `move(_:by:)` | moves the named nodes by one distance |
| `placeUnplaced(in:)` | gives a point to each node of the graph that has none |
| `retainOnly(_:)` | drops the points of nodes the graph no longer holds |
| `layOut(_:)` | every node takes the point the graph's layout states |
| `nodeSize`, `junctionSize`, `horizontalGap`, `verticalGap`, `margin` | the metrics, moved here from `TreeCanvasGestures` |

The type is small and named so the next canvas issues read one name for a
node's point.

### The point is view state for the open window

The point lives in `TreeEditor.Draft`, beside the graph, the pending
elements, the name, the description and *raises risk by*.

`TreeEditor` is view state for the open window, the way `CanvasState`
holds the tag filter: the window owns one, a change of stage keeps it, and
closing the tree drops it. A sidecar file is not used. The reason is the
history: `TreeEditor.change` snapshots the whole draft before every change,
so a point inside the draft is undone and redone with no new machinery, and
an undo of a join restores the graph and the points together.

`TreeEditor.save` reads the graph, the name, the description and *raises
risk by* alone. A point reaches no written value, so the `.attacktree`
bytes do not change.

### When the layout runs

`TreeGraph.positions` runs at two times, and at no other:

1. **Lay Out Tree.** The menu item calls `TreeEditor.layOutTree()`, which
   is one change labelled "Lay Out Tree". Every node takes the layout's
   point. Undo puts the old points back.
2. **A node with no point.** `TreeEditor.open` gives every node of the
   opened tree the layout's point, because the file states no point. Each
   later change gives a point to any node that has none, so a node the
   graph gains keeps a place to sit. A node that has a point keeps it.

A drop gives its node a point at once, so the layout never runs for it: a
junction takes the drop point, and a pending element takes the drop point
in `PendingElement.point`. Picking a threat on a pending element puts the
new node at the pending element's point, so the picked node does not move.

### A drag is one change

`TreeCanvasGestures.nodeDragEnded` calls `TreeEditor.move`, which is one
change labelled "Move". The drag in flight stays in
`TreeCanvasState.dragTranslation`, so the picture follows the pointer with
no history written until the drag ends.

`TreeCanvasState.held` and `TreeCanvasState.layOutAgain()` are deleted.
`TreeCanvasState.retainOnly` keeps the selection alone.

## What is not wanted

- No coordinates in `.attacktree`, and no sidecar file.
- No change to `TreeGraph.positions` or to `TreeGraphTests`.
- No layout on a join, a cut, a delete, a Set as Goal or a threat pick.

## Tests

- Three nodes placed by drag, then a join: every point is unchanged.
- A join, then a cut of that join: every point is unchanged after both.
- A delete, a Set as Goal and a threat pick: the points of the nodes that
  stand are unchanged.
- A drop: the node sits at the drop point.
- An opened tree the window has not placed: the nodes take the layout's
  points, and a later join keeps them.
- Lay Out Tree: the nodes move to the layout's points; undo puts the old
  points back.
- Undo of a join: the graph is restored and no node moves.
- `TreeGraphTests` stay green, unchanged.
