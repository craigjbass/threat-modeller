# What a tree node can connect to, and a box that waits for an element

**Status:** decided, 16 September 2026.

## The problem

Issue #135. The Attack Trees stage lists every component, flow and zone of
the system in `TreeSidebar`, with the number of threats each raises. Once a
node is on the tree, the list does not change. A person who joins a step to
the goal picks from every element, and nothing says which elements an
attacker at the goal's element can reach. The language states no adjacency
rule, so the writer and `check` accept any element under any node, and a
route that no flow supports reads as a route.

A person who knows the shape of the route before the element also has no
way to draw it: every node on the canvas names an element from the moment
it is dropped.

## The decision

### What "connectable" means

An attacker at one element reaches the elements the `.arch` file joins to
it. The set is read from the flows and the zones, and from nothing else.

| The node is on | It reaches |
| --- | --- |
| a component | the element itself; every component that holds a flow to or from it, in either direction; the zone it sits in; every component in that zone; every flow that touches it |
| a zone | the element itself; every component in the zone; every flow that crosses the zone's boundary: one end in the zone and the other end outside it |
| a flow | the element itself; the two components the flow joins; the zone each of those components sits in |

The element itself is in its own set because a route may state two threats
on one element: steal a credential on the api, then use it on the api.

A component sits in the zone whose rectangle holds its centre, which is
`ViewedComponent.zoneId`. A zone holds no zone, so a zone reaches no other
zone.

`TreeElement` gains `neighbours`: the payloads of the elements this element
reaches, built once by `TreeElement.list` from the components, the flows and
the zones. Every reader of the rule reads that field, so the sidebar, the
search and the warning agree.

### The anchor of a node

The element a node is on is its **anchor**. A step's anchor is its target.
A junction has no element of its own; its anchor is the anchor of the node
it feeds, because the junction's feeders are its children and the node it
feeds is where the attacker goes next. A box (below) with an element takes
that element; a box with none takes the anchor of the node it feeds, or of
the node that feeds it when it feeds nothing. A pending element's anchor is
its element. `TreeGraph.elementPayload(anchoring:)` states the rule.

### The rank

`TreeConnectable.rank(_:from:)` puts every element in one order for one
anchor: the elements the anchor reaches first, ranked by the number of
threats each raises, most first, ties in model order; then every other
element, in model order. Each row says whether it is connectable. With no
anchor, the rows are the model order and none is marked.

The sidebar reads the rank for the one selected node. A marked row draws a
check mark in the accent colour and comes first; an unmarked row is dimmed
and still draggable. The caption above the list names the anchor.

### An outside join is allowed, and the node says so

A join to an element the anchor does not reach is **allowed with a warning
on the node**, not refused and not silent.

- Refusing would make the architecture the only way to write a route, and
  a real route may run through a channel the diagram does not draw: a
  shared credential, a person, physical access.
- Silence is the fault the issue states.

The tree writes as it did. The step that feeds a node its element does not
reach draws a warning mark on the canvas, and the selection panel on that
step states `No flow or zone joins <element> to <element>.` The warning
reads `TreeElement.neighbours` for both ends; a step whose element the
model no longer states draws no warning, because the model has nothing to
say about it.

**`check` says nothing.** The language states no adjacency rule and this
design adds none: the `.attacktree` file does not change, the parser does
not change, and a tree that holds an outside join binds, scores and gates
the way it did. The rule lives in the window, where the person who draws
the join is.

### A box: a node with no element yet

The sidebar's junction section gains a third row, **Any element**. A drag
from it drops a **box** on the canvas: `TreeGraph.Kind.placeholder(element:)`
with no element. A box is a node, so a join reaches it the way a join
reaches a step: it takes one feeder and feeds one node.

A join from a known node to a box, or from a box to a known node, selects
the box. The selection panel on a box holds the search: a text field and
the elements the known end reaches, ranked by the threats each raises. A
box joined to nothing searches every element, ranked the same way. A query
that matches nothing says `No element matches "<query>".` and offers **Show
every element**, because an outside join is allowed.

Picking an element **fills** the box: the box holds the element, the panel
offers the threats the model raises on that element, as it does for a
dropped element, and picking one makes the box a step. The step keeps the
box's id, its point and its joins. A filled box can be emptied again with
**Pick another element**.

`TreeMenu.node` on a filled box offers the element's threats before Delete,
the way the menu on a pending element does.

### A box is view state and blocks the save

A box lives in `TreeEditor.Draft`, so undo and redo put it back with
everything else. `.attacktree` holds no syntax for it, the writer never
writes one, and no `SourceTreeNode` case is added.

`TreeGraph.tree(id:...)` refuses a graph that holds a box, filled or not,
after the goal checks and before the route checks:

| Refusal | Message |
| --- | --- |
| `.unfilledBox` | `a box holds no element yet; pick one, or delete the box` |
| `.boxNamesNoThreat(element:)` | `"<element>" names no threat yet; pick one` |

The refusal holds the save the way every refusal does: the last written
tree stays in the file until the box is filled or removed. The selection
panel with nothing selected states the refusal, and the panel on a selected
box states `This box is not written. The tree is not saved until you pick
an element, or delete the box.`

## What is not wanted

- No change to the attack tree language, the parser, the writer or `check`.
- No adjacency read from anything but the flows and the zones.
- No coordinates or boxes in `.attacktree`.

## Tests

- Three components and two flows: the rank for a node on the middle
  component marks the two joined components and the two flows, and puts
  every marked element before every unmarked one.
- A box dropped and joined to the goal: the search lists the elements the
  goal's element reaches and no other, ranked by threats raised.
- An element picked from the search, then a threat: the tree holds a step
  on that element, and the file holds the bytes the sheet-era writer wrote.
- A tree with an unfilled box is not written, the refusal names the box,
  and the selection on the box states why.
- A step joined to a node its element does not reach: the tree is written
  and the panel states the warning.
- `ViewRenderTests`: a canvas with a box draws, and draws differently from
  one without; a marked sidebar row draws differently from an unmarked one.
