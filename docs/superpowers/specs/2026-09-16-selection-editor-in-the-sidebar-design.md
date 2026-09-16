# The selection editor lives in the right sidebar

**Status:** decided, 16 September 2026.

## The rule

**The right sidebar of a diagram stage holds the editor for what is selected,
and its default content when nothing is selected.**

That is the whole rule. The Attack Trees stage already follows it:
`TreeSelectionPanel` sits in the detail column and draws the selected node.
The Architecture stage now follows it too.

## The problem

Selecting an element on the Architecture stage drew a bar under the canvas:
`ComponentPanel`, `UserPanel`, `ZonePanel`, `ConnectionPanel` or
`MitigatesPanel`, each a horizontal `ScrollView` placed with
`safeAreaInset(edge: .bottom)`. The bar never took the width of the diagram
column. Six changes moved it or measured it and each left the running
application wrong.

| Commit | Date | What it changed |
| --- | --- | --- |
| 6c728b3 | 09-15 | the sidebar and the bottom bars fit the columns they live in |
| 9ac1cc4 | 09-15 | the stage panel clears the selection panel under the canvas (#85) |
| 3acea2e | 09-15 | every selection panel keeps its controls inside the canvas column (#90) |
| 5369057 | 09-15 | the panels hide their scroll indicator |
| 8a7700b | 09-16 | the canvas toolbar and the workflow panel lay out from the column width (#121) |
| 4b7e7de | 09-16 | the workflow panel drops its lift on the Controls stage (#142) |

### What the measurement on `wip/143-selection-panel-width` found

The application was built, launched on a sample project and measured in the
window it draws, with a component selected. Frames in window coordinates:

| Window | Palette | Diagram column | Panel |
| --- | --- | --- | --- |
| 1400 | shown | x 268, width 700 | x 0, width 968 |
| 1200 | shown | x 268, width 651 | x 0, width 919 |
| 900 | shown | x 228, width 400 | x 0, width 628 |
| 1400 | hidden | x 0, width 919 | x 0, width 919 |

The palette floats over the diagram column. The column's own view keeps the
whole width and states a leading safe area of the palette's width. SwiftUI
spreads a `ScrollView` across that safe area, so every selection panel took
the whole column. Nine placements were measured and none of them held the
scroller: `safeAreaInset(edge: .bottom)`, `safeAreaPadding(.horizontal)`, an
explicit `frame(width:)`, `fixedSize`, `clipped`, `compositingGroup`, a row
of a `VStack`, a `GeometryReader`, and a plain background.

`docs/superpowers/specs/2026-09-16-selection-panel-column-fit-design.md` on
that branch holds the full record. The branch is superseded. Its measurement
is the reason this design moves the editor rather than placing the bar a
tenth time.

### The second fault the bar carried

A bar under the canvas is one row. `ComponentPanel` holds eleven controls
that need about 1500 points, and the diagram column on a 1200-point window is
about 650. A person reached a control by scrolling the row sideways, with no
sign that the row scrolled. A column is the shape that fits a form.

## The decision

### What the right sidebar shows, by selection

The Architecture stage's detail column is `SelectionSidebar`. It reads
`CanvasSelection.of(session:canvas:)`, which states one case:

| Selection | Case | What the column draws |
| --- | --- | --- |
| nothing | `.nothing` | the default content |
| one component | `.component` | `ComponentPanel` |
| one user | `.user` | `UserPanel` |
| one zone | `.zone` | `ZonePanel` |
| one flow | `.connection` | `ConnectionPanel` |
| two or more elements | `.several` | the multi-selection view |

`CanvasSelection` states the words a test reads, the way `TreeSelection` does,
so a test states what the column shows without a window.

### The editors are columns, one field per row

`ComponentPanel`, `UserPanel`, `ZonePanel`, `ConnectionPanel` and
`MitigatesPanel` keep their name, their fields, their accessibility
identifiers and their write-through. Each one changes from a horizontal
`ScrollView` of one row to a vertical `ScrollView` of fields, the shape
`TreeSelectionPanel` already draws. Every flow test that drives a panel keeps
passing, because only the body changed.

`SelectionEditor` is the shape: a scrolling column with a heading and one
field per row, with 16 points of padding. `SelectionField` is one field: its
label, then the control under it. The sidebar is 280 points at its narrowest,
so a label above its control leaves the control the column's whole width, and
no control states a width of its own.

### The multi-selection view

Two or more selected elements draw a short view, not the default content:

- a line per kind with the count: "2 components", "1 zone";
- **Merge…** when every selected element is a component and none is a user,
  which is the condition #124 states for the context menu. The button calls
  `CanvasState.startMerging`, so the merge sheet the context menu opens is
  the sheet this button opens;
- the mitigates row, when exactly two components are selected and neither is
  a user. `MitigatesPanel` is that row. One component lowering a threat on
  another is a fact only a two-component selection can state, so the editor
  for it belongs in the view that two components draw;
- **Delete**.

### Deselecting keeps the default content's scroll position

The default content is a long scroll. A person who scrolls to the exclusions,
clicks a component and clicks the background again must get the exclusions
back, not the top.

`SelectionSidebar` draws the default content and the editor in one `ZStack`
and hides the one that is not in front with `opacity` and `allowsHitTesting`.
The default content therefore stays in the view tree while an editor is in
front, and its `ScrollView` keeps the offset it had. Removing the view and
building it again loses that offset, so the view is never removed.

The hidden view takes `accessibilityHidden(true)`, so a screen reader reads
one of the two and never both.

### The Threats stage keeps its threat list

The Threats stage draws the diagram and the threat list side by side. A
selection on that diagram changes nothing in the right column: the threat
list stays.

The reason is what each stage is for. The Architecture stage is where a
person draws and describes the system. The Threats stage is where a person
reads the threats that architecture raises and answers them. An editor that
covered the threat list would take away the one thing the stage exists to
show, and a sheet over the diagram would cover the picture the list is about.
Every verb on an element stays reachable on the Threats stage through the
context menu, and the stage picker reaches the editor in one click.

### How #145's sheets share the column

#145 moves most of the sidebar's ten editors into sheets opened from a
**System** menu. The two designs meet on one rule:

- **The column holds one of two views: the default content, or the selection
  editor.** Nothing else goes in the column.
- **A sheet is a third surface. It covers the window and never takes the
  column.** A sheet stays open while the selection changes under it, and the
  column changes under the sheet.
- **`SelectionSidebar.defaultContent` names the default content in one
  place.** Today it is `AssumptionsPanel`. #145 changes what that view holds
  and changes nothing here.

The rule that sorts an editor is the one #145 states: what a person reads
while drawing stays in the column, and what a person writes once per system
moves to a sheet. A selection editor is neither: it belongs to the element in
front of the person, so it takes the column only while that element is
selected.

### What goes

The bottom panel and every mechanism that measured or lifted over it:

- `CanvasView`'s `safeAreaInset(edge: .bottom)` group;
- `CanvasState.selectionPanelHeight`;
- `WorkflowPanel.lift(over:)`, `reservedRoom`, `gapAboveSelectionPanel`,
  `selectionPanelRect(in:height:)` and the `liftedBy` property, with the
  plumbing #85 and #142 added through `ProjectColumns`;
- `SelectionPanelHeightTests`, and the `WindowLayoutTests` cases that
  measured the bar;
- `SelectionPanelColumn` from `wip/143-selection-panel-width`, which is never
  merged.

`WorkflowPanel.bottomMargin` and `WorkflowPanel.reservedHeight` stay. The
floating panel sits `bottomMargin` above the bottom of the column it floats
over, on every stage, and the column keeps `reservedHeight + bottomMargin`
under the canvas so nothing the canvas draws hides under the panel.

## Tests

- `WindowLayoutTests.theRightSidebarHoldsTheEditorForTheSelectedElement`
  selects a component at 900, 1200 and 1400 points, palette shown and
  hidden, and after a window resize, and states the component editor is in
  the detail column at the column's width; deselects and states the default
  content is back.
- `WindowLayoutTests.theWorkflowPanelKeepsTheMarginOnEveryStage` states the
  panel's bottom edge is `WorkflowPanel.bottomMargin` above the column on the
  Architecture stage with a component selected, and on the Controls stage.
- `SelectionSidebarTests` states `CanvasSelection.of` for each selection and
  that two components offer Merge.
  `WindowLayoutTests.theDefaultContentStaysInTheTreeWhileAnEditorIsInFront`
  states the default content keeps its place in the view tree, and with it
  its scroll position.
- `ViewRenderTests` draws the sidebar with the default content, with a
  component editor and with the multi-selection view.
- `NoBottomSelectionPanelTests` reads every file under `threatmodeller/` and
  states none of them holds `selectionPanelHeight` or
  `safeAreaInset(edge: .bottom)`.
- Every flow test that drives `ComponentPanel`, `UserPanel`, `ZonePanel`,
  `ConnectionPanel` or `MitigatesPanel` passes with no change.
