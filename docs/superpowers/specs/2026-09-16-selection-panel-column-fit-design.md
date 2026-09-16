# Every selection panel fits the diagram column

**Status:** decided, 16 September 2026.

## The problem

Selecting an element on the Architecture stage draws a bar under the canvas:
`ComponentPanel`, `UserPanel`, `ZonePanel`, `ConnectionPanel` or
`MitigatesPanel`. The bar did not take the width of the diagram column. It
started at the column's own leading edge, under the palette, and ran past the
part of the column a person sees by the palette's width. Five fixes changed
where the bar was placed and each left the running application wrong.

### What the reproduction states

The application was built, launched on a sample project and measured in the
window it draws, with a component selected. macOS refuses both permissions a
screen capture needs on this machine, so the pictures come from the project
window in a hosting window, resized after the panel appears, drawn with
`NSView.bitmapImageRepForCachingDisplay`.

| Window | Palette | Diagram column | Panel |
| --- | --- | --- | --- |
| 1400 | shown | x 268, width 700 | x 0, width 968 |
| 1200 | shown | x 268, width 651 | x 0, width 919 |
| 900 | shown | x 228, width 400 | x 0, width 628 |
| 1400 | hidden | x 0, width 919 | x 0, width 919 |

### The cause

The palette floats over the diagram column. The column's own view keeps the
whole width, from the window's leading edge to the assumptions column, and
states a leading safe area of the palette's width. SwiftUI places the drawing
inside that safe area, which is what a person sees.

SwiftUI spreads a `ScrollView` across that safe area. Every selection panel is
a horizontal `ScrollView`, so wherever the panel was placed the scroller took
the whole column. A `frame`, a `safeAreaPadding`, a `fixedSize`, a `clipped`
and a stack row were each measured and none of them held the scroller: the
scroller's own view was laid out at x 0 with the column's whole width every
time. The five earlier fixes measured the panel against the split view's
arranged subview, which is the whole column, so each check passed.

## The decision

### The row keeps scrolling sideways

Every selection panel stays one row of controls that scrolls sideways. The row
does not reflow to fit.

The alternative was a row that fits: flexible field widths with minimums, or a
second row below a stated width. Neither works here.

- `ComponentPanel` holds eleven controls that need about 1500 points. The
  diagram column on a 1200-point window is about 650 points with the palette
  shown. No arrangement of one row shows every control at a width a person can
  read, so flexible widths with minimums still leave controls off the end.
- A second row changes the panel's height. The floating workflow panel lifts by
  that height (#85, #142), and the diagram loses the room the second row takes.

So the row scrolls, and every control stays reachable at every column width.

### Every selection panel is one stated height

`SelectionPanel.height` is 40 points: one row of standard controls with eight
points above and below. Every selection panel draws at that height at every
column width. The floating workflow panel lifts by that one number, so the two
never cover each other, and a narrow column never takes room from the diagram.

### A selection panel is hosted in a view of its own

`HostedSelectionPanel` puts the panel in a `SelectionPanelBarView`, an
`NSView`, and hosts the panel inside it again. A hosted view takes the frame
SwiftUI's layout gives it, and the panel inside has a safe area of its own with
nothing in it, so the scroller keeps to the part of the column a person sees.

This is the one place the rule is stated, and every selection panel goes
through it: `CanvasView.selectionPanel(inColumn:)` picks the panel for what is
selected and calls `fitsTheDiagramColumn(width:)` on it.

### The panel is drawn where the canvas toolbar is drawn

`CanvasView` draws the panel in the same `ZStack` as the canvas toolbar, at the
width its `GeometryReader` states, and not with `safeAreaInset`. The reader
measures the part of the column a person sees, in the same layout pass, so a
window resize, a palette toggle and a drag of the assumptions column all move
the panel with the column and none of them leaves the panel one layout behind.

`safeAreaInset` places its content over the whole column instead of over the
part inside the safe area, which is the second half of why the panel was wrong.

`CanvasState.visibleSize` is the reader's size less `SelectionPanel.height`
while a panel is drawn, so Zoom to Fit keeps the diagram above the panel.

## What states it

`WindowLayoutTests`:

- `thePanelFitsTheDiagramColumnAfterTheWindowIsResized` resizes the window from
  1400 to 900 points with a component selected, then drags the assumptions
  column, and states the panel's x and width equal the diagram column's within
  one point at each size.
- `thePanelFitsTheDiagramColumnAfterThePaletteIsToggled` shows and hides the
  palette with the panel on screen and states the same.
- `everySelectionPanelIsOneHeightAtEveryColumnWidth` measures all five panels at
  400, 700, 900 and 1200 points and states one height.
