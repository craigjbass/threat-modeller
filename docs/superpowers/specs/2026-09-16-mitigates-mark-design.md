# The mitigates mark on the canvas

**Status:** decided, 16 September 2026.

## The problem

A `mitigates` edge states that one component lowers a threat set on another.
`MitigatesPanel` and `MitigatesSheet` write the edge, and `AssumptionsPanel`
lists every edge read-only. No drawing code reads `canvas.mitigations`, so
the canvas shows nothing between the protector and the protected component.
A reader opens one panel per pair to see the protection structure.

## The decision

### The mark

The canvas draws one mark for each `mitigates` edge. The mark is not a flow
and never carries an arrowhead.

| Part | Value |
| --- | --- |
| shape | one quadratic curve from the protector's box edge to the protected's box edge |
| bow | the control point sits `MitigatesGeometry.bow` (34) model units off the straight line, on the perpendicular |
| colour | teal, or the accent colour while both ends are selected |
| line width | 3, and 4 while both ends are selected |
| badge | a shield 18 wide and 20 tall, centred on the point at t = 0.5 |

The bow moves the mark off the straight line between the two boxes, so a
flow between the same pair and the mark never lie on each other.

A flow draws a thin cubic curve with an arrowhead, in the risk colour. The
mark draws a thick teal bowed curve with a shield and no arrowhead. The two
marks share no colour, no width and no end shape.

### `assumed` against `adopted`

| Status | Curve | Shield |
| --- | --- | --- |
| `adopted` | solid | filled with the mark's colour |
| `assumed` | dashed, 6 on and 4 off | filled with the window background, outlined in the mark's colour with a 3 on 3 off dash |

An adopted edge lowers the score today. An assumed edge states what a team
would run, so the mark is drawn broken and hollow, the way an assumed guard
chip is drawn broken at a boundary.

### What a click on the mark does

`CanvasGestures.backgroundTap` reads the flows first, then the mitigates
marks, then the zones. A click on a mark selects both of the edge's
components. Two selected components is what `CanvasView` already shows
`MitigatesPanel` for, so the same bar the assumptions panel names the edge
in opens under the canvas, with its Edit and Remove buttons.

`MitigatesGeometry.ordered` puts the protector first when an edge runs
between the two selected components. Without it the bar names the pair in
model order, which reverses the sentence and hides the edge the pair holds.

### Where the code sits

| File | What it holds |
| --- | --- |
| `threatmodeller/canvas/MitigatesGeometry.swift` | the marks, the shield, the hit test and the pair order. A pure value, no view. |
| `threatmodeller/canvas/ConnectionsLayer.swift` | draws the marks under the callouts |
| `threatmodeller/canvas/CanvasGestures.swift` | the click |
| `threatmodeller/reporting/CanvasPicture.swift` | the exported image draws the same marks |

The exported image draws through `CanvasPicture`, which draws the same
`ConnectionsLayer`, so the picture and the canvas hold one drawing rule.
