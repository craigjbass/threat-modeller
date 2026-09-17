# The Report stage draws the pictures

**Status:** decided, 17 September 2026.

This replaces two sections of
`docs/superpowers/specs/2026-09-16-report-stage-design.md`: "What a diagram
section shows" and "The sections the stage leaves out".

## The problem

The Report stage draws the report's text and leaves its pictures out. The HTML
export draws all of them: the data-flow diagram under the title, one picture
per top residual threat, one picture per control, the risk-over-time graph, and
a `mermaid` block as a block a page renders. A person reads the stage to know
what the report will say, and a report with the pictures cut out says less.

The stage left them out for one reason: `Generate Report` from the window ran
`CompileSystemReport`, which passed no pictures and no history, so the file
held none of them either. That reason is removed here.

## The decision

The stage draws every graphic the HTML export draws, from the same bytes.

| What the export draws | What the stage draws |
| --- | --- |
| the whole diagram as SVG under the title | `CanvasPicture`, at the area `ExportModelAsImage` states |
| one SVG per top residual threat | the same SVG, as an image |
| one SVG per control | the same SVG, as an image |
| the risk-over-time graph as SVG | the same SVG, as an image |
| a `mermaid` block | the same text, drawn by the native renderer below |
| a `d2` block | the text, with a line saying the window draws no D2 |

## One picture set for the window and for the executable

`ReportPictures` (`ThreatModelKit/Sources/DiagramRendering/ReportPictures.swift`)
draws the whole set once, from the model and the report:

```swift
ReportPictures.of(model:report:stem:history:)
```

It answers the threat pictures, the control pictures, the SVG of each by file
name, the whole diagram as SVG, and the risk-over-time graph with the name the
report links it under. The executable's `report` verb calls it, the window's
HTML export calls it, and the window's `Generate Report` calls it, so no
caller can draw a different set.

## How the window passes the pictures to `CompileSystemReport`

`CompileSystemReportRequest` carries what the executable passes to
`ExportModelAsMarkdown`: the threat pictures by file name, the control
pictures by file name, the bytes of each file, the risk-over-time picture, the
history rows and the change. `CompileSystemReport` writes each picture file
beside the report, then writes the report. A caller that passes none gets the
report it got before, so the use case stays usable with nothing drawn.

The window fills the request from `ReportPictures`. The SVGs come from the
same drawing code the executable runs, because the window and the executable
both read `ReportPictures`, so the file the window writes and the file a build
writes hold the same figures.

The history the window passes is the history the person sampled in the History
sheet. `ProjectSession` owns one `HistorySession` per open root, the sheet
reads it, and the Report stage reads the same rows. A window that sampled
nothing passes no rows, and the report writes no Risk over time section, the
way a project with one commit writes none.

## The mermaid renderer

**The window draws mermaid natively. It uses no `WKWebView`.**

A `WKWebView` needs the mermaid script, and the HTML page this application
writes loads none: the page holds its own pictures and its own stylesheet so
that it opens from any folder with no network. Carrying a megabyte of
third-party JavaScript in the application bundle to draw a diagram block, and
paying a WebKit content process to draw it, buys less than drawing it.

`MermaidDrawing` (`ThreatModelKit/Sources/DiagramRendering/MermaidDrawing.swift`)
reads the flowchart subset and answers a `DiagramDrawing`, which is the value
`SvgWriter` already writes SVG from. So a mermaid block reaches the stage the
way a threat picture does: SVG bytes, drawn as an image.

What the reader reads:

| Mermaid | Read as |
| --- | --- |
| `graph <direction>`, `flowchart <direction>` | the header; `TD`, `TB`, `LR`, `RL`, `BT` |
| `id`, `id[text]`, `id(text)`, `id([text])`, `id[[text]]`, `id((text))`, `id{text}`, `id{{text}}`, `id>text]` | one node, with its label |
| `A --> B`, `A --- B`, `A -.-> B`, `A ==> B` | one edge, with an arrow head when the mermaid states one |
| `A -->\|text\| B`, `A -- text --> B` | one edge, with its label |
| `A --> B --> C` | two edges |
| `subgraph id [title] \u{2026} end` | a titled box around the nodes declared inside it |
| `%%` comment, `classDef`, `class`, `style`, `linkStyle`, `click`, `direction` | nothing |

The layout is by rank: a node with no edge into it sits in rank zero, and
every other node sits one rank past the deepest node that reaches it. A cycle
stops the walk, so a graph that loops still draws. Ranks run down the page for
`TD`, `TB` and `BT`, and across it for `LR` and `RL`.

**Text the reader cannot read draws nothing.** A block with no node in it, or a
mermaid diagram of another type (`sequenceDiagram`, `classDiagram`, `erDiagram`,
`stateDiagram`, `gantt`, `pie`, `journey`, `mindmap`), answers nil. The stage
then shows the source text with a line saying the window does not draw that
kind, which is what it shows for `d2`.

## What a section holds now

`ReportBlock` gains three cases:

```swift
case picture(label: String, svg: String)
case dataFlow
case sampleHistory(String)
```

`.dataFlow` is the whole diagram, and the stage draws it with `CanvasPicture`
rather than with the SVG. The SVG is written by `SvgWriter` for a reader with
no application; the window has the canvas, and the canvas draws the mitigates
marks and the status marks the export draws. `CanvasImageRenderer` draws the
same view for the image export, so the stage's picture and the exported image
are the same pixels.

`.picture` is SVG bytes the exporter wrote, drawn through `NSImage`, which
reads SVG on macOS 26. Nothing in the window re-draws a threat picture, so the
stage and the file cannot drift.

The sections that were left out are built now:

- `threatPictures` draws the heading, one subheading and picture per drawn
  threat, the residual score line, what does not answer the threat, and what
  reduces it. It reads the same fields `MarkdownThreatPictures` reads.
- `riskOverTime` draws the graph and the table of sampled commits, with the
  same columns the Markdown writer writes. With no row sampled it says so and
  offers the sampling action, which is the read the History sheet runs.
- `whatChanged` draws what changed since the newest sampled commit, from the
  same `RiskChange` the Markdown writer reads.
- `protectionDependencies` draws each control's picture above the rows about
  that control.

## The column fits the picture

A picture is drawn at its own size and scaled down to the width of the reading
column. It is never scaled up: a small picture stays small rather than turning
into a blurred one. The data-flow diagram is the report's area, which is wider
than the column on most models, so it fits the width.

## The kinds a diagram block states

The architecture language takes one kind, `mermaid`, so no project holds a
`d2` block today. The stage still reads the kind rather than assuming one: a
kind it does not draw keeps its text, with a line naming the kind, so a kind
added to the language later shows its text rather than nothing.

## What this does not do

- It does not draw D2. A `d2` block shows its text.
- It does not sample the history by itself. Sampling compiles the model once
  per commit, so a person asks for it.
- It does not edit a diagram block. A diagram is written on the stage that
  owns it.
