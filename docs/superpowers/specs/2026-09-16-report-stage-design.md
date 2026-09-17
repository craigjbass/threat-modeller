# The Report stage

**Status:** decided, 16 September 2026.

## The problem

The window holds every section the report is built from and shows none of it as
a report. A person who wants to know what the report says for the model as it
stands writes a file, opens it in another application, changes the model, and
writes the file again. `WorkStage` holds four stages: Architecture, Attack
Trees, Threats, Controls. The last thing a person does, read the report, has no
stage.

## The decision

A fifth stage, **Report**, after Controls. It draws every section of the report
as native views, in the order the project's template states, from the same
`Report` value the exporters render. It writes no file to draw.

## The stage picker

Five buttons in a row, each with a word, is wider than the diagram column. #121
already drops the stage words below 660 points, and five icons are wider than
four icons, so a segmented control of icons grows the panel at the narrow end.

**The panel uses a popup**, a menu-style `Picker`. The popup names the stage
the window draws and lists the other four. Its width is one stage name plus the
chevron, whatever the number of stages, so a sixth stage never widens the panel
either. Below 660 points the popup takes the icon alone, the way the two verbs
drop their words.

| Column width | Four-stage panel today | Five-stage panel |
| --- | --- | --- |
| 660 points and wider | four segments, each with a word | one popup, the chosen stage's word |
| under 660 points | four segments, icons alone | one popup, the icon alone |

`WorkflowPanel` takes the stages it draws and which control draws them, so
`WindowLayoutTests` measures the four-stage segmented panel and the five-stage
popup panel at the same column width and states the second is no wider.

The keys do not change shape: `ThreatModelCommands` holds one item per stage,
Cmd+1 to Cmd+5, and Cmd+5 reaches Report.

## How the stage reads the template

The stage runs the two use cases the exporters run, and no others:

1. `ReadReportTemplate`, with the project root. `CompileSystemReport` and the
   window's Markdown and HTML exports resolve the template through this same
   use case, so the stage and the file cannot drift.
2. `BuildThreatModelReport`, which gives the `Report` value every writer reads.

The response decides what the stage draws:

| Response | What the stage draws |
| --- | --- |
| `.none` | the sections of `ExportModelAsMarkdown.defaultTemplate`, which is the shape this application ships |
| `.found(template, path)` | the sections that template names, in the order it names them |
| `.missing(path)` | the fault, in place of the sections, because the export writes nothing either |
| `.didNotParse(path, diagnostics)` | each diagnostic, in place of the sections |

`ReadReportTemplateResponse.found` carries the path it read, so the right
sidebar names the file the project renders through.

A slot the template leaves out is not built, so a reader sees on the stage what
the file will hold. A section the template names and the report has nothing for
writes nothing, the same rule the Markdown writers keep.

## What a section is

A section is a value, not text:

```swift
struct ReportStageSection {
    let slot: ReportTemplate.Slot
    let title: String
    let blocks: [ReportBlock]
}

enum ReportBlock {
    case heading(String)        // a "##" heading of the report
    case subheading(String)     // a "###" heading
    case lead(String)           // a bold line the report writes above a list
    case paragraph(String)
    case bullets([ReportBullet])
    case numbered([ReportBullet])
    case table(ReportTable)
    case fenced(kind: String, text: String)
}
```

`ReportStagePage.build(report:template:)` fills one section per slot from the
`Report` value. It reads the same fields the Markdown writer reads, keeps the
same headings, and keeps the same "nothing" line: Attack paths with no path
shows `None.`, the full threat register with no threat shows `None.`, and a
section the report writes nothing for is left out rather than shown empty.

Nothing on the stage reads Markdown or HTML. `ReportSectionView` draws a block:
a heading is a `Text` in the heading font, a table is a `Grid`, a fenced block
is monospaced text in a box.

## What a diagram section shows

**Superseded on 17 September 2026 by
`docs/superpowers/specs/2026-09-17-report-stage-pictures-design.md`.** The
stage draws a `mermaid` block as a picture, and shows the text only for a
kind the window does not draw.

## The sections the stage leaves out

**Superseded on 17 September 2026 by
`docs/superpowers/specs/2026-09-17-report-stage-pictures-design.md`.** The
stage draws `threat_pictures`, `risk_over_time` and `what_changed`, and
`Generate Report` passes the pictures and the history to
`CompileSystemReport`.

## The columns

Three columns, the shape the other stages use.

- **Left**: the sections the template names, in order. A click scrolls the
  middle column to that section. The list names each section by its first
  report heading.
- **Middle**: the sections, one after another, in template order.
- **Right**: `Generate Report`, the format picker, the template the project
  renders through, and the path the last report was written to.

The format picker states which file `Generate Report` writes:

| Format | Where it goes |
| --- | --- |
| Markdown | the system's report path in the project, with no save panel, which is the file `threatmodeller compile` writes |
| HTML | a file the person names in a save panel |
| PDF | a file the person names in a save panel |

The right sidebar names the path after each write, so a person knows which file
to open. The floating panel keeps its own `Generate Report`, which writes
Markdown, and both write the same bytes the File menu's **Export as Markdown**
writes.

## What this does not do

- It does not edit the report. A section is read on this stage and changed on
  the stage that owns it.
- It does not render a template's own words. The template's text lines are the
  team's Markdown, and the stage draws the sections, not the wrapper.
- It drew no picture until 17 September 2026. See the pictures design.
