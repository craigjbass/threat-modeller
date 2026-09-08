# Milestone 8: Reporting

Spec line: **Reporting — Markdown, threatcl HCL, PDF, PNG.**

A threat model is read by people who never open this application. Milestone 8
turns a saved model into four things a team can put in a pull request, a wiki, a
ticket or a slide.

## The decisions this milestone fixes

1. **One report tree, four outputs.** `BuildThreatModelReport` returns a pure
   value tree. Markdown, threatcl and PDF all read that tree; none of them reads
   the gateway. One place decides what a report says, and three places decide
   how it looks.

2. **The report is the assessment, not the file.** It carries what the sidebar
   shows — the threats with their scores, controls and sources — because that is
   what a reader needs. It does not carry positions, because a reader does not
   place components.

3. **Markdown is written by hand, not by a library.** The output is a document a
   team reviews in a pull request, so its shape is pinned by tests, character
   for character, the same way the document format is.

4. **threatcl is a third-party format and this application honours its shape.**
   `spec_version`, one `threatmodel` block, `information_asset` blocks for the
   components, and one `threat` block per assessed threat with `stride`,
   `impacts` and `control`. HCL string escaping is this application's own and
   is tested on its own.

5. **The PDF is rendered by a gateway, and its layout is not unit tested.** The
   `ReportRenderer` port accepts the report tree and returns PDF bytes. The
   integration test asserts the bytes are a PDF, the page count is at least one,
   and the model's name appears in the extracted text. Page layout is checked by
   eye, as spec §12 says.

6. **The PNG is the canvas as drawn, so the delivery mechanism renders it.**
   `ExportModelAsImage` returns the file name and the drawn size the exporter
   should use. `CanvasImageRenderer` in the app target turns the canvas view
   into PNG bytes. A use case never holds a bitmap.

7. **Every export is offered from the File menu and writes through a save
   panel.** The user chooses the path. Nothing writes a file the user did not
   name.

## Tasks

### Task 1: the report value tree and `BuildThreatModelReport`
`Report`, `ReportSummary`, `ReportComponent`, `ReportConnection`, `ReportZone`,
`ReportThreat`, `ReportControl`. The use case reads `ViewThreatModel`'s data,
`ThreatResolver` and `SummariseRisk` through the same gateway and catalogue the
rest of the application uses. Unit tests: an empty model, a model with one
component, and a model whose threats carry controls and sources.

### Task 2: `ExportModelAsMarkdown`
Headings for the model, the summary, the components, the connections, the zones
and the threats. Tests pin the exact text.

### Task 3: `ExportModelAsThreatcl`
The HCL shape of decision 4, plus escaping tests.

### Task 4: `ReportRenderer` port and the PDF gateway
The port in the kit; `PDFReportRenderer` in the app target over Core Graphics.
An integration test in the app test target.

### Task 5: `ExportModelAsImage` and `CanvasImageRenderer`
The use case returns the file name and the drawn size. The renderer turns the
canvas into PNG bytes with `ImageRenderer`.

### Task 6: the File menu and the save panel
Four commands: Export as Markdown…, Export as threatcl…, Export as PDF…,
Export as Image…. Each opens `NSSavePanel` with the right content type and a
name taken from the model.

### Task 7: acceptance test `ReportingAThreatModelTests`
Build a model, export it four ways, and read each output back.

### Task 8: the interface journey
Open the File menu and prove the four export commands are there and enabled
with a model on the canvas.
