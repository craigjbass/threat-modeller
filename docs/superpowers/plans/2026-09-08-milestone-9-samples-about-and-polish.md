# Milestone 9: Samples, About and attribution, theming, app icon, polish

Spec line: **Samples, About and attribution, theming, app icon, polish.**

## The decisions this milestone fixes

1. **A sample is a document, not a script.** Each sample is a version 2 document
   file in the application bundle, read by the same codec a user's own file goes
   through. A sample that stopped opening would be a document format defect,
   found by the same test.

2. **Loading a sample replaces the model in front of the user.** It is one
   undoable change, so a user who did not mean it presses ⌘Z.

3. **The About window carries the licence obligations.** Spec §7: this
   application ships a `NOTICE`, surfaces both attributions, and names the
   vendored catalogue's repository and tag. The tag comes from
   `TechnologyCatalogue.version()`, so it cannot fall out of step with what is
   assessed.

4. **The component inspector closes the sensitivity gap.** Until now every risk
   score acted on `internal`, because nothing could set anything else.
   `RenameComponent`, `SetComponentSensitivity` and `DisableComponentThreats`
   give the node panel what the zone panel already has.

5. **Colour is named once.** `RiskPalette` maps a risk level id to a colour, and
   the sidebar, the summary strip and the nodes all read it. Every colour is
   drawn from the system palette so both themes work without a second set.

6. **The application icon is drawn by a script, not by hand.** `scripts/make-icon.swift`
   renders the mark at every size the `.appiconset` asks for, so a change is one
   command rather than eleven exports.

## Tasks

### Task 1: `SampleModelGateway`, `ListSampleModels` and `LoadSampleModel`
The port, the bundled documents, a fake, and a shared contract run against both.

### Task 2: the samples browser
A sheet from the File menu listing each sample with its description. Opening
one replaces the model in front of the user.

### Task 3: `RenameComponent`, `SetComponentSensitivity`, `DisableComponentThreats`
Three use cases and their tests, then a node panel beside the zone panel.

### Task 4: the About window
Version, catalogue repository and tag, both attributions, and the MITRE notice.

### Task 5: `RiskPalette` and the themes
One colour source, read by every view that shows risk.

### Task 6: the application icon
A script that draws the mark, and the `.appiconset` it fills.

### Task 7: acceptance and interface tests
`StartingFromASampleTests`, the component inspector's tests, and an interface
journey that opens a sample and changes a component's sensitivity.
