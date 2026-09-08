# Carry-forward into Milestone 8

What Milestone 7 deliberately did not fix.

## Closed in Milestone 7

- The external actors: nine of them, app-owned data outside the vendored
  `Library/` directory, so a catalogue tag bump cannot remove the person using
  the system from a diagram.
- Custom technologies: `CreateCustomTechnology`, `EditCustomTechnology`,
  `DeleteCustomTechnology`, `ViewCustomTechnology` and `ListThreatChoices`, an
  editor sheet, and the palette group they sit in.
- `TechnologyLookup`: the model wins over the catalogue, in one place, and
  every reader asks it — `AddComponent`, `ViewThreatModel`,
  `ListTechnologies`, `ListPathwayMitigations`, `ThreatResolver` and the drift
  check in `OpenThreatModel`.
- Document format version 2, which reads version 1.
- Item 18 of the Milestone 7 list: the format now has a migration path, and it
  has been used once.

## Still open, unchanged

The defect found in Milestone 6B stands:

1. **Drawing a zone leaves more than one undoable change.** One undo does not
   remove the zone; two do, and the second also removes the component added
   before it. `CanvasGestures.zoneDragEnded` refuses to commit a move unless a
   move was started, which is correct on its own and did not fix this. Find the
   second change by logging every use case the session calls during one zone
   drag.
2. **The user interface journey no longer walks an undo.** Put it back once
   item 1 is fixed.

Items 3, 4, 6 to 17, 19 and 20 to 22 of the Milestone 7 carry-forward stand as
written. Item 5 stands and is still the largest gap: every risk score acts on a
sensitivity the user cannot set.

## New in Milestone 7

23. **A custom technology's threats are found by walking every technology in
    the catalogue.** `TechnologyLookup.everyThreat()` builds the whole index on
    every call. At 277 technologies that is wasteful, and `ListThreatChoices`
    does the same walk again. Add `allThreats()` to the `TechnologyCatalogue`
    port if the suite's time moves.

24. **A custom technology carries no controls of its own.** It reuses the
    catalogue's threats, and a threat carries the controls, so a user's own
    service offers exactly the controls of the threats they chose. A user who
    wants to record a control their service alone has cannot.

25. **Deleting a custom technology is not confirmed.** It deletes the
    components using it, their connections and their control ticks, from a
    context menu, with only undo to take it back.

26. **The editor's category list comes from the palette**, so it can only offer
    a category some technology already sits in. An empty catalogue category is
    invisible to it.

27. **Nothing stops two custom technologies sharing a name.** The identifier is
    generated, so the model stays correct, but the palette shows two rows a
    user cannot tell apart.

28. **A custom technology cannot cross documents.** Copy carries components,
    connections and zones; paste into another document produces a component
    whose technology that document does not define, and the drift report is
    what says so.
