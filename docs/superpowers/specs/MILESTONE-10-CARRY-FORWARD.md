# Carry-forward after Milestone 9

What Milestone 9 closed, and what still stands.

## Closed in Milestone 9

- Three bundled examples, a `SampleModelGateway` port with a shared contract
  run against the fake and the bundle, and a browser to open one. A sample is a
  document read by the codec a user's own file goes through.
- `SetComponentProperties`, and the node panel that writes through it. This
  closes item 5 of the earlier lists: a user can now set a component's name,
  its data sensitivity and whether it raises threats at all. Every risk score
  no longer acts on `internal` alone.
- The About window: the version, the vendored catalogue's repository and tag
  read from the catalogue itself, both attributions and the MITRE notice.
- `RiskPalette`: one colour per risk level, read by the summary strip and the
  threat cards.
- The application icon, drawn by `scripts/make-icon.swift` at all ten sizes.
- Two interface journeys: opening an example, and selecting a node to read its
  panel. That is the first interface coverage of node selection.

## Still open

1. **Drawing a zone leaves more than one undoable change.** Unchanged since
   Milestone 6B. One undo does not remove the zone; two do, and the second also
   removes the component added before it. Find the second change by logging
   every use case the session calls during one zone drag.
2. **The interface journey no longer walks an undo.** Put it back once item 1
   is fixed.
3. **Three catalogue faults tied to a tag bump**: the dangling threat id
   dropped by `compactMap`, the trap on a duplicate technology id, and the fake
   disagreeing with the real gateway on a duplicate id.
4. **`IdentityGenerator` has no shared contract.**
5. **`LabelConnection` is unwritten**, so "double-click a connection to edit
   its label" is the one line of keyboard parity not met.
6. **`ContentView` shows `String(describing: error)`** when the catalogue fails
   to load.
7. **The palette has no keyboard path and no search**; pan needs the Command
   key; zoom needs a pinch or a button. Spec §9 asks for palette search.
8. **The resolver runs twice per change and is unmeasured**, and the history
   holds up to a hundred whole-model snapshots per document.
9. **A zone is selected one at a time; zone drawing order cannot be changed;
   the zone name field, the node name field and the mitigation slider write on
   every keystroke or step.**
10. **No interface test covers node drag, marquee, connection drawing, zone
    move, zone resize or undo.**
11. **Nothing prunes a control key whose description has left the catalogue.**
12. **A technology named `connection` or `zone` would collide with the override
    key shapes.**
13. **A severity override is keyed by technology.** Spec §5.3.
14. **The application saves its split-view arrangement and nothing validates
    it.**
15. **`ThreatCard` has no grouping; the sidebar has no filter and no search.**
16. **Two pathway mitigations answering one threat give the stronger, not the
    sum; a zone threat is never pathway-mitigated; the mitigation defaults are
    ours.**
17. **The drift banner is dismissed per window and offers no way to act on what
    drifted.**
18. **The session's clipboard tests use the real system pasteboard.**
19. **`CommandGroup(replacing: .pasteboard)` removes the standard Cut, Copy and
    Paste everywhere.** The zone name field and the node name field have not
    been checked by hand for ⌘V.
20. **Pasting carries no ticks and no overrides.**
21. **A custom technology's threats are found by walking every technology in
    the catalogue**, and `ListThreatChoices` walks them again.
22. **A custom technology carries no controls of its own.**
23. **Deleting a custom technology is not confirmed.**
24. **The custom technology editor's category list comes from the palette.**
25. **Nothing stops two custom technologies sharing a name.**
26. **A custom technology cannot cross documents.**

## New in Milestone 9

27. **Clicking a node the example placed far from the origin did not select
    it in the interface test.** A node placed at the default point selects
    correctly, and that is what the journey now walks. The example journey
    reads its nodes rather than clicking one. Whether the accessibility frame
    of a node far right of the canvas matches where it draws is unproven.

28. **The samples browser has no preview.** A user opens an example on its
    name and its one-line description alone.

29. **`LoadSampleModel` replaces the model but not the document's file.** A
    user who opens an example and presses ⌘S writes it over whatever file the
    window was already showing.

30. **The About window reads the catalogue a second time.** `Dependencies()`
    is built once more at launch to get the version, so the vendored data is
    parsed twice.

31. **The icon script draws at ten sizes but nothing checks the output.** A
    change that breaks the drawing is found by eye.
