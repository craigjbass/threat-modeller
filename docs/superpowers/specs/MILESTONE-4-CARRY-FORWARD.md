# Carry-forward into Milestone 4

What Milestone 3 deliberately did not fix. Each says why it waited and what
triggers it.

## Closed in Milestone 3

- `CanvasView` held layout, every gesture and the hit test in one file. It is
  now split: `CanvasView` holds layout, `CanvasGestures` holds the gestures, and
  `CanvasHitTest` holds pure hit testing with its own tests.
- The component footprint and the zone header height were each about to be
  stated twice. Both are stated once, in the core, and the canvas reads them.

## Still deferred from Milestones 1 and 2

1. **`ThreatModelGateway` has no atomic append.** Every caller is synchronous
   and runs on the main actor, and `ThreatModelSession` is `@MainActor`. Add the
   atomic append operation before any caller becomes asynchronous, or in
   Milestone 6 when documents open concurrently.

2. **Three catalogue faults tied to a tag bump.** Do not raise the pinned tag
   above `v1.0.1` before these are fixed.
   - `BundledTechnologyCatalogue.threatsFor` drops a dangling threat id with no
     signal. 0 dangling references today.
   - `BundledTechnologyCatalogue` traps the process on a duplicate technology
     id. All 277 ids unique today.
   - `InMemoryTechnologyCatalogue` returns the first match on a duplicate id
     where the real gateway traps, and no contract test covers the difference.

3. **`IdentityGenerator` and `ThreatModelGateway` still have no shared
   contract.** `TechnologyCatalogue` has one and it now covers
   `connectionThreats()` and `zoneThreats()`. Add contracts as those two ports
   gain a second implementation.

4. **`ThreatModelSession` still fixes `sensitivity: "internal"`.**
   `SetComponentSensitivity`, `RenameComponent` and `DisableComponentThreats`
   are still unwritten, so a component's sensitivity cannot be changed. The
   zone panel shows what a property panel looks like; the component one belongs
   with those three use cases.

5. **`ContentView` shows `String(describing: error)`** when the catalogue fails
   to load. Reachable only if the bundled resource is missing or corrupt.

6. **The palette has no keyboard path**, pan needs the Command key, and zoom
   needs a pinch or a button. Revisit the pointer and key bindings when
   Milestone 6 adds menu commands and shortcuts.

7. **The canvas draws in a fixed 20000 point square.** A component or a zone
   outside it would draw no connections. Nothing can place one there today.
   Replace the square with a frame derived from the model's own bounds when
   Milestone 6 opens a saved document that may carry far-apart items.

8. **The anchor pair and the path sampling are recomputed on every draw and
   every hit test, and are unmeasured.** `ZoneContainment` now joins them: it
   walks every zone for every component on every assessment. All three are
   correct and none is measured as slow at the model sizes seen so far. Measure
   before Milestone 8 renders a large model to PNG and PDF.

## New in Milestone 3

9. **A zone can only be selected one at a time, and cannot be moved with the
   arrow keys.** The panel edits one zone, and the marquee gathers components
   only. A user who wants to move two zones together must move each. Revisit
   when Milestone 6 adds copy, paste and duplicate.

10. **A zone's drawing order is the order it was drawn in, and nothing changes
    it.** Where two zones overlap the later one wins, in the canvas and in the
    core alike. There is no bring-to-front or send-to-back. Add one when a user
    reports being unable to express a nesting they need.

11. **`ZonePanel` writes on every keystroke in the name field.** Each keystroke
    calls `SetZoneProperties` and then a full reassessment. The reassessment is
    measured in microseconds at the sizes tested, so this is not a defect today.
    Debounce the field if the assessment ever grows expensive — see item 8.

12. **The zone panel has no undo.** Turning risk reduction off and on again
    restores the percentage, because the percentage is stored either way, but a
    name typed over is gone. Undo arrives in Milestone 6.

13. **No user interface test covers node drag, marquee, connection drawing,
    delete, zone move or zone resize.** The journey covers adding a technology
    and drawing a zone. The geometry, the selection rules and the hit testing
    are covered by `CanvasGeometryTests`, `CanvasStateTests` and
    `CanvasHitTestTests`; the gestures joining them to those rules are covered
    by eye only.

14. **A zone shorter than its own header holds nothing.** `Zone.minimumSize` is
    120 by 100 and the header is 40, so `AddZone` and `ResizeZone` cannot make
    one, but `ThreatModel` accepts one from a future document reader.
    Milestone 6 must validate a zone rectangle on open.
