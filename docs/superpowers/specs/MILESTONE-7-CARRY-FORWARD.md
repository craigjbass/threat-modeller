# Carry-forward into Milestone 7

What Milestones 6A and 6B deliberately did not fix.

## Closed in Milestone 6

- The non-atomic gateway append, the fixed 20000 point drawing square, and the
  missing `ThreatModelGateway` contract (6A).
- Undo and redo, copy, cut, paste, duplicate, and the menu and keys for all of
  them (6B).

## A defect found in Milestone 6B and not fixed

1. **Drawing a zone leaves more than one undoable change.** After drawing a
   zone on the canvas, one undo does not remove it; two do, and the second also
   removes the component added before it. Evidence, from the user interface
   suite before the step was removed:

   - the Edit menu's Undo is enabled after the drag;
   - one undo, waited on for ten seconds, leaves the zone's threats showing;
   - two undos leave neither the zone nor the component.

   `CanvasGestures.zoneDragEnded` now refuses to commit a move unless a move was
   actually started, which is correct on its own and did not fix this. The
   second change has not been identified. Every use case is one undo step at the
   boundary — 349 package tests including `TakingItBackTests` prove it — so the
   extra change comes from the canvas calling a second use case during the same
   drag. Find it by logging every use case the session calls during one zone
   drag.

   Until it is fixed, drawing a zone costs two undos to take back.

2. **The user interface journey no longer walks an undo.** It was removed rather
   than left red or made to pass by asserting the wrong number of undos. Put it
   back once item 1 is fixed.

## Still deferred

3. **Three catalogue faults tied to a tag bump**: the dangling threat id dropped
   by `compactMap`, the trap on a duplicate technology id, and the fake
   disagreeing with the real gateway on a duplicate id. The tag stays `v1.0.1`.
4. **`IdentityGenerator` has no shared contract.**
5. **`ThreatModelSession` still fixes `sensitivity: "internal"`.** Still the
   largest gap: every risk score acts on a sensitivity the user cannot set.
   `RenameComponent`, `SetComponentSensitivity` and `DisableComponentThreats`
   are unwritten.
6. **`LabelConnection` is unwritten**, so spec §9's "double-click a connection
   to edit its label" is the one line of keyboard parity not met.
7. **`ContentView` shows `String(describing: error)`** when the catalogue fails
   to load.
8. **The palette has no keyboard path**; pan needs the Command key; zoom needs a
   pinch or a button.
9. **The resolver runs twice per change and is unmeasured**, and the history now
   holds up to a hundred whole-model snapshots per document, which is memory
   nothing has measured either.
10. **A zone is selected one at a time; zone drawing order cannot be changed;
    the zone name field and the mitigation slider write on every step.**
11. **No user interface test covers node drag, marquee, connection drawing,
    delete, zone move, zone resize, or now undo.**
12. **Nothing prunes a control key whose description has left the catalogue.**
13. **A technology named `connection` or `zone` would collide with the override
    key shapes.**
14. **A severity override is keyed by technology.** Spec §5.3.
15. **The app saves its split-view arrangement and nothing validates it.**
16. **`ThreatCard` has no grouping; the sidebar has no filter and no search.**
17. **Two pathway mitigations answering one threat give the stronger, not the
    sum; a zone threat is never pathway-mitigated; the mitigation defaults are
    ours; and the panel offers a mitigation nothing provides without warning
    that the switch changed no score.**
18. **The document format has one version and no migration path.**
19. **The drift banner is dismissed per window, lists nothing beyond one line,
    and offers no way to act on what drifted. Drift is reported for technologies
    only.**

## New in Milestone 6B

20. **The session's clipboard tests use the real system pasteboard**, so running
    the suite changes what the person running it has copied. Put a `Clipboard`
    port behind the session if that becomes a problem.

21. **`CommandGroup(replacing: .pasteboard)` removes the standard Cut, Copy and
    Paste everywhere**, including in a text field. The zone name field has not
    been checked by hand for ⌘V. If it is broken, scope the four commands to a
    `CommandMenu("Diagram")` instead.

22. **Pasting carries no ticks and no overrides**, deliberately: a control key
    names a component that no longer exists after the paste, and an override is
    keyed by technology and already applies. If a user asks for the ticks to
    come along, the control keys have to be rewritten as the components are.
