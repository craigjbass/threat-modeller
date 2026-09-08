# Carry-forward into Milestone 6B

What Milestone 6A deliberately did not fix.

## Closed in Milestone 6A

- **The non-atomic gateway append.** SwiftUI asks a `FileDocument` for its bytes
  wherever it likes, so the concurrent caller the port warned about now exists.
  All fourteen write use cases read, change and write in one step, and a shared
  contract races two hundred appends to prove none is lost.
- **The fixed 20000 point drawing square.** The layer now holds what the model
  holds, with room to drag past it.
- **`ThreatModelGateway` had no contract.** It has one now, written ahead of a
  second implementation rather than retrofitted to one.

## Milestone 6B's own work

Undo and redo over the history gateway, copy, cut, paste, duplicate, menu
commands and keyboard shortcuts. Spec section 9 lists the keyboard parity it has
to reach: select all, shift-click, escape, copy, cut, paste, duplicate, delete,
arrow nudge 10 points, shift-arrow nudge 1 point, undo and redo.

`pushHistory()`, `undo()` and `redo()` join `ThreatModelGateway` there, and the
contract written in 6A grows to cover them.

## Still deferred

1. **Three catalogue faults tied to a tag bump**: the dangling threat id dropped
   by `compactMap`, the trap on a duplicate technology id, and the fake
   disagreeing with the real gateway on a duplicate id. The tag stays `v1.0.1`.
2. **`IdentityGenerator` still has no shared contract.** Add one when it gains a
   second implementation.
3. **`ThreatModelSession` still fixes `sensitivity: "internal"`.** This remains
   the largest gap: pathway escalation, the zone multiplier and every risk score
   act on a sensitivity the user cannot set. `RenameComponent`,
   `SetComponentSensitivity` and `DisableComponentThreats` are unwritten.
4. **The palette has no keyboard path**, pan needs the Command key, and zoom
   needs a pinch or a button. 6B revisits the pointer and key bindings.
5. **The resolver is recomputed on every read, twice per change**, and walks the
   connection graph. Unmeasured. Measure before Milestone 8 renders a large
   model.
6. **A zone is selected one at a time; zone drawing order cannot be changed; the
   zone name field and the mitigation slider write on every step.**
7. **No user interface test covers node drag, marquee, connection drawing,
   delete, zone move or zone resize.**
8. **Nothing prunes a control key whose description has left the catalogue.**
9. **A technology named `connection` or `zone` would collide with the link and
   zone override key shapes.**
10. **A severity override is keyed by technology.** Spec section 5.3.
11. **The app saves its split-view arrangement and nothing validates a restored
    arrangement against the window it is restored into.**
12. **`ThreatCard` renders every control as a checkbox with no grouping, and the
    sidebar has no filter and no search.**
13. **Where two pathway mitigations answer one threat the stronger wins rather
    than the sum**, and **a zone threat is never pathway-mitigated**.
14. **The pathway mitigation defaults are ours, not the catalogue's.**
15. **The panel offers a mitigation nothing on the diagram provides**, and
    nothing warns the user that the switch they moved changed no score.

## New in Milestone 6A

16. **Nothing writes the document except SwiftUI's own save.** There is no
    autosave interval of the application's own and no explicit Save command in a
    menu; `DocumentGroup` supplies both. 6B adds the menu.

17. **A document that fails to load the catalogue still opens a window.** It
    shows the failure instead of a diagram, and its `fileWrapper` throws. The
    user cannot save it, which is right, but the message is
    `String(describing: error)`. Same item as the old carry-forward 5, now
    reachable in two places.

18. **The drift banner is dismissed per window and never returns.** Reopening
    the file shows it again. There is no list of what drifted beyond the
    banner's one line, and no way to act on it — no "replace this technology
    with that one".

19. **`OpenThreatModel` reports drift only for technologies.** A severity
    override or a control key naming a threat the catalogue has retired is
    silently inert, exactly as an unpruned control key is. Widen the drift
    report if a catalogue update is ever seen to strand one.

20. **The document format has one version and no migration path.** Version 2
    will need a reader for version 1. The refusal is deliberate and the field is
    there; the reader is not.

21. **Two documents share one `SequentialIdentityGenerator` per graph but the
    identifiers are only unique within a document.** Pasting between documents
    in 6B must not assume otherwise.
