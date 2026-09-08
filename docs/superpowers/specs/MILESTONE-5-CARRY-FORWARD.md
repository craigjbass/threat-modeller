# Carry-forward into Milestone 5

What Milestone 4 deliberately did not fix. Each says why it waited and what
triggers it.

## Closed in Milestone 4

- `AssessThreatModel` and `SummariseRisk` each resolved threats their own way,
  which would have let a count disagree with the list beneath it. Both now read
  one `ThreatResolver`.
- The key formats of spec section 5.3 were about to be built in a view. The core
  mints every control key and every override key and hands them out; a write use
  case takes a key it was given.

## Still deferred from Milestones 1 to 3

1. **`ThreatModelGateway` has no atomic append.** Every caller is synchronous
   and main-actor isolated. Add the atomic append before any caller becomes
   asynchronous, or in Milestone 6 when documents open concurrently.
2. **Three catalogue faults tied to a tag bump**: the dangling threat id dropped
   by `compactMap`, the trap on a duplicate technology id, and the fake
   disagreeing with the real gateway on a duplicate id. Do not raise the pinned
   tag above `v1.0.1` before they are fixed.
3. **`IdentityGenerator` and `ThreatModelGateway` still have no shared
   contract.** Add one as each gains a second implementation.
4. **`ThreatModelSession` still fixes `sensitivity: "internal"`.**
   `RenameComponent`, `SetComponentSensitivity` and `DisableComponentThreats`
   are unwritten, so the sensitivity half of every risk score cannot be changed.
   This is now the largest thing the user cannot do.
5. **`ContentView` shows `String(describing: error)`** when the catalogue fails
   to load.
6. **The palette has no keyboard path**, pan needs the Command key, and zoom
   needs a pinch or a button. Revisit with Milestone 6's menu commands.
7. **The canvas draws in a fixed 20000 point square.** Replace it with a frame
   derived from the model's bounds when Milestone 6 opens a saved document.
8. **The anchor pair, the path sampling, the zone containment and now the whole
   `ThreatResolver` are recomputed on every read, and are unmeasured.** The
   session runs the resolver twice per change: once for the list and once for
   the summary. Measure before Milestone 8 renders a large model.
9. **A zone is selected one at a time and has no arrow-key move; zone drawing
   order cannot be changed; the zone name field writes on every keystroke;
   there is no undo.** Undo arrives in Milestone 6.
10. **No user interface test covers node drag, marquee, connection drawing,
    delete, zone move or zone resize.**

## New in Milestone 4

11. **Nothing prunes a control key whose description has left the catalogue.**
    The key stays in the model, shows nowhere, and its tick returns if the
    description ever comes back. Spec section 5.3 asks for no sweep. Add one
    only if a catalogue update is ever seen to strand a tick a user cares about.

12. **A technology named `connection` or `zone` would collide with the link and
    zone override key shapes.** `SeverityOverrideKeyTests` records the collision.
    No such technology exists at tag `v1.0.1`. Fix the shapes if one appears.

13. **A severity override is keyed by technology, so it applies to every
    component of that technology, and a link or zone override applies to every
    link or every zone.** That is spec section 5.3 and the original's behaviour.
    The card's tooltip says so. If a user asks for a per-component override, it
    needs a second key shape and a rule for which wins.

14. **The app saves its split-view arrangement in its container preferences,
    and a saved arrangement wider than the window leaves a column collapsed.**
    Milestone 2's 20000-point window defect wrote one, and the user interface
    suite then failed at its first assertion with no window at all. Clearing
    `defaults delete uk.craigbass.threatmodeller` fixes it. Nothing validates a
    restored arrangement against the window it is restored into.

15. **`ThreatCard` renders every control as a checkbox with no grouping, and a
    threat with many controls makes a tall card.** The vendored catalogue gives
    each threat four controls, so no card is unmanageable today. Revisit if a
    catalogue update raises that count.

16. **The sidebar has no filter and no search.** A model with twenty components
    gives twenty groups. Spec section 9 does not ask for filtering in this
    milestone; the original application has it.
