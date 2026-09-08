# Carry-forward into Milestone 6

What Milestone 5 deliberately did not fix. Each says why it waited and what
triggers it.

## Closed in Milestone 5

- The catalogue port now answers every method spec section 6 lists. Nothing is
  left to add to it.

## Still deferred from Milestones 1 to 4

1. **`ThreatModelGateway` has no atomic append.** Every caller is synchronous
   and main-actor isolated. Milestone 6 opens documents concurrently, so this
   trigger fires **in Milestone 6**. Add the atomic append before the document
   work.
2. **Three catalogue faults tied to a tag bump**: the dangling threat id dropped
   by `compactMap`, the trap on a duplicate technology id, and the fake
   disagreeing with the real gateway on a duplicate id. The tag stays `v1.0.1`.
3. **`IdentityGenerator` and `ThreatModelGateway` still have no shared
   contract.** Milestone 6 gives `ThreatModelGateway` a second implementation
   backed by a file, so this trigger fires **in Milestone 6**.
4. **`ThreatModelSession` still fixes `sensitivity: "internal"`.** This is now
   the largest gap: pathway escalation and the zone multiplier both act on a
   sensitivity the user cannot set. `RenameComponent`,
   `SetComponentSensitivity` and `DisableComponentThreats` are unwritten.
5. **`ContentView` shows `String(describing: error)`** when the catalogue fails
   to load.
6. **The palette has no keyboard path**, pan needs the Command key, and zoom
   needs a pinch or a button. Milestone 6 adds menu commands and shortcuts, so
   this trigger fires **in Milestone 6**.
7. **The canvas draws in a fixed 20000 point square.** Milestone 6 opens a saved
   document that may carry far-apart items, so this trigger fires **in
   Milestone 6**.
8. **The `ThreatResolver` is recomputed on every read, twice per change**, once
   for the list and once for the summary, and now walks the connection graph as
   well. Every part of it is unmeasured. Measure before Milestone 8 renders a
   large model.
9. **A zone is selected one at a time, zone drawing order cannot be changed, the
   zone name field writes on every keystroke, and there is no undo.** Undo
   arrives in Milestone 6.
10. **No user interface test covers node drag, marquee, connection drawing,
    delete, zone move or zone resize.**
11. **Nothing prunes a control key whose description has left the catalogue.**
12. **A technology named `connection` or `zone` would collide with the link and
    zone override key shapes.**
13. **A severity override is keyed by technology**, so it applies to every
    component of that technology. That is spec section 5.3.
14. **The app saves its split-view arrangement, and nothing validates a restored
    arrangement against the window it is restored into.** A bad one leaves a
    column collapsed and the user interface suite failing with no window.
    `defaults delete uk.craigbass.threatmodeller` clears it.
15. **`ThreatCard` renders every control as a checkbox with no grouping.**
16. **The sidebar has no filter and no search.**

## New in Milestone 5

17. **Where two mitigations both answer one threat, the stronger wins rather
    than the sum.** `remove` beats `reduce`, and among two reductions the one
    leaving the lower score wins. The spec states no rule for this. Revisit if a
    user expects two controls to compound.

18. **A zone threat is never pathway-mitigated.** A zone sits nowhere in the
    connection graph, so nothing is upstream of it. Spec section 5.3 speaks only
    of components and links. Revisit if a zone is ever given a position in the
    graph.

19. **The mitigation defaults are ours, not the catalogue's.** The master toggle
    starts off and each mitigation starts enabled at `reduce` 50 per cent. The
    spec now records the choice and the reason. If parity with the original
    application ever matters more than the reason, change the defaults and the
    spec together.

20. **`PathwayMitigationsPanel` writes on every slider step and every keystroke,
    and each write reassesses the whole model.** Same shape as the zone name
    field. See item 8.

21. **The panel offers a mitigation nothing on the diagram provides, greyed,
    with what would provide it.** A user can switch on a control they do not
    have, and no score moves. That is deliberate — they are choosing what to
    build as much as what they have — but nothing warns them that the switch
    they just moved changed nothing.
