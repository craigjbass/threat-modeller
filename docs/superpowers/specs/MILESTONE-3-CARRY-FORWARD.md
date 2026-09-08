# Carry-forward into Milestone 3

What Milestone 2 deliberately did not fix. Each says why it waited and what
triggers it.

## Still deferred from Milestone 1

1. **`ThreatModelGateway` has no atomic append.**
   `AddComponent` and `ConnectComponents` read, change and save. Two
   overlapping calls would lose a change. Contained today by one gateway per
   document, synchronous use cases, and a main-actor `ThreatModelSession`.
   Milestone 2 added `@MainActor` to that session, so the containment is now
   compiler-enforced on the delivery side, but the port still does not state
   it. Add the atomic append operation before any caller becomes asynchronous,
   or in Milestone 6 when documents open concurrently.

2. **Three catalogue faults tied to a tag bump.** Do not raise the pinned tag
   above `v1.0.1` before these are fixed.
   - `BundledTechnologyCatalogue.threatsFor` uses `compactMap`, so a dangling
     threat id is dropped with no signal. 0 dangling references today.
   - `BundledTechnologyCatalogue` builds its index with
     `Dictionary(uniqueKeysWithValues:)`, which traps the process on a
     duplicate technology id. All 277 ids unique today.
   - `InMemoryTechnologyCatalogue` returns the first match on a duplicate id
     where the real gateway traps. The two gateways differ, and no contract
     test covers it.

3. **Spec section 6 is not fully met.** `TechnologyCatalogue` now has a fake, a
   real implementation and a shared contract that covers `connectionThreats()`.
   `IdentityGenerator` still has two implementations and no contract.
   `ThreatModelGateway` still has one implementation and no contract. Add
   contracts as those ports gain a second implementation.

4. **`ContentView` shows `String(describing: error)`** when the catalogue fails
   to load. Reachable only if the bundled resource is missing or corrupt.

## New in Milestone 2

5. **`ThreatModelSession` still fixes `sensitivity: "internal"`.**
   Position now comes from the drop point or the stepped default point, so that
   half of the Milestone 1 item is closed. A default sensitivity is a rule
   sitting in the delivery mechanism. `SetComponentSensitivity` and its control
   are out of scope until the milestone that adds the property panel.

6. **The palette row is a drag source with no keyboard path.**
   A drag places a component where it is dropped; a double-click places it at a
   stepped default point. Neither is reachable from the keyboard alone. Add a
   keyboard path when Milestone 6 adds menu commands and shortcuts.

7. **The canvas draws in a 20000 point square.**
   `ConnectionsLayer` takes a fixed 20000 by 20000 frame, and a `GeometryReader`
   stops that size reaching the window. A component placed outside that square
   would draw no connections. Nothing can place one there today, because every
   placement is inside the visible viewport. Replace the fixed square with a
   frame derived from the model's own bounds when Milestone 6 opens a saved
   document that may carry far-apart components.

8. **Pan needs the Command key and zoom needs a pinch or a button.**
   A plain background drag draws the marquee, so panning is Command-drag. There
   is no scroll-wheel pan and no scroll-wheel zoom. Milestone 6 adds menu
   commands and shortcuts; revisit the pointer bindings then.

9. **`CanvasView` is one file holding the gestures, the hit test and the
   layout.** It is readable now. Milestone 3 adds zone drawing, zone resizing
   and zone hit-testing to the same view. Split the gesture handling out before
   that lands, or the file stops being one thing.

10. **The connection anchor pair is recomputed on every draw and every hit
    test.** `AnchorGeometry.nearestPair` walks 16 pairs per connection, and
    `ConnectionPath.distance` samples 40 points per connection per click. Both
    are correct and neither is measured as slow at the model sizes seen so far.
    Measure before Milestone 8 renders a large model to PNG and PDF.

11. **No user interface test covers drag, marquee, connection drawing or
    delete.** `XCUITest` drag on a SwiftUI canvas is fragile, and spec section
    10 keeps the user interface suite to smoke tests. The geometry and the
    selection rules are covered by `CanvasGeometryTests` and `CanvasStateTests`;
    the gestures that join them to those rules are covered by eye only.
