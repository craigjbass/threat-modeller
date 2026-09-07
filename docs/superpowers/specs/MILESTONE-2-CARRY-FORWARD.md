# Carry-forward into Milestone 2

Findings from the Milestone 1 whole-branch review that were deliberately not
fixed in Milestone 1. Each says why it waited and what triggers it.

## Must be in the Milestone 2 plan

1. **The application target builds in Swift 5 language mode.**
   `threatmodeller.xcodeproj/project.pbxproj` sets `SWIFT_VERSION = 5.0` in all
   six configurations, while `ThreatModelKit` runs Swift 6 language mode. The
   delivery mechanism therefore gets no data-race checking. This also weakens the
   containment argument for item 5 below.

2. **`UseCaseFactory` lives in the application target.**
   `TestDependencies` in `TestSupport` cannot conform to it, so two composition
   roots vend the same three use cases with nothing keeping them in step. Move the
   protocol into the core and make both conform BEFORE Milestone 2 adds use cases.

3. **The application unit tests read the vendored catalogue from disk.**
   `threatmodellerTests` builds the real `Dependencies()`. Spec section 10 places
   real vendored JSON in `GatewayIntegrationTests`. `ThreatModelSession` already
   takes a `UseCaseFactory`, so a fake factory is small. Today the file pins
   catalogue numbers a second time, so a catalogue update breaks it.

4. **Spec section 5.3: "Duplicate (threat, source) pairs are raised once" is not
   implemented.** `AssessThreatModel` emits one row per entry of `threatsFor`.
   Latent only: no vendored service lists a threat id twice across all 277
   services at tag v1.0.1. The threat list's row identity also assumes this.

5. **`ThreatModelGateway` has no atomic append.**
   `AddComponent` reads, appends and saves. Two overlapping calls would lose a
   component. Contained today by one gateway per document, synchronous use cases,
   and main-actor callers. The doc comment now states that rule, but the compiler
   does not enforce it. Fix the port in Milestone 6, when documents open
   concurrently, or sooner if any caller becomes asynchronous.

## Tied to the next catalogue tag bump

Do not raise the pinned tag above `v1.0.1` before these are fixed. All three are
safe against the current data and unsafe against unknown data.

6. `BundledTechnologyCatalogue.threatsFor` uses `compactMap`, so a dangling threat
   id is dropped with no signal. 0 dangling references today.
7. `BundledTechnologyCatalogue` builds its index with
   `Dictionary(uniqueKeysWithValues:)`, which traps the process on a duplicate
   technology id. All 277 ids unique today.
8. `InMemoryTechnologyCatalogue` returns the first match on a duplicate id where
   the real gateway traps. The two gateways differ, and no contract test covers it.

## Spec section 6 is not fully met

Only `TechnologyCatalogue` has a fake, a real implementation and a shared
contract. `IdentityGenerator` has two implementations and no contract.
`ThreatModelGateway` has one implementation and no contract. Add contracts as
those ports gain a second implementation.

## Smaller items

- `ComponentId` sits in `Component.swift` while the catalogue ids sit together in
  `Identifiers.swift`. Split it out before `ConnectionId` and `ZoneId` arrive.
- `ThreatModelSession` fixes `sensitivity: "internal"` and position `0, 0`. A
  default sensitivity is a rule sitting in the delivery mechanism. Milestone 2
  gives the canvas a real position, and a later milestone gives the user a
  sensitivity control.
- `ContentView` shows `String(describing: error)` when the catalogue fails to
  load. Reachable only if the bundled resource is missing or corrupt.
- `threatmodellerUITests` still holds two template leftovers,
  `testLaunchPerformance` and `testLaunch`, which launch the application and add
  no cover. Delete them when the user interface suite next changes.
