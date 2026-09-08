# Milestone 5: Pathway Mitigations — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A threat that reaches a component through the diagram is answered by what sits in front of it. A WAF upstream of an application drops or lowers the injection threats that application carries, and a threat that feeds more sensitive data downstream is scored against that higher sensitivity.

**Architecture:** `UpstreamGraph` walks the connections backwards to the components strictly upstream of one component. `PathwayMitigation` decides whether a mitigation applies to a threat and what it does to the score. Both are assessment domain objects the `ThreatResolver` reads, so the sidebar, the summary and the exports all see the same answer.

**Tech Stack:** Swift 6.3, Swift Package Manager, Swift Testing, SwiftUI, macOS 26.

**Spec:** `docs/superpowers/specs/2026-09-07-native-macos-threat-modeller-design.md`

**Carry-forward:** `docs/superpowers/specs/MILESTONE-5-CARRY-FORWARD.md`

**Read Task 7 before starting Task 1.** Task 7 is the acceptance test — the outer loop.

## Global Constraints

- Everything in the Milestone 4 plan's Global Constraints still holds.
- WARNING: two source files in one module may not share a basename.
- WARNING: a key path passed to a `rethrows` method inside `#expect` fails to compile; use a closure. `#expect` also keeps each operand's own type, so convert a `CGFloat` before comparing it with a `Double`.
- WARNING: the app saves its split-view arrangement. If the user interface suite fails at its first assertion with no window, run `osascript -e 'tell application "threatmodeller" to quit'` then `defaults delete uk.craigbass.threatmodeller`.
- Upstream is strict: a component is never upstream of itself, so a component never mitigates its own threats.
- A pathway mitigation applies when the master toggle is on, that mitigation is enabled, a strictly upstream component's technology provides it, and the mitigation lists the threat id.
- Mode `remove` drops the threat. Mode `reduce` gives `max(1, floor(score − score × percent / 100))`, so a reduced threat never reaches zero.
- A link's threats use the **source** component's upstream mitigations.
- A threat flagged `isPathwayThreat` escalates its sensitivity to the highest sensitivity among the components **directly** downstream of it, when that is higher than its own.
- Escalation happens before the score; the zone multiplier and then the pathway mitigation apply after it.
- Defaults: the master toggle is off; each mitigation is enabled, mode `reduce`, 50 per cent.
- Catalogue pinned at `v1.0.1`.
- Commit after every task. Never commit a red suite.

## Out of scope for this milestone

Undo/redo, documents, copy and paste, custom technologies, external actors, exports, samples, connection labels, the component property panel, sidebar filtering and search. Every item on `MILESTONE-5-CARRY-FORWARD.md` keeps the trigger recorded against it.

## File Structure

**Created:**

| Path | Responsibility |
|---|---|
| `.../catalogue/domain/PathwayMitigationDefinition.swift` | What the catalogue says a mitigation is |
| `.../catalogue/usecase/ListPathwayMitigations.swift` | The settings screen's contents |
| `.../assessment/domain/UpstreamGraph.swift` | Reverse traversal, and the direct downstream set |
| `.../assessment/domain/PathwayMitigation.swift` | `PathwayMitigationMode`, `PathwayMitigationConfig`, `PathwayMitigationSettings`, and what a mitigation does to a score |
| `.../assessment/usecase/ConfigurePathwayMitigations.swift` | and its Request/Response |
| `ThreatModelKit/Tests/UnitTests/UpstreamGraphTests.swift` | Traversal |
| `.../UnitTests/PathwayMitigationTests.swift` | The modes and the settings |
| `.../UnitTests/ListPathwayMitigationsTests.swift` | The settings screen's contents |
| `.../UnitTests/ConfigurePathwayMitigationsTests.swift` | The write use case |
| `.../AcceptanceTests/AnsweringThreatsUpstreamTests.swift` | The milestone's outer loop |
| `threatmodeller/sidebar/PathwayMitigationsPanel.swift` | The settings the user turns on |

**Modified:**

- `.../catalogue/gateway/TechnologyCatalogue.swift` — gains `pathwayMitigations()`
- `.../CatalogueGateways/BundledTechnologyCatalogue.swift`, `CatalogueJSON.swift` — read the vendored file
- `.../TestSupport/` — the fake, the fixture, the contract, `TestDependencies`
- `.../modelling/domain/ThreatModel.swift` — gains `pathwayMitigations`
- `.../assessment/domain/SensitivityLadder.swift` — gains the highest-of-many rule
- `.../assessment/domain/ThreatResolver.swift` — escalation, then mitigation
- `.../assessment/usecase/AssessThreatModel.swift` — the response says what a mitigation did
- `.../UseCaseFactory.swift`, `Dependencies.swift` — two more use cases
- `threatmodeller/ThreatModelSession.swift` — the mitigations and the command
- `threatmodeller/ContentView.swift` — the panel reaches the window
- `threatmodellerUITests/threatmodellerUITests.swift` — the journey turns a mitigation on

---

### Task 1: The catalogue's pathway mitigations

**Files:**
- Create: `.../catalogue/domain/PathwayMitigationDefinition.swift`
- Modify: `.../catalogue/gateway/TechnologyCatalogue.swift`
- Modify: `.../CatalogueGateways/CatalogueJSON.swift`, `BundledTechnologyCatalogue.swift`
- Modify: `.../TestSupport/InMemoryTechnologyCatalogue.swift`, `CatalogueFixture.swift`, `TechnologyCatalogueContract.swift`
- Modify: `ThreatModelKit/Tests/GatewayIntegrationTests/BundledTechnologyCatalogueTests.swift`

**Interfaces:**
- Consumes: `ThreatId`, `TechnologyId`.
- Produces: `PathwayMitigationId`; `PathwayMitigationDefinition(id:label:description:mitigatesThreatIds:technologyIds:)`; `TechnologyCatalogue.pathwayMitigations() -> [PathwayMitigationDefinition]`; `CatalogueFixture.pathwayMitigations()` and `CatalogueFixture.waf()`.

The vendored file is `mitigations/pathway-mitigations.json` with a `mitigations` array of `{ id, label, description, mitigatesThreatIds, technologyIds }`. Tag `v1.0.1` holds four: `ddos-protection`, `waf-protection`, `rate-limiting`, `network-firewall`.

- [ ] **Step 1: Write the failing test**

Add to `verifyTechnologyCatalogueContract`:

```swift
    let mitigations = subject.pathwayMitigations()
    #expect(mitigations.isEmpty == false)
    #expect(Set(mitigations.map(\.id)).count == mitigations.count)
    for mitigation in mitigations {
        #expect(mitigation.label.isEmpty == false)
        #expect(mitigation.mitigatesThreatIds.isEmpty == false)
        #expect(mitigation.technologyIds.isEmpty == false)
        // Every technology named must be one the catalogue holds, or the
        // settings screen would offer a mitigation nothing can provide.
        for technologyId in mitigation.technologyIds {
            #expect(subject.findById(technologyId) != nil)
        }
    }
```

Add to `BundledTechnologyCatalogueTests`:

```swift
    @Test func listsThePathwayMitigationsTheVendoredDataHolds() throws {
        let catalogue = try BundledTechnologyCatalogue()

        #expect(catalogue.pathwayMitigations().map(\.id.value) == [
            "ddos-protection",
            "waf-protection",
            "rate-limiting",
            "network-firewall"
        ])

        let waf = try #require(catalogue.pathwayMitigations().first { $0.id.value == "waf-protection" })
        #expect(waf.label == "WAF Protection")
        #expect(waf.mitigatesThreatIds.map(\.value).contains("connection-injection"))
        #expect(waf.technologyIds.map(\.value).contains("aws-waf"))
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter TechnologyCatalogueContractTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `has no member 'pathwayMitigations'`.

- [ ] **Step 3: Write the domain value**

Create `.../catalogue/domain/PathwayMitigationDefinition.swift`:

```swift
public struct PathwayMitigationId: Hashable, Sendable, CustomStringConvertible {
    public let value: String
    public init(_ value: String) { self.value = value }
    public var description: String { value }
}

/// A control that answers a threat for everything downstream of it.
///
/// The catalogue says what a mitigation is called, which threats it answers and
/// which technologies provide it. Whether it is switched on, and what it does
/// to a score, are the user's settings and live on the model.
public struct PathwayMitigationDefinition: Equatable, Sendable {
    public let id: PathwayMitigationId
    public let label: String
    public let description: String
    public let mitigatesThreatIds: [ThreatId]
    /// The technologies that provide this mitigation.
    public let technologyIds: [TechnologyId]

    public init(
        id: PathwayMitigationId,
        label: String,
        description: String,
        mitigatesThreatIds: [ThreatId],
        technologyIds: [TechnologyId]
    ) {
        self.id = id
        self.label = label
        self.description = description
        self.mitigatesThreatIds = mitigatesThreatIds
        self.technologyIds = technologyIds
    }

    public func mitigates(_ threatId: ThreatId) -> Bool {
        mitigatesThreatIds.contains(threatId)
    }

    public func isProvidedBy(_ technologyId: TechnologyId) -> Bool {
        technologyIds.contains(technologyId)
    }
}
```

- [ ] **Step 4: Add the method to the port and the fake**

In `TechnologyCatalogue.swift`, add after `zoneThreats()` and drop the "later milestone" sentence, because this is the last method the spec lists:

```swift
    /// Every pathway mitigation the catalogue defines, in catalogue order.
    func pathwayMitigations() -> [PathwayMitigationDefinition]
```

In `InMemoryTechnologyCatalogue`, take them in the initialiser with an empty default and return them:

```swift
    private let pathwayMitigationsValue: [PathwayMitigationDefinition]
```

```swift
    public func pathwayMitigations() -> [PathwayMitigationDefinition] { pathwayMitigationsValue }
```

- [ ] **Step 5: Give the fixture a mitigation and a technology that provides it**

Add to `CatalogueFixture`:

```swift
    /// A technology that provides a mitigation, so a test can put one upstream
    /// of something and watch the threat change.
    public static func waf() -> Technology {
        Technology(
            id: TechnologyId("aws-waf"),
            name: "WAF",
            provider: ProviderId("aws"),
            category: CategoryId("compute"),
            description: "Web application firewall",
            threatIds: []
        )
    }

    /// One mitigation, answering a threat EC2 carries and one every link
    /// carries, so a test can tell a component threat from a link threat.
    public static func pathwayMitigations() -> [PathwayMitigationDefinition] {
        [
            PathwayMitigationDefinition(
                id: PathwayMitigationId("waf-protection"),
                label: "WAF Protection",
                description: "Mitigates: Credential Theft, Connection Flooding",
                mitigatesThreatIds: [ThreatId("credential-theft"), ThreatId("connection-dos")],
                technologyIds: [TechnologyId("aws-waf")]
            )
        ]
    }
```

and change `catalogue()`:

```swift
    public static func catalogue() -> InMemoryTechnologyCatalogue {
        InMemoryTechnologyCatalogue(
            technologies: [ec2(), rds(), bigQuery(), waf()],
            threats: ec2Threats() + connectionThreats() + zoneThreats(),
            taxonomy: taxonomy(),
            providers: providers(),
            pathwayMitigations: pathwayMitigations()
        )
    }
```

WARNING: adding `waf()` changes what `ListTechnologies` returns. `BuildingAThreatModelTests.offersTheCatalogueGroupedForBrowsing` asserts `aws.categories.first?.technologies.map(\.name) == ["EC2"]`. WAF is also `aws`/`compute`, and the palette sorts by name, so that becomes `["EC2", "WAF"]`. Update that expectation.

- [ ] **Step 6: Read the vendored file**

Add to `CatalogueJSON.swift`:

```swift
struct PathwayMitigationsFileJSON: Decodable {
    let mitigations: [PathwayMitigationJSON]
}

struct PathwayMitigationJSON: Decodable {
    let id: String
    let label: String
    let description: String
    let mitigatesThreatIds: [String]
    let technologyIds: [String]
}
```

In `BundledTechnologyCatalogue`, add the stored property, decode the file in `init` after the providers are loaded, and return it:

```swift
    private let pathwayMitigationsValue: [PathwayMitigationDefinition]
```

```swift
        let mitigationsJSON = try decoder.decode(
            PathwayMitigationsFileJSON.self,
            from: try LibraryResources.data(named: "mitigations/pathway-mitigations.json")
        )
        pathwayMitigationsValue = mitigationsJSON.mitigations.map {
            PathwayMitigationDefinition(
                id: PathwayMitigationId($0.id),
                label: $0.label,
                description: $0.description,
                mitigatesThreatIds: $0.mitigatesThreatIds.map(ThreatId.init),
                technologyIds: $0.technologyIds.map(TechnologyId.init)
            )
        }
```

```swift
    public func pathwayMitigations() -> [PathwayMitigationDefinition] { pathwayMitigationsValue }
```

- [ ] **Step 7: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

Expected: PASS. The contract proves the fake and the real gateway both answer, and that every technology a mitigation names is one the catalogue holds.

- [ ] **Step 8: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit
git commit -m "feat: read the pathway mitigations from the catalogue

The catalogue says what a mitigation answers and which technologies provide
it. The contract proves every technology it names is one the catalogue holds,
so the settings screen cannot offer a mitigation nothing can provide."
```

---

### Task 2: `UpstreamGraph`

**Files:**
- Create: `.../assessment/domain/UpstreamGraph.swift`
- Test: `ThreatModelKit/Tests/UnitTests/UpstreamGraphTests.swift`

**Interfaces:**
- Consumes: `Connection`, `ComponentId`.
- Produces: `UpstreamGraph(connections:)` with `.upstream(of:) -> Set<ComponentId>` and `.directlyDownstream(of:) -> Set<ComponentId>`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/UpstreamGraphTests.swift`:

```swift
import Testing
import ThreatModelKit

struct UpstreamGraphTests {
    private func link(_ id: String, _ source: String, _ target: String) -> Connection {
        Connection(id: ConnectionId(id), source: ComponentId(source), target: ComponentId(target))
    }

    private func graph(_ connections: [Connection]) -> UpstreamGraph {
        UpstreamGraph(connections: connections)
    }

    @Test func findsNothingUpstreamOfALoneComponent() {
        #expect(graph([]).upstream(of: ComponentId("c1")).isEmpty)
    }

    @Test func findsTheComponentOneHopUpstream() {
        let found = graph([link("k1", "a", "b")]).upstream(of: ComponentId("b"))

        #expect(found == [ComponentId("a")])
    }

    @Test func walksEveryHopBack() {
        // a -> b -> c -> d
        let found = graph([
            link("k1", "a", "b"),
            link("k2", "b", "c"),
            link("k3", "c", "d")
        ]).upstream(of: ComponentId("d"))

        #expect(found == [ComponentId("a"), ComponentId("b"), ComponentId("c")])
    }

    @Test func findsEveryBranchThatFeedsIn() {
        // a -> c, b -> c
        let found = graph([link("k1", "a", "c"), link("k2", "b", "c")])
            .upstream(of: ComponentId("c"))

        #expect(found == [ComponentId("a"), ComponentId("b")])
    }

    @Test func neverCountsAComponentAsUpstreamOfItself() {
        // A cycle: a -> b -> a. Spec section 5.3 makes upstream strict.
        let found = graph([link("k1", "a", "b"), link("k2", "b", "a")])
            .upstream(of: ComponentId("a"))

        #expect(found == [ComponentId("b")])
    }

    @Test func stopsRatherThanLoopingOnACycle() {
        // a -> b -> c -> b. The walk must finish.
        let found = graph([
            link("k1", "a", "b"),
            link("k2", "b", "c"),
            link("k3", "c", "b")
        ]).upstream(of: ComponentId("c"))

        #expect(found == [ComponentId("a"), ComponentId("b")])
    }

    @Test func ignoresWhatIsOnlyDownstream() {
        let found = graph([link("k1", "a", "b"), link("k2", "b", "c")])
            .upstream(of: ComponentId("a"))

        #expect(found.isEmpty)
    }

    @Test func findsOnlyTheComponentsOneHopDownstream() {
        // a -> b -> c. Directly downstream of a is b, not c.
        let found = graph([link("k1", "a", "b"), link("k2", "b", "c")])
            .directlyDownstream(of: ComponentId("a"))

        #expect(found == [ComponentId("b")])
    }

    @Test func findsEveryBranchOneHopDownstream() {
        let found = graph([link("k1", "a", "b"), link("k2", "a", "c")])
            .directlyDownstream(of: ComponentId("a"))

        #expect(found == [ComponentId("b"), ComponentId("c")])
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter UpstreamGraphTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'UpstreamGraph' in scope`.

- [ ] **Step 3: Write the graph**

Create `.../assessment/domain/UpstreamGraph.swift`:

```swift
/// Which components feed which. Spec section 5.2.
///
/// A pathway mitigation belongs to whatever sits in front of a component, so
/// the assessment has to walk the links backwards. A pathway threat escalates
/// to what it feeds, so it also has to look one hop forwards.
public struct UpstreamGraph {
    private let sourcesByTarget: [ComponentId: [ComponentId]]
    private let targetsBySource: [ComponentId: [ComponentId]]

    public init(connections: [Connection]) {
        var sources: [ComponentId: [ComponentId]] = [:]
        var targets: [ComponentId: [ComponentId]] = [:]
        for connection in connections {
            sources[connection.target, default: []].append(connection.source)
            targets[connection.source, default: []].append(connection.target)
        }
        sourcesByTarget = sources
        targetsBySource = targets
    }

    /// Every component that reaches this one by any number of hops.
    ///
    /// Strict: a component is never upstream of itself, even in a cycle, so a
    /// component never mitigates its own threats. The walk marks what it has
    /// seen, so a cycle finishes rather than looping.
    public func upstream(of component: ComponentId) -> Set<ComponentId> {
        var found: Set<ComponentId> = []
        var queue = sourcesByTarget[component] ?? []

        while let next = queue.popLast() {
            guard next != component else { continue }
            guard found.contains(next) == false else { continue }
            found.insert(next)
            queue.append(contentsOf: sourcesByTarget[next] ?? [])
        }

        return found
    }

    /// The components one hop forward. A pathway threat escalates to the data
    /// these hold, not to everything further on.
    public func directlyDownstream(of component: ComponentId) -> Set<ComponentId> {
        Set(targetsBySource[component] ?? [])
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit
git commit -m "feat: add UpstreamGraph

Walks the links backwards to everything that feeds a component, and one hop
forwards to what it feeds. Upstream is strict, so a component never mitigates
its own threats, and a cycle finishes rather than looping."
```

---

### Task 3: The settings, the modes, and what a mitigation does to a score

**Files:**
- Create: `.../assessment/domain/PathwayMitigation.swift`
- Modify: `.../modelling/domain/ThreatModel.swift`
- Modify: `.../assessment/domain/SensitivityLadder.swift`
- Test: `ThreatModelKit/Tests/UnitTests/PathwayMitigationTests.swift`

**Interfaces:**
- Consumes: `PathwayMitigationId`, `PathwayMitigationDefinition`, `DataSensitivity`.
- Produces: `PathwayMitigationMode` (`.remove`, `.reduce`); `PathwayMitigationConfig(isEnabled:mode:reductionPercent:)`; `PathwayMitigationSettings(isMasterEnabled:configs:)` with `.config(for:)` and `PathwayMitigationSettings.defaultConfig`; `PathwayMitigationOutcome` (`.unchanged`, `.removed`, `.reduced(to:)`) and `PathwayMitigation.outcome(score:mode:percent:)`; `ThreatModel.pathwayMitigations`; `SensitivityLadder.highest(of:)`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/PathwayMitigationTests.swift`:

```swift
import Testing
import ThreatModelKit

struct PathwayMitigationTests {
    @Test func startsWithTheMasterToggleOff() {
        let settings = PathwayMitigationSettings()

        // A model must not score lower than the catalogue says until the user
        // states the mitigation is real on their system.
        #expect(settings.isMasterEnabled == false)
        #expect(settings.configs.isEmpty)
    }

    @Test func startsEachMitigationEnabledAtHalfReduction() {
        let settings = PathwayMitigationSettings()
        let config = settings.config(for: PathwayMitigationId("waf-protection"))

        #expect(config == PathwayMitigationSettings.defaultConfig)
        #expect(config.isEnabled)
        #expect(config.mode == .reduce)
        #expect(config.reductionPercent == 50)
    }

    @Test func remembersTheConfigTheUserSet() {
        let id = PathwayMitigationId("waf-protection")
        let settings = PathwayMitigationSettings(
            isMasterEnabled: true,
            configs: [id: PathwayMitigationConfig(isEnabled: false, mode: .remove, reductionPercent: 90)]
        )

        let config = settings.config(for: id)
        #expect(config.isEnabled == false)
        #expect(config.mode == .remove)
        #expect(config.reductionPercent == 90)
    }

    @Test func dropsAThreatEntirelyInRemoveMode() {
        #expect(PathwayMitigation.outcome(score: 12, mode: .remove, percent: 0) == .removed)
        #expect(PathwayMitigation.outcome(score: 1, mode: .remove, percent: 90) == .removed)
    }

    @Test func lowersAScoreInReduceMode() {
        // max(1, floor(score - score * percent / 100)). Spec section 5.3.
        #expect(PathwayMitigation.outcome(score: 12, mode: .reduce, percent: 50) == .reduced(to: 6))
        #expect(PathwayMitigation.outcome(score: 12, mode: .reduce, percent: 25) == .reduced(to: 9))
        #expect(PathwayMitigation.outcome(score: 7, mode: .reduce, percent: 30) == .reduced(to: 4))
    }

    @Test func neverReducesAThreatToNothing() {
        #expect(PathwayMitigation.outcome(score: 12, mode: .reduce, percent: 100) == .reduced(to: 1))
        #expect(PathwayMitigation.outcome(score: 1, mode: .reduce, percent: 99) == .reduced(to: 1))
    }

    @Test func leavesAScoreAloneAtNoReduction() {
        #expect(PathwayMitigation.outcome(score: 12, mode: .reduce, percent: 0) == .reduced(to: 12))
    }

    @Test func floorsRatherThanRounds() {
        // 7 - 7 * 10 / 100 = 6.3, which floors to 6 rather than rounding to 6.
        // 9 - 9 * 5 / 100 = 8.55, which floors to 8 and would round to 9.
        #expect(PathwayMitigation.outcome(score: 9, mode: .reduce, percent: 5) == .reduced(to: 8))
    }

    @Test func picksTheHighestOfManySensitivities() {
        #expect(SensitivityLadder.highest(of: []) == nil)
        #expect(SensitivityLadder.highest(of: [.publicData]) == .publicData)
        #expect(SensitivityLadder.highest(of: [.publicData, .restricted, .internalData]) == .restricted)
    }

    @Test func aModelStartsWithNoMitigationsSwitchedOn() {
        #expect(ThreatModel().pathwayMitigations == PathwayMitigationSettings())
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter PathwayMitigationTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'PathwayMitigationSettings' in scope`.

- [ ] **Step 3: Write the settings and the modes**

Create `.../assessment/domain/PathwayMitigation.swift`:

```swift
import Foundation

/// What a mitigation does to a threat it answers.
public enum PathwayMitigationMode: String, CaseIterable, Equatable, Sendable {
    /// The threat is dropped entirely.
    case remove
    /// The score is lowered but never to nothing.
    case reduce

    public var label: String {
        switch self {
        case .remove: "Remove the threat"
        case .reduce: "Lower the score"
        }
    }
}

/// How the user has set one mitigation.
public struct PathwayMitigationConfig: Equatable, Sendable {
    public let isEnabled: Bool
    public let mode: PathwayMitigationMode
    /// 0 to 100. Only read in `reduce` mode.
    public let reductionPercent: Int

    public init(isEnabled: Bool, mode: PathwayMitigationMode, reductionPercent: Int) {
        self.isEnabled = isEnabled
        self.mode = mode
        self.reductionPercent = reductionPercent
    }
}

/// Every pathway mitigation setting on a model.
///
/// The master toggle starts off: a model must not score lower than the
/// catalogue says until the user states the mitigation is real on their
/// system. A mitigation the user has never touched takes `defaultConfig`.
public struct PathwayMitigationSettings: Equatable, Sendable {
    public static let defaultConfig = PathwayMitigationConfig(
        isEnabled: true,
        mode: .reduce,
        reductionPercent: 50
    )

    public var isMasterEnabled: Bool
    public var configs: [PathwayMitigationId: PathwayMitigationConfig]

    public init(
        isMasterEnabled: Bool = false,
        configs: [PathwayMitigationId: PathwayMitigationConfig] = [:]
    ) {
        self.isMasterEnabled = isMasterEnabled
        self.configs = configs
    }

    public func config(for id: PathwayMitigationId) -> PathwayMitigationConfig {
        configs[id] ?? Self.defaultConfig
    }
}

/// What happened to a threat's score.
public enum PathwayMitigationOutcome: Equatable, Sendable {
    case unchanged
    case removed
    case reduced(to: Int)
}

/// What a mitigation does to a score. Spec section 5.3.
public enum PathwayMitigation {
    /// `remove` drops the threat. `reduce` gives
    /// `max(1, floor(score − score × percent / 100))`, so a reduced threat
    /// never reaches zero: a control that lowers a risk has not removed it.
    public static func outcome(
        score: Int,
        mode: PathwayMitigationMode,
        percent: Int
    ) -> PathwayMitigationOutcome {
        switch mode {
        case .remove:
            return .removed
        case .reduce:
            let reduced = Double(score) - Double(score) * Double(percent) / 100
            return .reduced(to: max(1, Int(reduced.rounded(.down))))
        }
    }
}
```

- [ ] **Step 4: Give the model its settings and the ladder its highest-of-many rule**

Add to `ThreatModel` as the last stored property and the last initialiser parameter, defaulting to `PathwayMitigationSettings()`:

```swift
    /// How the user has set the pathway mitigations. Starts with the master
    /// toggle off, so nothing is mitigated until they say so.
    public var pathwayMitigations: PathwayMitigationSettings
```

Add to `SensitivityLadder`:

```swift
    /// The highest of many, or nil for none. A pathway threat escalates to the
    /// highest sensitivity among the components it directly feeds.
    public static func highest(of sensitivities: [DataSensitivity]) -> DataSensitivity? {
        sensitivities.max { $0.rank < $1.rank }
    }
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit
git commit -m "feat: add the pathway mitigation settings and modes

The master toggle starts off, so a model never scores lower than the
catalogue says until the user states the mitigation is real. Reduce floors
rather than rounds and never reaches zero: a control that lowers a risk has
not removed it."
```

---

### Task 4: `ListPathwayMitigations` and `ConfigurePathwayMitigations`

**Files:**
- Create: `.../catalogue/usecase/ListPathwayMitigations.swift`
- Create: `.../assessment/usecase/ConfigurePathwayMitigations.swift`
- Modify: `.../UseCaseFactory.swift`, `.../TestDependencies.swift`, `threatmodeller/Dependencies.swift`
- Test: `.../UnitTests/ListPathwayMitigationsTests.swift`, `.../UnitTests/ConfigurePathwayMitigationsTests.swift`

**Interfaces:**
- Produces: `ListPathwayMitigationsUseCase`, `ListPathwayMitigationsRequest()`, `ListPathwayMitigationsResponse(isMasterEnabled:mitigations:)`, `ListedPathwayMitigation(id:label:description:isEnabled:mode:reductionPercent:providedByTechnologyNames:mitigatedThreatNames:isProvidedOnThisModel:)`; `ConfigurePathwayMitigationsUseCase`, `ConfigurePathwayMitigationsRequest(isMasterEnabled:mitigationId:isEnabled:mode:reductionPercent:)`, `ConfigurePathwayMitigationsResponse` (`.configured`, `.unknownMitigation`, `.unknownMode`, `.reductionOutOfRange`).

`ListPathwayMitigations` reads the model as well as the catalogue, because the settings screen has to say whether anything on this diagram actually provides each mitigation. A switch the user turns on that nothing provides changes no score, and the screen should say so rather than leave them guessing.

- [ ] **Step 1: Write the failing tests**

Create `.../UnitTests/ListPathwayMitigationsTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct ListPathwayMitigationsTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func list(_ model: ThreatModel) -> ListPathwayMitigationsResponse {
        ListPathwayMitigations(models: InMemoryThreatModelGateway(model), catalogue: catalogue)
            .execute(ListPathwayMitigationsRequest())
    }

    private func component(_ id: String, _ technologyId: String) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId(technologyId),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData
        )
    }

    @Test func listsEveryMitigationTheCatalogueDefines() throws {
        let listed = list(ThreatModel())

        #expect(listed.mitigations.map(\.id) == ["waf-protection"])
        let waf = try #require(listed.mitigations.first)
        #expect(waf.label == "WAF Protection")
        #expect(waf.description.isEmpty == false)
    }

    @Test func startsWithTheMasterToggleOffAndEachMitigationOn() throws {
        let listed = list(ThreatModel())

        #expect(listed.isMasterEnabled == false)
        let waf = try #require(listed.mitigations.first)
        #expect(waf.isEnabled)
        #expect(waf.mode == "reduce")
        #expect(waf.reductionPercent == 50)
    }

    @Test func showsWhatTheUserSet() throws {
        let listed = list(
            ThreatModel(
                pathwayMitigations: PathwayMitigationSettings(
                    isMasterEnabled: true,
                    configs: [
                        PathwayMitigationId("waf-protection"):
                            PathwayMitigationConfig(isEnabled: false, mode: .remove, reductionPercent: 90)
                    ]
                )
            )
        )

        #expect(listed.isMasterEnabled)
        let waf = try #require(listed.mitigations.first)
        #expect(waf.isEnabled == false)
        #expect(waf.mode == "remove")
        #expect(waf.reductionPercent == 90)
    }

    @Test func namesWhatProvidesItAndWhatItAnswers() throws {
        let waf = try #require(list(ThreatModel()).mitigations.first)

        #expect(waf.providedByTechnologyNames == ["WAF"])
        #expect(waf.mitigatedThreatNames.sorted() == ["Connection Flooding", "Credential Theft"])
    }

    @Test func saysWhenNothingOnThisModelProvidesIt() throws {
        // A switch the user turns on that nothing provides changes no score.
        // The screen says so rather than leaving them guessing.
        #expect(try #require(list(ThreatModel()).mitigations.first).isProvidedOnThisModel == false)

        let withWaf = list(ThreatModel(components: [component("c1", "aws-waf")]))
        #expect(try #require(withWaf.mitigations.first).isProvidedOnThisModel)

        let withoutWaf = list(ThreatModel(components: [component("c1", "aws-ec2")]))
        #expect(try #require(withoutWaf.mitigations.first).isProvidedOnThisModel == false)
    }
}
```

Create `.../UnitTests/ConfigurePathwayMitigationsTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct ConfigurePathwayMitigationsTests {
    private let models = InMemoryThreatModelGateway()
    private let catalogue = CatalogueFixture.catalogue()
    private let waf = PathwayMitigationId("waf-protection")

    private func configure(
        master: Bool = true,
        id: String? = nil,
        enabled: Bool = true,
        mode: String = "reduce",
        percent: Int = 50
    ) -> ConfigurePathwayMitigationsResponse {
        ConfigurePathwayMitigations(models: models, catalogue: catalogue).execute(
            ConfigurePathwayMitigationsRequest(
                isMasterEnabled: master,
                mitigationId: id,
                isEnabled: enabled,
                mode: mode,
                reductionPercent: percent
            )
        )
    }

    private func settings() -> PathwayMitigationSettings {
        models.current().pathwayMitigations
    }

    @Test func turnsTheMasterToggleOnWithoutTouchingAMitigation() {
        #expect(configure(master: true, id: nil) == .configured)

        #expect(settings().isMasterEnabled)
        #expect(settings().configs.isEmpty)
    }

    @Test func setsOneMitigation() {
        #expect(configure(id: "waf-protection", enabled: false, mode: "remove", percent: 80) == .configured)

        #expect(settings().isMasterEnabled)
        #expect(settings().config(for: waf)
                == PathwayMitigationConfig(isEnabled: false, mode: .remove, reductionPercent: 80))
    }

    @Test func leavesEveryOtherMitigationAlone() {
        _ = configure(id: "waf-protection", mode: "remove")

        #expect(settings().configs.count == 1)
    }

    @Test func refusesAMitigationTheCatalogueDoesNotDefine() {
        #expect(configure(id: "magic-shield") == .unknownMitigation)
        #expect(settings().configs.isEmpty)
        #expect(settings().isMasterEnabled == false)
    }

    @Test func refusesAModeItDoesNotKnow() {
        #expect(configure(id: "waf-protection", mode: "obliterate") == .unknownMode)
        #expect(settings().configs.isEmpty)
    }

    @Test func refusesAReductionOutsideZeroToOneHundred() {
        #expect(configure(id: "waf-protection", percent: -1) == .reductionOutOfRange)
        #expect(configure(id: "waf-protection", percent: 101) == .reductionOutOfRange)
        #expect(settings().configs.isEmpty)
    }

    @Test func turnsTheMasterToggleBackOff() {
        _ = configure(master: true, id: "waf-protection")

        #expect(configure(master: false, id: nil) == .configured)
        #expect(settings().isMasterEnabled == false)
        // The per-mitigation settings survive, so turning the master back on
        // restores what the user had.
        #expect(settings().configs.count == 1)
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter PathwayMitigations 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'ListPathwayMitigations' in scope`.

- [ ] **Step 3: Write `ListPathwayMitigations`**

Create `.../catalogue/usecase/ListPathwayMitigations.swift`:

```swift
public protocol ListPathwayMitigationsUseCase {
    func execute(_ request: ListPathwayMitigationsRequest) -> ListPathwayMitigationsResponse
}

public struct ListPathwayMitigationsRequest: Equatable, Sendable {
    public init() {}
}

public struct ListedPathwayMitigation: Equatable, Sendable {
    public let id: String
    public let label: String
    public let description: String
    public let isEnabled: Bool
    public let mode: String
    public let reductionPercent: Int
    /// The technologies that provide it, by name, so the screen can say what
    /// the user would have to add.
    public let providedByTechnologyNames: [String]
    /// The threats it answers, by name.
    public let mitigatedThreatNames: [String]
    /// True when something on this diagram provides it. A switch turned on
    /// that nothing provides changes no score.
    public let isProvidedOnThisModel: Bool

    public init(
        id: String,
        label: String,
        description: String,
        isEnabled: Bool,
        mode: String,
        reductionPercent: Int,
        providedByTechnologyNames: [String],
        mitigatedThreatNames: [String],
        isProvidedOnThisModel: Bool
    ) {
        self.id = id
        self.label = label
        self.description = description
        self.isEnabled = isEnabled
        self.mode = mode
        self.reductionPercent = reductionPercent
        self.providedByTechnologyNames = providedByTechnologyNames
        self.mitigatedThreatNames = mitigatedThreatNames
        self.isProvidedOnThisModel = isProvidedOnThisModel
    }
}

public struct ListPathwayMitigationsResponse: Equatable, Sendable {
    public let isMasterEnabled: Bool
    public let mitigations: [ListedPathwayMitigation]

    public init(isMasterEnabled: Bool, mitigations: [ListedPathwayMitigation]) {
        self.isMasterEnabled = isMasterEnabled
        self.mitigations = mitigations
    }
}

/// The pathway mitigation settings screen's contents.
///
/// It reads the model as well as the catalogue, because a mitigation nothing
/// on this diagram provides changes no score however the user sets it, and the
/// screen should say so rather than leave them guessing.
public struct ListPathwayMitigations: ListPathwayMitigationsUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: ListPathwayMitigationsRequest) -> ListPathwayMitigationsResponse {
        let model = models.current()
        let settings = model.pathwayMitigations
        let present = Set(model.components.map(\.technologyId))

        // Every threat the catalogue knows, so a mitigation can be named after
        // what it answers rather than after threat ids.
        var threatNames: [ThreatId: String] = [:]
        for technology in catalogue.all() {
            for threat in catalogue.threatsFor(technologyId: technology.id) {
                threatNames[threat.id] = threat.name
            }
        }
        for threat in catalogue.connectionThreats() + catalogue.zoneThreats() {
            threatNames[threat.id] = threat.name
        }

        return ListPathwayMitigationsResponse(
            isMasterEnabled: settings.isMasterEnabled,
            mitigations: catalogue.pathwayMitigations().map { definition in
                let config = settings.config(for: definition.id)
                return ListedPathwayMitigation(
                    id: definition.id.value,
                    label: definition.label,
                    description: definition.description,
                    isEnabled: config.isEnabled,
                    mode: config.mode.rawValue,
                    reductionPercent: config.reductionPercent,
                    providedByTechnologyNames: definition.technologyIds.compactMap {
                        catalogue.findById($0)?.name
                    },
                    mitigatedThreatNames: definition.mitigatesThreatIds.compactMap { threatNames[$0] },
                    isProvidedOnThisModel: definition.technologyIds.contains(where: present.contains)
                )
            }
        )
    }
}
```

- [ ] **Step 4: Write `ConfigurePathwayMitigations`**

Create `.../assessment/usecase/ConfigurePathwayMitigations.swift`:

```swift
public protocol ConfigurePathwayMitigationsUseCase {
    func execute(_ request: ConfigurePathwayMitigationsRequest) -> ConfigurePathwayMitigationsResponse
}

public struct ConfigurePathwayMitigationsRequest: Equatable, Sendable {
    public let isMasterEnabled: Bool
    /// Nil to set only the master toggle. Otherwise the mitigation to set, and
    /// the three values below apply to it.
    public let mitigationId: String?
    public let isEnabled: Bool
    public let mode: String
    /// 0 to 100 inclusive.
    public let reductionPercent: Int

    public init(
        isMasterEnabled: Bool,
        mitigationId: String?,
        isEnabled: Bool,
        mode: String,
        reductionPercent: Int
    ) {
        self.isMasterEnabled = isMasterEnabled
        self.mitigationId = mitigationId
        self.isEnabled = isEnabled
        self.mode = mode
        self.reductionPercent = reductionPercent
    }
}

public enum ConfigurePathwayMitigationsResponse: Equatable, Sendable {
    case configured
    case unknownMitigation
    case unknownMode
    case reductionOutOfRange
}

/// Sets the master toggle, and one mitigation at a time.
///
/// All or nothing: one bad value leaves every setting as it was, so a rejected
/// form never half-applies. Turning the master toggle off keeps the
/// per-mitigation settings, so turning it back on restores what the user had.
public struct ConfigurePathwayMitigations: ConfigurePathwayMitigationsUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(
        _ request: ConfigurePathwayMitigationsRequest
    ) -> ConfigurePathwayMitigationsResponse {
        var model = models.current()

        if let rawId = request.mitigationId {
            let id = PathwayMitigationId(rawId)
            guard catalogue.pathwayMitigations().contains(where: { $0.id == id }) else {
                return .unknownMitigation
            }
            guard let mode = PathwayMitigationMode(rawValue: request.mode) else {
                return .unknownMode
            }
            guard (0...100).contains(request.reductionPercent) else {
                return .reductionOutOfRange
            }

            model.pathwayMitigations.configs[id] = PathwayMitigationConfig(
                isEnabled: request.isEnabled,
                mode: mode,
                reductionPercent: request.reductionPercent
            )
        }

        model.pathwayMitigations.isMasterEnabled = request.isMasterEnabled
        models.save(model)

        return .configured
    }
}
```

- [ ] **Step 5: Vend them from both composition roots**

Add to `UseCaseFactory`:

```swift
    func listPathwayMitigations() -> ListPathwayMitigationsUseCase
    func configurePathwayMitigations() -> ConfigurePathwayMitigationsUseCase
```

Add to `TestDependencies` and `Dependencies`:

```swift
    func listPathwayMitigations() -> ListPathwayMitigationsUseCase {
        ListPathwayMitigations(models: models, catalogue: catalogue)
    }

    func configurePathwayMitigations() -> ConfigurePathwayMitigationsUseCase {
        ConfigurePathwayMitigations(models: models, catalogue: catalogue)
    }
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit threatmodeller/Dependencies.swift
git commit -m "feat: list and configure the pathway mitigations

The list reads the model as well as the catalogue, so the screen can say when
nothing on this diagram provides a mitigation. Turning the master toggle off
keeps the per-mitigation settings."
```

---

### Task 5: A pathway threat escalates to what it feeds

**Files:**
- Modify: `.../assessment/domain/ThreatResolver.swift`
- Modify: `ThreatModelKit/Tests/UnitTests/AssessThreatModelTests.swift`

**Interfaces:**
- Consumes: `UpstreamGraph.directlyDownstream(of:)`, `SensitivityLadder.highest(of:)`, `Threat.isPathwayThreat`.
- Produces: nothing new on the boundary. The score changes; `sensitivityId` reports the escalated sensitivity.

Spec §5.3: a threat flagged `isPathwayThreat` escalates its sensitivity to the highest sensitivity among the components **directly** downstream of it, when that is higher than its own. A component holding public data that feeds a component holding restricted data is a way into restricted data.

In `CatalogueFixture`, `credential-theft` and `dos-attack` carry `isPathwayThreat: true`; `misconfiguration` does not.

- [ ] **Step 1: Write the failing test**

Add to `AssessThreatModelTests`:

```swift
    @Test func escalatesAPathwayThreatToTheDataItFeeds() throws {
        // EC2 holds public data (1) and feeds RDS holding restricted (4).
        // Credential theft is a pathway threat and is critical (4), so it
        // scores 4 x 4 = 16 rather than 4 x 1 = 4.
        let response = assess(
            ThreatModel(
                components: [
                    ec2(id: "c1", sensitivity: .publicData),
                    rds(sensitivity: .restricted)
                ],
                connections: [link("k1", "c1", "c2")]
            )
        )

        let theft = try #require(response.threats.first {
            $0.threatId == "credential-theft" && $0.source.id == "component:c1"
        })
        #expect(theft.sensitivityId == "restricted")
        #expect(theft.riskScore == 16)
    }

    @Test func leavesAThreatThatIsNotAPathwayThreatAlone() throws {
        let response = assess(
            ThreatModel(
                components: [
                    ec2(id: "c1", sensitivity: .publicData),
                    rds(sensitivity: .restricted)
                ],
                connections: [link("k1", "c1", "c2")]
            )
        )

        // Misconfiguration is not a pathway threat, so it stays on public data.
        let misconfiguration = try #require(response.threats.first {
            $0.threatId == "misconfiguration" && $0.source.id == "component:c1"
        })
        #expect(misconfiguration.sensitivityId == "public")
        #expect(misconfiguration.riskScore == 2)
    }

    @Test func neverEscalatesDownwards() throws {
        // EC2 holds restricted data and feeds RDS holding public. The threat
        // keeps its own higher sensitivity.
        let response = assess(
            ThreatModel(
                components: [
                    ec2(id: "c1", sensitivity: .restricted),
                    rds(sensitivity: .publicData)
                ],
                connections: [link("k1", "c1", "c2")]
            )
        )

        #expect(try #require(response.threats.first {
            $0.threatId == "credential-theft" && $0.source.id == "component:c1"
        }).sensitivityId == "restricted")
    }

    @Test func escalatesOnlyOneHopForward() throws {
        // a -> b -> c. The threat on a escalates to b's data, not to c's.
        let response = assess(
            ThreatModel(
                components: [
                    ec2(id: "c1", sensitivity: .publicData),
                    rds(id: "c2", sensitivity: .internalData),
                    ec2(id: "c3", sensitivity: .restricted)
                ],
                connections: [link("k1", "c1", "c2"), link("k2", "c2", "c3")]
            )
        )

        #expect(try #require(response.threats.first {
            $0.threatId == "credential-theft" && $0.source.id == "component:c1"
        }).sensitivityId == "internal")
    }

    @Test func escalatesToTheHighestOfSeveralBranches() throws {
        let response = assess(
            ThreatModel(
                components: [
                    ec2(id: "c1", sensitivity: .publicData),
                    rds(id: "c2", sensitivity: .internalData),
                    rds(id: "c3", sensitivity: .confidential)
                ],
                connections: [link("k1", "c1", "c2"), link("k2", "c1", "c3")]
            )
        )

        #expect(try #require(response.threats.first {
            $0.threatId == "credential-theft" && $0.source.id == "component:c1"
        }).sensitivityId == "confidential")
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter AssessThreatModelTests 2>&1 | grep -E '✘' | head -5
```

Expected: FAIL — the escalated scores come back unescalated.

- [ ] **Step 3: Escalate in the resolver**

Build the graph once, above the component loop, beside the zone map:

```swift
        let graph = UpstreamGraph(connections: model.connections)
        var sensitivityById: [ComponentId: DataSensitivity] = [:]
        for component in model.components {
            sensitivityById[component.id] = component.sensitivity
        }
```

Add the helper:

```swift
    /// Spec section 5.3: a pathway threat escalates to the highest sensitivity
    /// among the components it directly feeds, when that is higher than its
    /// own. A component holding public data that feeds restricted data is a
    /// way into restricted data.
    private func sensitivity(
        for threat: Threat,
        on component: Component,
        graph: UpstreamGraph,
        sensitivityById: [ComponentId: DataSensitivity]
    ) -> DataSensitivity {
        guard threat.isPathwayThreat else { return component.sensitivity }
        let downstream = graph.directlyDownstream(of: component.id).compactMap { sensitivityById[$0] }
        guard let highest = SensitivityLadder.highest(of: downstream) else {
            return component.sensitivity
        }
        return SensitivityLadder.higher(component.sensitivity, highest)
    }
```

In the component loop, replace `sensitivity: component.sensitivity` in the score and in the raised threat with the escalated value:

```swift
                let sensitivity = sensitivity(
                    for: threat,
                    on: component,
                    graph: graph,
                    sensitivityById: sensitivityById
                )
                let base = RiskScore(severity: chosen.severity, sensitivity: sensitivity)
```

and pass `sensitivity: sensitivity` on the `ResolvedThreat`.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit
git commit -m "feat: escalate a pathway threat to the data it feeds

A component holding public data that feeds restricted data is a way into
restricted data, so a threat flagged as a pathway threat is scored against
the higher sensitivity. One hop forward only, and never downwards."
```

---

### Task 6: An upstream mitigation answers the threat

**Files:**
- Modify: `.../assessment/domain/ThreatResolver.swift`
- Modify: `.../assessment/usecase/AssessThreatModel.swift`
- Modify: `ThreatModelKit/Tests/UnitTests/AssessThreatModelTests.swift`

**Interfaces:**
- Consumes: `UpstreamGraph.upstream(of:)`, `PathwayMitigation.outcome(score:mode:percent:)`, `TechnologyCatalogue.pathwayMitigations()`, `ThreatModel.pathwayMitigations`.
- Produces: `ResolvedThreat.mitigatedBy: [PathwayMitigationDefinition]` and `.scoreBeforePathwayMitigation: Int`; `AssessedThreat.pathwayMitigationLabels: [String]` and `.scoreBeforePathwayMitigation: Int`.

Decisions this task fixes, because the spec leaves them open:

- **A zone threat is never pathway-mitigated.** A zone sits nowhere in the connection graph, so it has nothing upstream. Spec §5.3 speaks only of components and links.
- **When two mitigations both answer a threat, `remove` wins.** Among two reductions, the one leaving the lower score wins. A user who has switched on two controls that both answer a threat gets the stronger of the two, not the sum.

- [ ] **Step 1: Write the failing test**

Add to `AssessThreatModelTests`. A helper first:

```swift
    private func waf(_ id: String = "w1", sensitivity: DataSensitivity = .internalData) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-waf"),
            position: Point(x: 0, y: 0),
            sensitivity: sensitivity
        )
    }

    private func mitigationsOn(
        mode: PathwayMitigationMode = .reduce,
        percent: Int = 50,
        enabled: Bool = true
    ) -> PathwayMitigationSettings {
        PathwayMitigationSettings(
            isMasterEnabled: true,
            configs: [
                PathwayMitigationId("waf-protection"):
                    PathwayMitigationConfig(isEnabled: enabled, mode: mode, reductionPercent: percent)
            ]
        )
    }
```

Then the cases:

```swift
    @Test func lowersAThreatAnUpstreamMitigationAnswers() throws {
        // WAF -> EC2. The fixture's waf-protection answers credential-theft.
        // 12 reduced by half floors to 6.
        let response = assess(
            ThreatModel(
                components: [waf(), ec2(id: "c1")],
                connections: [link("k1", "w1", "c1")],
                pathwayMitigations: mitigationsOn()
            )
        )

        let theft = try #require(response.threats.first {
            $0.threatId == "credential-theft" && $0.source.id == "component:c1"
        })
        #expect(theft.riskScore == 6)
        #expect(theft.scoreBeforePathwayMitigation == 12)
        #expect(theft.pathwayMitigationLabels == ["WAF Protection"])
    }

    @Test func dropsAThreatEntirelyInRemoveMode() {
        let response = assess(
            ThreatModel(
                components: [waf(), ec2(id: "c1")],
                connections: [link("k1", "w1", "c1")],
                pathwayMitigations: mitigationsOn(mode: .remove)
            )
        )

        #expect(response.threats.contains {
            $0.threatId == "credential-theft" && $0.source.id == "component:c1"
        } == false)
    }

    @Test func leavesAThreatAloneWhileTheMasterToggleIsOff() throws {
        let response = assess(
            ThreatModel(
                components: [waf(), ec2(id: "c1")],
                connections: [link("k1", "w1", "c1")],
                pathwayMitigations: PathwayMitigationSettings(isMasterEnabled: false)
            )
        )

        let theft = try #require(response.threats.first {
            $0.threatId == "credential-theft" && $0.source.id == "component:c1"
        })
        #expect(theft.riskScore == 12)
        #expect(theft.pathwayMitigationLabels.isEmpty)
    }

    @Test func leavesAThreatAloneWhileThatMitigationIsOff() throws {
        let response = assess(
            ThreatModel(
                components: [waf(), ec2(id: "c1")],
                connections: [link("k1", "w1", "c1")],
                pathwayMitigations: mitigationsOn(enabled: false)
            )
        )

        #expect(try #require(response.threats.first {
            $0.threatId == "credential-theft" && $0.source.id == "component:c1"
        }).riskScore == 12)
    }

    @Test func leavesAThreatAloneWhenTheMitigationIsNotUpstream() throws {
        // EC2 -> WAF. The WAF is downstream, so it answers nothing here.
        let response = assess(
            ThreatModel(
                components: [waf(), ec2(id: "c1")],
                connections: [link("k1", "c1", "w1")],
                pathwayMitigations: mitigationsOn()
            )
        )

        #expect(try #require(response.threats.first {
            $0.threatId == "credential-theft" && $0.source.id == "component:c1"
        }).riskScore == 12)
    }

    @Test func leavesAThreatTheMitigationDoesNotAnswerAlone() throws {
        // waf-protection answers credential-theft, not misconfiguration.
        let response = assess(
            ThreatModel(
                components: [waf(), ec2(id: "c1")],
                connections: [link("k1", "w1", "c1")],
                pathwayMitigations: mitigationsOn()
            )
        )

        #expect(try #require(response.threats.first {
            $0.threatId == "misconfiguration" && $0.source.id == "component:c1"
        }).riskScore == 6)
    }

    @Test func reachesThroughEveryHop() throws {
        // WAF -> RDS -> EC2. The WAF is still upstream of EC2.
        let response = assess(
            ThreatModel(
                components: [waf(), rds(id: "c2"), ec2(id: "c1")],
                connections: [link("k1", "w1", "c2"), link("k2", "c2", "c1")],
                pathwayMitigations: mitigationsOn()
            )
        )

        #expect(try #require(response.threats.first {
            $0.threatId == "credential-theft" && $0.source.id == "component:c1"
        }).riskScore == 6)
    }

    @Test func neverLetsAComponentMitigateItsOwnThreats() throws {
        // The WAF alone. Upstream is strict, so its own threats are untouched.
        let response = assess(
            ThreatModel(
                components: [waf(), ec2(id: "c1", sensitivity: .confidential)],
                connections: [link("k1", "c1", "w1")],
                pathwayMitigations: mitigationsOn()
            )
        )

        #expect(try #require(response.threats.first {
            $0.threatId == "credential-theft" && $0.source.id == "component:c1"
        }).riskScore == 12)
    }

    @Test func usesTheSourcesUpstreamForALinksThreats() throws {
        // WAF -> EC2 -> RDS. The link EC2 to RDS takes the WAF, because the
        // WAF is upstream of the link's source. Spec section 5.3.
        // connection-dos is low (1) against internal (2), so 2; halved floors
        // to 1.
        let response = assess(
            ThreatModel(
                components: [
                    waf(),
                    ec2(id: "c1", sensitivity: .internalData),
                    rds(id: "c2", sensitivity: .internalData)
                ],
                connections: [link("k1", "w1", "c1"), link("k2", "c1", "c2")],
                pathwayMitigations: mitigationsOn()
            )
        )

        let flood = try #require(response.threats.first {
            $0.threatId == "connection-dos" && $0.source.id == "connection:k2"
        })
        #expect(flood.riskScore == 1)
        #expect(flood.scoreBeforePathwayMitigation == 2)
    }

    @Test func neverMitigatesAZoneThreat() throws {
        // A zone sits nowhere in the connection graph, so nothing is upstream
        // of it. The fixture's mitigation does not answer a zone threat either,
        // but the rule holds whatever the catalogue says.
        let response = assess(
            ThreatModel(
                components: [waf(), ec2(id: "c1")],
                connections: [link("k1", "w1", "c1")],
                zones: [privateZone("z1")],
                pathwayMitigations: mitigationsOn(mode: .remove)
            )
        )

        #expect(response.threats.contains { $0.source.id == "zone:z1" })
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter AssessThreatModelTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `has no member 'pathwayMitigationLabels'`.

- [ ] **Step 3: Apply the mitigation in the resolver**

Add the two fields to `ResolvedThreat`, as the last stored properties and initialiser parameters:

```swift
    /// The mitigations that answered this threat. Empty when none did.
    public let mitigatedBy: [PathwayMitigationDefinition]
    /// The score before any pathway mitigation. Equal to `score.value` when
    /// none applied.
    public let scoreBeforePathwayMitigation: Int
```

Add the helper to `ThreatResolver`:

```swift
    /// What the mitigations upstream of a component do to a threat's score.
    ///
    /// Nil means the threat is dropped. Spec section 5.3: it applies when the
    /// master toggle is on, that mitigation is enabled, a strictly upstream
    /// component's technology provides it, and the mitigation lists the threat
    /// id. Where two mitigations both answer, `remove` wins, and among two
    /// reductions the one leaving the lower score wins: the user gets the
    /// stronger of the controls they switched on, not the sum of them.
    private func mitigated(
        threat: Threat,
        score: Int,
        upstreamOf component: ComponentId,
        graph: UpstreamGraph,
        technologyById: [ComponentId: TechnologyId]
    ) -> (score: Int, by: [PathwayMitigationDefinition])? {
        let settings = model.pathwayMitigations
        guard settings.isMasterEnabled else { return (score, []) }

        let upstreamTechnologies = Set(
            graph.upstream(of: component).compactMap { technologyById[$0] }
        )
        guard upstreamTechnologies.isEmpty == false else { return (score, []) }

        var lowest = score
        var applied: [PathwayMitigationDefinition] = []

        for definition in catalogue.pathwayMitigations() {
            let config = settings.config(for: definition.id)
            guard config.isEnabled,
                  definition.mitigates(threat.id),
                  upstreamTechnologies.contains(where: definition.isProvidedBy) else { continue }

            applied.append(definition)

            switch PathwayMitigation.outcome(
                score: score,
                mode: config.mode,
                percent: config.reductionPercent
            ) {
            case .removed:
                return nil
            case .reduced(let to):
                lowest = min(lowest, to)
            case .unchanged:
                break
            }
        }

        return (lowest, applied)
    }
```

Build `technologyById` beside `sensitivityById`, then at the component raise site work the mitigation out after the zone multiplier and before `raise`:

```swift
                guard let mitigation = mitigated(
                    threat: threat,
                    score: score.value,
                    upstreamOf: component.id,
                    graph: graph,
                    technologyById: technologyById
                ) else { continue }
                let finalScore = RiskScore(value: mitigation.score)
```

Pass `score: finalScore`, `mitigatedBy: mitigation.by`, `scoreBeforePathwayMitigation: score.value`.

At the link raise site do the same, but `upstreamOf: source.id` — spec §5.3 says a link's threats use the source component's upstream mitigations.

At the zone raise site pass `mitigatedBy: []` and `scoreBeforePathwayMitigation: score.value`. A zone sits nowhere in the connection graph.

- [ ] **Step 4: Carry them onto the response**

Add to `AssessedThreat`, after `overriddenSeverityId`, with matching initialiser parameters:

```swift
    /// The pathway mitigations that answered this threat, by label. Empty when
    /// none did.
    public let pathwayMitigationLabels: [String]
    /// The score before any pathway mitigation. Equal to `riskScore` when none
    /// applied, so a card can show what the mitigation bought.
    public let scoreBeforePathwayMitigation: Int
```

and map them in `execute`:

```swift
                    pathwayMitigationLabels: threat.mitigatedBy.map(\.label),
                    scoreBeforePathwayMitigation: threat.scoreBeforePathwayMitigation
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' build 2>&1 | grep -E 'error:|BUILD' | head -5
```

Expected: PASS and BUILD SUCCEEDED.

- [ ] **Step 6: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit
git commit -m "feat: let an upstream mitigation answer a threat

A mitigation applies when the master toggle is on, it is enabled, a strictly
upstream component provides it, and it lists the threat. Remove drops the
threat; reduce lowers the score and never to nothing. A link takes its
source's upstream. A zone sits nowhere in the graph, so it takes none. Where
two mitigations answer, the stronger wins rather than the sum."
```

---

### Task 7: The acceptance test

**Files:**
- Create: `ThreatModelKit/Tests/AcceptanceTests/AnsweringThreatsUpstreamTests.swift`

- [ ] **Step 1: Write the test**

```swift
import Testing
import ThreatModelKit
import TestSupport

/// Given a control sitting in front of my application
/// When I say that control is real on my system
/// Then the threats it answers fall, and a threat feeding sensitive data rises
struct AnsweringThreatsUpstreamTests {
    private let app = TestDependencies()

    private func add(_ technologyId: String, sensitivity: String) -> String {
        let response = app.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: 0, y: 0, sensitivity: sensitivity)
        )
        guard case .added(let componentId) = response else {
            Issue.record("Expected the component to be added, got \(response)")
            return ""
        }
        return componentId
    }

    private func connect(_ source: String, _ target: String) {
        let response = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: source, targetComponentId: target)
        )
        guard case .connected = response else {
            Issue.record("Expected the link to be made, got \(response)")
            return
        }
    }

    private func threat(_ threatId: String, from sourceId: String) -> AssessedThreat? {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
            .first { $0.threatId == threatId && $0.source.id == sourceId }
    }

    private func turnOn(_ mitigationId: String, mode: String, percent: Int) {
        #expect(app.configurePathwayMitigations().execute(
            ConfigurePathwayMitigationsRequest(
                isMasterEnabled: true,
                mitigationId: mitigationId,
                isEnabled: true,
                mode: mode,
                reductionPercent: percent
            )
        ) == .configured)
    }

    @Test func raisesAThreatThatFeedsMoreSensitiveData() throws {
        let web = add("aws-ec2", sensitivity: "public")
        let database = add("aws-rds", sensitivity: "restricted")

        // Alone, credential theft on public data is critical (4) x public (1).
        #expect(threat("credential-theft", from: "component:\(web)")?.riskScore == 4)

        connect(web, database)

        // Feeding restricted data, it is scored against restricted.
        let escalated = try #require(threat("credential-theft", from: "component:\(web)"))
        #expect(escalated.sensitivityId == "restricted")
        #expect(escalated.riskScore == 16)
        #expect(escalated.riskLevel == "critical")
    }

    @Test func showsWhichMitigationsThisModelCanUse() throws {
        let listed = app.listPathwayMitigations().execute(ListPathwayMitigationsRequest())

        #expect(listed.isMasterEnabled == false)
        let waf = try #require(listed.mitigations.first { $0.id == "waf-protection" })
        #expect(waf.isProvidedOnThisModel == false)
        #expect(waf.providedByTechnologyNames == ["WAF"])

        _ = add("aws-waf", sensitivity: "internal")

        let after = app.listPathwayMitigations().execute(ListPathwayMitigationsRequest())
        #expect(try #require(after.mitigations.first).isProvidedOnThisModel)
    }

    @Test func lowersTheThreatsAControlInFrontAnswers() throws {
        let firewall = add("aws-waf", sensitivity: "internal")
        let web = add("aws-ec2", sensitivity: "confidential")
        connect(firewall, web)

        #expect(threat("credential-theft", from: "component:\(web)")?.riskScore == 12)

        turnOn("waf-protection", mode: "reduce", percent: 50)

        let lowered = try #require(threat("credential-theft", from: "component:\(web)"))
        #expect(lowered.riskScore == 6)
        #expect(lowered.scoreBeforePathwayMitigation == 12)
        #expect(lowered.pathwayMitigationLabels == ["WAF Protection"])
    }

    @Test func dropsTheThreatEntirelyWhenTheUserSaysRemove() throws {
        let firewall = add("aws-waf", sensitivity: "internal")
        let web = add("aws-ec2", sensitivity: "confidential")
        connect(firewall, web)

        turnOn("waf-protection", mode: "remove", percent: 0)

        #expect(threat("credential-theft", from: "component:\(web)") == nil)
        // Everything the mitigation does not answer stays.
        #expect(threat("misconfiguration", from: "component:\(web)") != nil)
    }

    @Test func changesNothingUntilTheUserSaysTheControlIsReal() throws {
        let firewall = add("aws-waf", sensitivity: "internal")
        let web = add("aws-ec2", sensitivity: "confidential")
        connect(firewall, web)

        // The catalogue knows the WAF provides the mitigation. The score does
        // not move until the master toggle goes on.
        #expect(threat("credential-theft", from: "component:\(web)")?.riskScore == 12)

        turnOn("waf-protection", mode: "reduce", percent: 50)
        #expect(threat("credential-theft", from: "component:\(web)")?.riskScore == 6)

        #expect(app.configurePathwayMitigations().execute(
            ConfigurePathwayMitigationsRequest(
                isMasterEnabled: false,
                mitigationId: nil,
                isEnabled: true,
                mode: "reduce",
                reductionPercent: 50
            )
        ) == .configured)
        #expect(threat("credential-theft", from: "component:\(web)")?.riskScore == 12)
    }

    @Test func lowersALinksThreatsFromWhatIsInFrontOfItsSource() throws {
        let firewall = add("aws-waf", sensitivity: "internal")
        let web = add("aws-ec2", sensitivity: "internal")
        let database = add("aws-rds", sensitivity: "internal")
        connect(firewall, web)
        connect(web, database)

        let link = try #require(
            app.viewThreatModel().execute(ViewThreatModelRequest()).connections
                .first { $0.sourceComponentId == web }
        ).id

        #expect(threat("connection-dos", from: "connection:\(link)")?.riskScore == 2)

        turnOn("waf-protection", mode: "reduce", percent: 50)

        #expect(threat("connection-dos", from: "connection:\(link)")?.riskScore == 1)
    }

    @Test func summarisesWhatTheMitigationLeaves() throws {
        let firewall = add("aws-waf", sensitivity: "internal")
        let web = add("aws-ec2", sensitivity: "confidential")
        connect(firewall, web)
        let before = app.summariseRisk().execute(SummariseRiskRequest())

        turnOn("waf-protection", mode: "remove", percent: 0)

        let after = app.summariseRisk().execute(SummariseRiskRequest())
        #expect(after.totalThreats < before.totalThreats)
        #expect(after.totalThreats
                == app.assessThreatModel().execute(AssessThreatModelRequest()).threats.count)
    }
}
```

- [ ] **Step 2: Run it, then the whole suite**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter AnsweringThreatsUpstreamTests 2>&1 | tail -5
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && time swift test 2>&1 | tail -3
```

Expected: PASS, whole suite under 30 seconds.

- [ ] **Step 3: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit/Tests/AcceptanceTests/AnsweringThreatsUpstreamTests.swift
git commit -m "test: accept the milestone 5 core at the use case boundary

A threat feeding more sensitive data is scored against it. A control in front
lowers or drops the threats it answers, and nothing moves until the user says
the control is real on their system."
```

---

### Task 8: The session and the settings panel

**Files:**
- Create: `threatmodeller/sidebar/PathwayMitigationsPanel.swift`
- Modify: `threatmodeller/ThreatModelSession.swift`
- Modify: `threatmodeller/sidebar/ThreatSidebar.swift`, `ThreatCard.swift`
- Modify: `threatmodellerTests/threatmodellerTests.swift`

**Interfaces:**
- Consumes: `ListPathwayMitigations`, `ConfigurePathwayMitigations`.
- Produces: `ThreatModelSession.pathwayMitigations: ListPathwayMitigationsResponse`, `.setPathwayMaster(_:)`, `.setPathwayMitigation(id:isEnabled:mode:reductionPercent:)`; `PathwayMitigationsPanel(session:)`; accessibility identifiers `pathway-master`, `pathway-<id>-enabled`, `pathway-<id>-mode`, `pathway-<id>-percent`.

The panel sits above the risk summary in the threat sidebar, behind a disclosure, so it is reachable without taking room from the cards.

- [ ] **Step 1: Write the failing test**

Add to `threatmodellerTests/threatmodellerTests.swift`:

```swift
    @Test func listsThePathwayMitigationsOnLaunch() throws {
        let session = session()

        #expect(session.pathwayMitigations.isMasterEnabled == false)
        let waf = try #require(session.pathwayMitigations.mitigations.first)
        #expect(waf.id == "waf-protection")
        #expect(waf.isProvidedOnThisModel == false)
    }

    @Test func saysWhenTheModelProvidesAMitigation() throws {
        let session = session()

        session.add(technologyId: "aws-waf", x: 0, y: 0)

        #expect(try #require(session.pathwayMitigations.mitigations.first).isProvidedOnThisModel)
    }

    @Test func lowersAThreatWhenTheUserSwitchesTheControlOn() throws {
        let session = session()
        session.add(technologyId: "aws-waf", x: 0, y: 0)
        session.add(technologyId: "aws-ec2", x: 300, y: 0)
        let ids = session.canvas.components.map(\.id)
        session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])

        let before = try #require(
            session.threats.first { $0.threatId == "credential-theft" }
        ).riskScore

        session.setPathwayMitigation(
            id: "waf-protection",
            isEnabled: true,
            mode: "reduce",
            reductionPercent: 50
        )

        let after = try #require(session.threats.first { $0.threatId == "credential-theft" })
        #expect(after.riskScore < before)
        #expect(after.pathwayMitigationLabels == ["WAF Protection"])
        #expect(session.pathwayMitigations.isMasterEnabled)
        #expect(session.errorMessage == nil)
    }

    @Test func turnsEveryMitigationOffAtOnce() throws {
        let session = session()
        session.add(technologyId: "aws-waf", x: 0, y: 0)
        session.add(technologyId: "aws-ec2", x: 300, y: 0)
        let ids = session.canvas.components.map(\.id)
        session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])
        session.setPathwayMitigation(
            id: "waf-protection",
            isEnabled: true,
            mode: "reduce",
            reductionPercent: 50
        )

        session.setPathwayMaster(false)

        #expect(session.pathwayMitigations.isMasterEnabled == false)
        #expect(try #require(session.threats.first { $0.threatId == "credential-theft" })
                .pathwayMitigationLabels.isEmpty)
    }

    @Test func reportsAReductionOutsideTheRangeOnAMitigation() {
        let session = session()

        session.setPathwayMitigation(
            id: "waf-protection",
            isEnabled: true,
            mode: "reduce",
            reductionPercent: 500
        )

        #expect(session.errorMessage == "Risk reduction must be between 0 and 100 per cent.")
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `has no member 'pathwayMitigations'`.

- [ ] **Step 3: Give the session the mitigations and the two commands**

Add beside `severityChoices`:

```swift
    private(set) var pathwayMitigations = ListPathwayMitigationsResponse(
        isMasterEnabled: false,
        mitigations: []
    )
```

Add the commands:

```swift
    func setPathwayMaster(_ isEnabled: Bool) {
        apply(
            ConfigurePathwayMitigationsRequest(
                isMasterEnabled: isEnabled,
                mitigationId: nil,
                isEnabled: true,
                mode: PathwayMitigationMode.reduce.rawValue,
                reductionPercent: 50
            )
        )
    }

    /// Setting any one mitigation also turns the master toggle on: a user who
    /// reaches for one control means it to take effect.
    func setPathwayMitigation(id: String, isEnabled: Bool, mode: String, reductionPercent: Int) {
        apply(
            ConfigurePathwayMitigationsRequest(
                isMasterEnabled: true,
                mitigationId: id,
                isEnabled: isEnabled,
                mode: mode,
                reductionPercent: reductionPercent
            )
        )
    }

    private func apply(_ request: ConfigurePathwayMitigationsRequest) {
        switch useCases.configurePathwayMitigations().execute(request) {
        case .configured:
            errorMessage = nil
        case .unknownMitigation:
            errorMessage = "That mitigation is not in the catalogue."
        case .unknownMode:
            errorMessage = "That mitigation mode is not recognised."
        case .reductionOutOfRange:
            errorMessage = "Risk reduction must be between 0 and 100 per cent."
        }

        refresh()
    }
```

and extend `refresh`:

```swift
        pathwayMitigations = useCases.listPathwayMitigations()
            .execute(ListPathwayMitigationsRequest())
```

- [ ] **Step 4: Write the panel**

Create `threatmodeller/sidebar/PathwayMitigationsPanel.swift`:

```swift
import SwiftUI
import ThreatModelKit

/// The controls the user says are real on their system.
///
/// Nothing here changes a score until the master toggle goes on, so the panel
/// starts collapsed and says how many mitigations this diagram can actually
/// use. A mitigation nothing on the diagram provides is shown greyed with what
/// would provide it, rather than hidden: the user is choosing what to build as
/// much as what they have.
struct PathwayMitigationsPanel: View {
    let session: ThreatModelSession

    @State private var isExpanded = false

    private var usable: Int {
        session.pathwayMitigations.mitigations.filter(\.isProvidedOnThisModel).count
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            header

            if isExpanded {
                Toggle("Apply pathway mitigations", isOn: Binding(
                    get: { session.pathwayMitigations.isMasterEnabled },
                    set: { session.setPathwayMaster($0) }
                ))
                .toggleStyle(.switch)
                .accessibilityIdentifier("pathway-master")

                ForEach(session.pathwayMitigations.mitigations, id: \.id) { mitigation in
                    row(mitigation)
                }
            }
        }
        .padding(12)
    }

    private var header: some View {
        Button {
            isExpanded.toggle()
        } label: {
            HStack(spacing: 6) {
                Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .frame(width: 10)
                Text("Pathway mitigations")
                    .font(.subheadline.weight(.semibold))
                Spacer(minLength: 4)
                Text(session.pathwayMitigations.isMasterEnabled ? "\(usable) in use" : "Off")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("pathway-mitigations")
    }

    private func row(_ mitigation: ListedPathwayMitigation) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Toggle(isOn: Binding(
                get: { mitigation.isEnabled },
                set: {
                    session.setPathwayMitigation(
                        id: mitigation.id,
                        isEnabled: $0,
                        mode: mitigation.mode,
                        reductionPercent: mitigation.reductionPercent
                    )
                }
            )) {
                Text(mitigation.label).font(.caption)
            }
            .toggleStyle(.checkbox)
            .accessibilityIdentifier("pathway-\(mitigation.id)-enabled")

            if mitigation.isProvidedOnThisModel == false {
                Text("Nothing on this diagram provides it. \(mitigation.providedByTechnologyNames.joined(separator: ", ")) would.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if mitigation.isEnabled {
                HStack(spacing: 8) {
                    Picker("Mode", selection: Binding(
                        get: { mitigation.mode },
                        set: {
                            session.setPathwayMitigation(
                                id: mitigation.id,
                                isEnabled: mitigation.isEnabled,
                                mode: $0,
                                reductionPercent: mitigation.reductionPercent
                            )
                        }
                    )) {
                        Text("Lower the score").tag("reduce")
                        Text("Remove the threat").tag("remove")
                    }
                    .labelsHidden()
                    .frame(width: 170)
                    .accessibilityIdentifier("pathway-\(mitigation.id)-mode")

                    if mitigation.mode == "reduce" {
                        Slider(
                            value: Binding(
                                get: { Double(mitigation.reductionPercent) },
                                set: {
                                    session.setPathwayMitigation(
                                        id: mitigation.id,
                                        isEnabled: mitigation.isEnabled,
                                        mode: mitigation.mode,
                                        reductionPercent: Int($0.rounded())
                                    )
                                }
                            ),
                            in: 0...100,
                            step: 5
                        )
                        .frame(width: 100)
                        .accessibilityIdentifier("pathway-\(mitigation.id)-percent")
                        Text("\(mitigation.reductionPercent)%")
                            .font(.caption2.monospacedDigit())
                    }
                }
            }
        }
        .padding(.leading, 16)
        .opacity(mitigation.isProvidedOnThisModel ? 1 : 0.6)
    }
}
```

- [ ] **Step 5: Put the panel in the sidebar, and show what a mitigation bought**

In `ThreatSidebar`, above `RiskSummaryView`:

```swift
                PathwayMitigationsPanel(session: session)
                Divider()
                RiskSummaryView(summary: session.summary)
```

In `ThreatCard.header`, show the score a mitigation moved away from:

```swift
            Spacer(minLength: 8)
            if threat.pathwayMitigationLabels.isEmpty == false,
               threat.scoreBeforePathwayMitigation != threat.riskScore {
                Text("\(threat.scoreBeforePathwayMitigation)")
                    .font(.caption.monospacedDigit())
                    .strikethrough()
                    .foregroundStyle(.tertiary)
                    .help(threat.pathwayMitigationLabels.joined(separator: ", "))
            }
            Text("\(threat.riskLevel.capitalized) · \(threat.riskScore)")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'Failing tests|\*\* TEST' -A3 | head -8
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add threatmodeller threatmodellerTests
git commit -m "feat: let the user say which controls are real on their system

The panel sits above the risk summary behind a disclosure. A mitigation
nothing on the diagram provides is shown greyed with what would provide it,
rather than hidden: the user is choosing what to build as much as what they
have. A card shows the score a mitigation moved away from."
```

---

### Task 9: The user interface journey

**Files:**
- Modify: `threatmodellerUITests/threatmodellerUITests.swift`

- [ ] **Step 1: Extend the journey**

After the control-ticking assertions:

```swift
        // Open the pathway mitigations and switch them on.
        mark("opening the pathway mitigations")
        let pathwayHeader = app.descendants(matching: .any)["pathway-mitigations"].firstMatch
        XCTAssertTrue(
            pathwayHeader.waitForExistence(timeout: 5),
            "The pathway mitigations control never appeared in the sidebar."
        )
        pathwayHeader.click()

        let master = app.descendants(matching: .any)["pathway-master"].firstMatch
        XCTAssertTrue(
            master.waitForExistence(timeout: 5),
            "Opening the pathway mitigations did not reveal the master switch."
        )
        XCTAssertEqual(master.value as? Int, 0, "Pathway mitigations started on.")
        master.click()

        let switchedOn = XCTNSPredicateExpectation(
            predicate: NSPredicate(format: "value == 1"),
            object: master
        )
        XCTAssertEqual(
            XCTWaiter().wait(for: [switchedOn], timeout: 10),
            .completed,
            "Clicking the master switch did not turn the pathway mitigations on."
        )
        mark("pathway mitigations on")
```

WARNING: if `pathway-master` is not found as a switch, dump the tree with `print(app.debugDescription)` and read which element kind it is. Remove the dump before committing.

- [ ] **Step 2: Run the user interface suite**

```bash
cd /Users/craigjbass/Projects/threat-modeller
osascript -e 'tell application "threatmodeller" to quit' 2>/dev/null
defaults delete uk.craigbass.threatmodeller 2>/dev/null
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller \
    -destination 'platform=macOS' -only-testing:threatmodellerUITests test 2>&1 | grep -E 'error:|Failing tests|\*\* TEST' -A3 | head -10
```

Expected: PASS.

- [ ] **Step 3: Run every suite**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && time swift test 2>&1 | tail -3
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'Failing tests|\*\* TEST' -A3 | head -6
```

Expected: PASS, package suite under 30 seconds.

- [ ] **Step 4: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add threatmodellerUITests
git commit -m "test: walk the journey as far as switching a mitigation on"
```

---

## Milestone complete

- [ ] `swift test` from `ThreatModelKit/` is green and runs in under 30 seconds.
- [ ] `xcodebuild ... test` is green, including the user interface suite.
- [ ] The catalogue tag is still `v1.0.1`.
- [ ] A pathway threat is scored against the highest sensitivity one hop downstream, when that is higher.
- [ ] A threat is never escalated downwards, and a threat that is not a pathway threat is never escalated at all.
- [ ] A mitigation applies only when the master toggle is on, that mitigation is enabled, a strictly upstream component provides it, and it lists the threat.
- [ ] `remove` drops the threat; `reduce` floors and never reaches zero.
- [ ] A link's threats take its source's upstream mitigations; a zone's threats take none.
- [ ] A component never mitigates its own threats.
- [ ] The panel says when nothing on the diagram provides a mitigation, and names what would.
- [ ] Turning the master toggle off keeps the per-mitigation settings.

Then write `docs/superpowers/specs/MILESTONE-6-CARRY-FORWARD.md` and start the Milestone 6 plan.

Deferred, with the trigger unchanged: everything on `MILESTONE-5-CARRY-FORWARD.md`. The fixed `internal` sensitivity is now the largest gap, because escalation and the zone multiplier both act on a sensitivity the user cannot set.

New and deferred from this milestone: where two mitigations answer one threat the stronger wins rather than the sum, and the plan records that as a decision the spec does not state; a zone threat is never pathway-mitigated, because a zone sits nowhere in the connection graph; and the `ThreatResolver` now walks the connection graph for every threat, which joins the unmeasured arithmetic on the carry-forward list.
