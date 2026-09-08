# Milestone 4: Threat Sidebar — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The user reads every threat as a card grouped under the thing that raised it, with its STRIDE tags, its MITRE techniques and its controls; ticks off the controls already in place; overrides a threat's severity when the catalogue's rating is wrong for their system; and sees a risk summary over the whole model.

**Architecture:** The threat resolution moves out of `AssessThreatModel` into a `ThreatResolver` in the assessment domain, so `SummariseRisk` counts exactly what the sidebar lists. `ControlIdentity` mints the djb2-fingerprinted control keys of spec §5.3 and `SeverityOverrideKey` mints the override keys. Every key is minted in the core and handed out on the response; a write use case takes a key it was given, so no view builds one.

**Tech Stack:** Swift 6.3, Swift Package Manager, Swift Testing, SwiftUI, macOS 26.

**Spec:** `docs/superpowers/specs/2026-09-07-native-macos-threat-modeller-design.md`

**Carry-forward:** `docs/superpowers/specs/MILESTONE-4-CARRY-FORWARD.md`

**Read Task 9 before starting Task 1.** Task 9 is the acceptance test — the outer loop.

## Global Constraints

- Everything in the Milestone 3 plan's Global Constraints still holds: macOS 26, Swift 6 language mode in both the package and the app target, `nonisolated` on every app-target value type, no `SwiftUI`/`AppKit`/`CoreGraphics` in the core, catalogue pinned at `v1.0.1`.
- WARNING: two source files in one module may not share a basename.
- WARNING: a key path passed to a `rethrows` method inside an `#expect` macro fails to compile. Use a closure.
- WARNING: `#expect` keeps each captured operand's own type. Comparing a `CGFloat` against a `Double` reads as unequal even when both print the same number. Convert one side.
- Control fingerprint: djb2 over the UTF-8 bytes of the description, trimmed and with runs of whitespace collapsed to a single space. `hash = 5381`, then `hash = hash * 33 + byte`, unsigned 32-bit, rendered as 8 lower-case hex digits.
- Control keys: `node:{componentId}:{threatId}::{fingerprint}` for a threat's generic controls, `node:{componentId}:{threatId}:tech::{fingerprint}` for a technology's own mitigations, `connection:{threatId}::{fingerprint}` consolidated across every link, `zone:{threatId}::{fingerprint}` consolidated across every zone.
- Severity override keys: `{technologyId}::{threatId}` for a component threat, `connection::{threatId}`, `zone::{threatId}`.
- An override replaces the threat's severity before the risk score is worked out. The zone multiplier then applies to that score.
- Recording a control changes no score. Spec §5.3 gives it no scoring rule.
- Removing a component prunes every `node:{componentId}:` key.
- Commit after every task. Never commit a red suite.

## Out of scope for this milestone

Pathway mitigations, undo/redo, documents, copy and paste, custom technologies, external actors, exports, samples, connection labels, the component property panel, threat filtering and search.

`ThreatModelSession` still fixes `sensitivity: "internal"`; `RenameComponent`, `SetComponentSensitivity` and `DisableComponentThreats` stay unwritten. Every other item on `MILESTONE-4-CARRY-FORWARD.md` keeps the trigger recorded against it.

Nothing prunes a control key whose description has left the catalogue. That key stays in the model, shows nowhere, and its tick returns if the description ever comes back. Spec §5.3 asks for no sweep and this plan adds none.

## File Structure

**Created:**

| Path | Responsibility |
|---|---|
| `.../assessment/domain/ControlIdentity.swift` | `ControlKey`, the djb2 fingerprint, the four scoped keys, the prune prefix |
| `.../assessment/domain/SeverityOverride.swift` | `SeverityOverrideKey` and its three shapes |
| `.../assessment/domain/ThreatResolver.swift` | The resolution both `AssessThreatModel` and `SummariseRisk` read |
| `.../assessment/usecase/OverrideThreatSeverity.swift` | and its Request/Response |
| `.../assessment/usecase/ClearSeverityOverride.swift` | and its Request/Response |
| `.../assessment/usecase/RecordControlImplemented.swift` | and its Request/Response |
| `.../assessment/usecase/RecordControlNotImplemented.swift` | and its Request/Response |
| `.../assessment/usecase/SummariseRisk.swift` | and its Request/Response |
| `ThreatModelKit/Tests/UnitTests/ControlIdentityTests.swift` | The fingerprint and every key |
| `.../UnitTests/SeverityOverrideKeyTests.swift` | The three override key shapes |
| `.../UnitTests/OverrideThreatSeverityTests.swift` | Overriding and clearing |
| `.../UnitTests/RecordControlTests.swift` | Both control use cases |
| `.../UnitTests/SummariseRiskTests.swift` | The counts |
| `.../AcceptanceTests/ReadingAndAnsweringThreatsTests.swift` | The milestone's outer loop |
| `threatmodeller/sidebar/RiskSummaryView.swift` | The strip at the top |
| `threatmodeller/sidebar/ThreatCard.swift` | One threat |
| `threatmodeller/sidebar/ThreatSidebar.swift` | The summary, the groups and their cards |

**Modified:**

- `.../modelling/domain/ThreatModel.swift` — gains `severityOverrides` and `implementedControls`
- `.../modelling/usecase/RemoveComponents.swift` — prunes the removed components' control keys
- `.../assessment/usecase/AssessThreatModel.swift` — reads `ThreatResolver`; the response gains the keys and the flags
- `.../ThreatModelKit/UseCaseFactory.swift`, `.../TestSupport/TestDependencies.swift`, `threatmodeller/Dependencies.swift` — five more use cases
- `threatmodeller/ThreatModelSession.swift` — the summary, and one method per new use case
- `threatmodeller/ContentView.swift` — the flat threat list becomes `ThreatSidebar`
- `threatmodellerUITests/threatmodellerUITests.swift` — the journey ticks a control

---

### Task 1: `ControlIdentity` and `SeverityOverrideKey`

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ControlIdentity.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/SeverityOverride.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ControlIdentityTests.swift`
- Test: `ThreatModelKit/Tests/UnitTests/SeverityOverrideKeyTests.swift`

**Interfaces:**
- Consumes: `ComponentId`, `ThreatId`, `TechnologyId`.
- Produces: `ControlKey(_ value: String)` with `.value`; `ControlIdentity.fingerprint(of:)`, `.componentControl(componentId:threatId:description:isTechnologySpecific:)`, `.connectionControl(threatId:description:)`, `.zoneControl(threatId:description:)`, `.componentPrefix(_:)`; `SeverityOverrideKey(_ value: String)` with `.value`, `SeverityOverrideKey.forComponent(technologyId:threatId:)`, `.forConnection(threatId:)`, `.forZone(threatId:)`.

- [ ] **Step 1: Write the failing tests**

Create `ThreatModelKit/Tests/UnitTests/ControlIdentityTests.swift`:

```swift
import Testing
import ThreatModelKit

struct ControlIdentityTests {
    @Test func hashesADescriptionToEightHexDigits() {
        let fingerprint = ControlIdentity.fingerprint(of: "Rotate credentials regularly")

        #expect(fingerprint.count == 8)
        #expect(fingerprint.allSatisfy { $0.isHexDigit })
        #expect(fingerprint == fingerprint.lowercased())
    }

    @Test func givesTheSameDescriptionTheSameFingerprint() {
        #expect(ControlIdentity.fingerprint(of: "Apply rate limits")
                == ControlIdentity.fingerprint(of: "Apply rate limits"))
    }

    @Test func givesTwoDescriptionsDifferentFingerprints() {
        #expect(ControlIdentity.fingerprint(of: "Apply rate limits")
                != ControlIdentity.fingerprint(of: "Apply rate limiting"))
    }

    @Test func ignoresSurroundingAndRepeatedWhitespace() {
        let plain = ControlIdentity.fingerprint(of: "Rotate credentials regularly")

        #expect(ControlIdentity.fingerprint(of: "  Rotate credentials regularly  ") == plain)
        #expect(ControlIdentity.fingerprint(of: "Rotate   credentials\tregularly") == plain)
        #expect(ControlIdentity.fingerprint(of: "Rotate\ncredentials regularly") == plain)
    }

    @Test func matchesTheDjb2AlgorithmTheSpecStates() {
        // hash = 5381; hash = hash * 33 + byte, unsigned 32-bit.
        // "a" -> 5381 * 33 + 97 = 177670 = 0x0002b606
        #expect(ControlIdentity.fingerprint(of: "a") == "0002b606")
        // "" -> 5381 = 0x00001505
        #expect(ControlIdentity.fingerprint(of: "") == "00001505")
    }

    @Test func scopesAComponentsGenericControl() {
        let key = ControlIdentity.componentControl(
            componentId: ComponentId("c1"),
            threatId: ThreatId("credential-theft"),
            description: "Rotate credentials regularly",
            isTechnologySpecific: false
        )

        #expect(key.value == "node:c1:credential-theft::\(ControlIdentity.fingerprint(of: "Rotate credentials regularly"))")
    }

    @Test func marksATechnologysOwnMitigationApart() {
        let generic = ControlIdentity.componentControl(
            componentId: ComponentId("c1"),
            threatId: ThreatId("credential-theft"),
            description: "Enforce IMDSv2",
            isTechnologySpecific: false
        )
        let specific = ControlIdentity.componentControl(
            componentId: ComponentId("c1"),
            threatId: ThreatId("credential-theft"),
            description: "Enforce IMDSv2",
            isTechnologySpecific: true
        )

        #expect(specific.value.contains(":tech::"))
        #expect(generic != specific)
    }

    @Test func consolidatesALinksControlAcrossEveryLink() {
        let key = ControlIdentity.connectionControl(
            threatId: ThreatId("connection-mitm"),
            description: "Enforce TLS on every hop"
        )

        #expect(key.value == "connection:connection-mitm::\(ControlIdentity.fingerprint(of: "Enforce TLS on every hop"))")
    }

    @Test func consolidatesAZonesControlAcrossEveryZone() {
        let key = ControlIdentity.zoneControl(
            threatId: ThreatId("lateral-movement"),
            description: "Segment the network"
        )

        #expect(key.value == "zone:lateral-movement::\(ControlIdentity.fingerprint(of: "Segment the network"))")
    }

    @Test func givesAComponentAPrefixItsKeysArePrunedBy() {
        let prefix = ControlIdentity.componentPrefix(ComponentId("c1"))
        let mine = ControlIdentity.componentControl(
            componentId: ComponentId("c1"),
            threatId: ThreatId("credential-theft"),
            description: "Rotate credentials",
            isTechnologySpecific: false
        )
        let theirs = ControlIdentity.componentControl(
            componentId: ComponentId("c2"),
            threatId: ThreatId("credential-theft"),
            description: "Rotate credentials",
            isTechnologySpecific: false
        )

        #expect(prefix == "node:c1:")
        #expect(mine.value.hasPrefix(prefix))
        #expect(theirs.value.hasPrefix(prefix) == false)
    }
}
```

Create `ThreatModelKit/Tests/UnitTests/SeverityOverrideKeyTests.swift`:

```swift
import Testing
import ThreatModelKit

struct SeverityOverrideKeyTests {
    @Test func keysAComponentThreatByItsTechnology() {
        // Spec section 5.3. An override set on one EC2 node applies to every
        // EC2 node, because the key names the technology and not the component.
        let key = SeverityOverrideKey.forComponent(
            technologyId: TechnologyId("aws-ec2"),
            threatId: ThreatId("credential-theft")
        )

        #expect(key.value == "aws-ec2::credential-theft")
    }

    @Test func keysALinkThreatAcrossEveryLink() {
        #expect(SeverityOverrideKey.forConnection(threatId: ThreatId("connection-mitm")).value
                == "connection::connection-mitm")
    }

    @Test func keysAZoneThreatAcrossEveryZone() {
        #expect(SeverityOverrideKey.forZone(threatId: ThreatId("lateral-movement")).value
                == "zone::lateral-movement")
    }

    @Test func tellsTheThreeShapesApart() {
        let keys = Set([
            SeverityOverrideKey.forComponent(technologyId: TechnologyId("connection"), threatId: ThreatId("x")),
            SeverityOverrideKey.forConnection(threatId: ThreatId("x")),
            SeverityOverrideKey.forZone(threatId: ThreatId("x"))
        ])

        // A technology literally named "connection" would collide with the
        // link shape. The catalogue has no such technology, and the shapes are
        // the ones the spec states.
        #expect(keys.count == 2)
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter ControlIdentityTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'ControlIdentity' in scope`.

- [ ] **Step 3: Write `ControlIdentity`**

Create `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ControlIdentity.swift`:

```swift
/// Identifies one control the user can record as in place.
public struct ControlKey: Hashable, Sendable, CustomStringConvertible {
    public let value: String
    public init(_ value: String) { self.value = value }
    public var description: String { value }
}

/// How a control is identified across a model. Spec section 5.3.
///
/// A control has no identifier in the catalogue that survives an edit to its
/// wording, so the identity is a hash of the wording itself, scoped by what
/// the control belongs to. Two components each get their own key for the same
/// control, while every link shares one key and every zone shares one, because
/// the spec consolidates those two.
public enum ControlIdentity {
    /// djb2 over the UTF-8 bytes of the normalised description.
    ///
    /// `hash = 5381`, then `hash = hash * 33 + byte`, kept to unsigned 32 bits
    /// and rendered as 8 lower-case hex digits. Normalising means trimmed, with
    /// runs of whitespace collapsed to one space, so re-wrapping a description
    /// does not lose the user's tick.
    public static func fingerprint(of description: String) -> String {
        var hash: UInt32 = 5381
        for byte in Array(normalised(description).utf8) {
            hash = hash &* 33 &+ UInt32(byte)
        }
        let hex = String(hash, radix: 16)
        return String(repeating: "0", count: max(0, 8 - hex.count)) + hex
    }

    /// A control on one component's threat. A technology's own mitigation is
    /// marked apart, because the same wording can appear as both.
    public static func componentControl(
        componentId: ComponentId,
        threatId: ThreatId,
        description: String,
        isTechnologySpecific: Bool
    ) -> ControlKey {
        let scope = isTechnologySpecific ? ":tech" : ""
        return ControlKey(
            "node:\(componentId.value):\(threatId.value)\(scope)::\(fingerprint(of: description))"
        )
    }

    /// Consolidated across every link. Spec section 5.3.
    public static func connectionControl(threatId: ThreatId, description: String) -> ControlKey {
        ControlKey("connection:\(threatId.value)::\(fingerprint(of: description))")
    }

    /// Consolidated across every zone. Spec section 5.3.
    public static func zoneControl(threatId: ThreatId, description: String) -> ControlKey {
        ControlKey("zone:\(threatId.value)::\(fingerprint(of: description))")
    }

    /// Every key belonging to one component starts with this. `RemoveComponents`
    /// prunes by it.
    public static func componentPrefix(_ componentId: ComponentId) -> String {
        "node:\(componentId.value):"
    }

    private static func normalised(_ description: String) -> String {
        var words: [String] = []
        var current = ""
        for character in description {
            if character.isWhitespace {
                if current.isEmpty == false { words.append(current); current = "" }
            } else {
                current.append(character)
            }
        }
        if current.isEmpty == false { words.append(current) }
        return words.joined(separator: " ")
    }
}
```

- [ ] **Step 4: Write `SeverityOverrideKey`**

Create `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/SeverityOverride.swift`:

```swift
/// Identifies a severity the user has overridden. Spec section 5.3.
///
/// WARNING: a component threat is keyed by its **technology**, not by the
/// component. An override set on one EC2 node applies to every EC2 node, and a
/// link or zone override applies to every link or every zone. That is the
/// original application's behaviour and the ported tests hold it.
public struct SeverityOverrideKey: Hashable, Sendable, CustomStringConvertible {
    public let value: String
    public init(_ value: String) { self.value = value }
    public var description: String { value }

    public static func forComponent(technologyId: TechnologyId, threatId: ThreatId) -> SeverityOverrideKey {
        SeverityOverrideKey("\(technologyId.value)::\(threatId.value)")
    }

    public static func forConnection(threatId: ThreatId) -> SeverityOverrideKey {
        SeverityOverrideKey("connection::\(threatId.value)")
    }

    public static func forZone(threatId: ThreatId) -> SeverityOverrideKey {
        SeverityOverrideKey("zone::\(threatId.value)")
    }
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
git commit -m "feat: add ControlIdentity and SeverityOverrideKey

A control has no catalogue identifier that survives an edit to its wording,
so its identity is a djb2 hash of the wording, scoped by what it belongs to.
A severity override is keyed by technology, not by component, which is what
the original does."
```

---

### Task 2: The model holds overrides and implemented controls

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/ThreatModel.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/RemoveComponents.swift`
- Modify: `ThreatModelKit/Tests/UnitTests/RemoveComponentsTests.swift`

**Interfaces:**
- Consumes: `ControlKey`, `SeverityOverrideKey`, `ControlIdentity.componentPrefix(_:)`.
- Produces: `ThreatModel(name:components:connections:zones:severityOverrides:implementedControls:)` with `severityOverrides: [SeverityOverrideKey: String]` and `implementedControls: Set<ControlKey>`.

- [ ] **Step 1: Write the failing test**

Add to `ThreatModelKit/Tests/UnitTests/RemoveComponentsTests.swift`:

```swift
    @Test func prunesTheRemovedComponentsControlKeys() {
        let mine = ControlIdentity.componentControl(
            componentId: ComponentId("c1"),
            threatId: ThreatId("credential-theft"),
            description: "Rotate credentials",
            isTechnologySpecific: false
        )
        let theirs = ControlIdentity.componentControl(
            componentId: ComponentId("c2"),
            threatId: ThreatId("credential-theft"),
            description: "Rotate credentials",
            isTechnologySpecific: false
        )
        let shared = ControlIdentity.connectionControl(
            threatId: ThreatId("connection-mitm"),
            description: "Enforce TLS"
        )
        let models = InMemoryThreatModelGateway(
            ThreatModel(
                components: [Self.component("c1"), Self.component("c2")],
                implementedControls: [mine, theirs, shared]
            )
        )

        _ = RemoveComponents(models: models).execute(RemoveComponentsRequest(componentIds: ["c1"]))

        #expect(models.current().implementedControls == [theirs, shared])
    }

    @Test func leavesEverySeverityOverrideAlone() {
        // An override is keyed by technology, so removing one component of that
        // technology must not clear it.
        let key = SeverityOverrideKey.forComponent(
            technologyId: TechnologyId("aws-ec2"),
            threatId: ThreatId("credential-theft")
        )
        let models = InMemoryThreatModelGateway(
            ThreatModel(components: [Self.component("c1")], severityOverrides: [key: "low"])
        )

        _ = RemoveComponents(models: models).execute(RemoveComponentsRequest(componentIds: ["c1"]))

        #expect(models.current().severityOverrides == [key: "low"])
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter RemoveComponentsTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with an unknown `implementedControls` argument.

- [ ] **Step 3: Give the aggregate its two records**

In `ThreatModel`, add the two stored properties after `zones`, the two initialiser parameters in the same position each defaulting to empty, and the two assignments:

```swift
    /// A severity the user has overridden, keyed as spec section 5.3 states.
    /// The value is a severity id the taxonomy resolves.
    public var severityOverrides: [SeverityOverrideKey: String]
    /// Every control the user has recorded as in place.
    public var implementedControls: Set<ControlKey>
```

- [ ] **Step 4: Prune on removal**

In `RemoveComponents.execute`, after the components and connections are removed and before `models.save(model)`:

```swift
        // Spec section 5.3: removing a component prunes every key scoped to it.
        // A severity override is keyed by technology, not by component, so
        // nothing prunes one of those.
        let prefixes = doomed.map(ControlIdentity.componentPrefix)
        model.implementedControls = model.implementedControls.filter { key in
            prefixes.contains(where: key.value.hasPrefix) == false
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
git commit -m "feat: hold severity overrides and implemented controls on the model

Removing a component prunes every control key scoped to it. A severity
override is keyed by technology, so removing one component of that technology
leaves the override alone."
```

---

### Task 3: Extract `ThreatResolver`

A refactor with no behaviour change. `SummariseRisk` must count exactly the threats the sidebar lists, so the resolution moves out of `AssessThreatModel` into one place both read.

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ThreatResolver.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/AssessThreatModel.swift`

**Interfaces:**
- Consumes: `ThreatModel`, `TechnologyCatalogue`, `ZoneContainment`, `ZoneMultiplier`, `SensitivityLadder`, `ConnectionEncryption`, `RiskScore`.
- Produces: `ResolvedControl(description:isTechnologySpecific:)`, `ResolvedSource` (`.component(id:name:providerId:)`, `.connection(id:sourceName:targetName:)`, `.zone(id:name:)`) with `.id` and `.displayName`, `ResolvedThreat`, `ThreatResolver(model:catalogue:).resolve() -> [ResolvedThreat]`.

`ThreatResolver` reads a gateway port. Spec §3.3 has the assessment context declare `TechnologyCatalogue` as its own port, so a domain object in that context reading it stays inside the context.

- [ ] **Step 1: Write the resolver**

Create `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ThreatResolver.swift`:

```swift
/// One control offered against a resolved threat.
public struct ResolvedControl: Equatable, Sendable {
    public let description: String
    /// True when the control came from the technology rather than the threat.
    public let isTechnologySpecific: Bool

    public init(description: String, isTechnologySpecific: Bool) {
        self.description = description
        self.isTechnologySpecific = isTechnologySpecific
    }
}

/// What raised a threat, in domain terms.
public enum ResolvedSource: Hashable, Sendable {
    case component(id: ComponentId, name: String, providerId: ProviderId)
    case connection(id: ConnectionId, sourceName: String, targetName: String)
    case zone(id: ZoneId, name: String)

    public var displayName: String {
        switch self {
        case .component(_, let name, _):
            name
        case .connection(_, let sourceName, let targetName):
            "\(sourceName) \u{2192} \(targetName)"
        case .zone(_, let name):
            name
        }
    }

    /// Identifies the source across kinds. Two sources of different kinds never
    /// share one.
    public var id: String {
        switch self {
        case .component(let id, _, _):
            "component:\(id.value)"
        case .connection(let id, _, _):
            "connection:\(id.value)"
        case .zone(let id, _):
            "zone:\(id.value)"
        }
    }
}

/// One threat the model raises, scored.
public struct ResolvedThreat: Equatable, Sendable {
    public let threat: Threat
    /// The severity the score used. The threat's own, unless overridden.
    public let severity: ThreatSeverity
    public let source: ResolvedSource
    public let sensitivity: DataSensitivity
    public let score: RiskScore
    public let controls: [ResolvedControl]
    public let context: String?
    public let isTlsMitigated: Bool

    public init(
        threat: Threat,
        severity: ThreatSeverity,
        source: ResolvedSource,
        sensitivity: DataSensitivity,
        score: RiskScore,
        controls: [ResolvedControl],
        context: String?,
        isTlsMitigated: Bool
    ) {
        self.threat = threat
        self.severity = severity
        self.source = source
        self.sensitivity = sensitivity
        self.score = score
        self.controls = controls
        self.context = context
        self.isTlsMitigated = isTlsMitigated
    }
}

/// Resolves every threat a model raises, and scores each one.
///
/// Component threats come from the component's technology. Connection threats
/// come from the catalogue and belong to the link, not to either end. Zone
/// threats belong to each private zone. `AssessThreatModel` turns the result
/// into plain values for a delivery mechanism; `SummariseRisk` counts it. Both
/// read this one resolution, so a count can never disagree with a list.
public struct ThreatResolver {
    private let model: ThreatModel
    private let catalogue: TechnologyCatalogue

    public init(model: ThreatModel, catalogue: TechnologyCatalogue) {
        self.model = model
        self.catalogue = catalogue
    }

    public func resolve() -> [ResolvedThreat] {
        var resolved: [ResolvedThreat] = []
        // Spec section 5.3: a duplicate threat and source pair is raised once.
        var raised: Set<String> = []

        func raise(_ threat: ResolvedThreat) {
            let pair = "\(threat.threat.id.value)@\(threat.source.id)"
            guard raised.contains(pair) == false else { return }
            raised.insert(pair)
            resolved.append(threat)
        }

        // Derived, never stored. Spec section 5.2.
        var zonesByComponent: [ComponentId: Zone] = [:]
        for component in model.components {
            zonesByComponent[component.id] = ZoneContainment.zone(
                holding: component.centre,
                in: model.zones
            )
        }

        for component in model.components {
            guard component.threatsDisabled == false else { continue }
            guard let technology = catalogue.findById(component.technologyId) else { continue }

            let multiplier = ZoneMultiplier.value(for: zonesByComponent[component.id])

            for threat in catalogue.threatsFor(technologyId: component.technologyId) {
                let base = RiskScore(severity: threat.severity, sensitivity: component.sensitivity)
                let score = RiskScore(value: ZoneMultiplier.apply(multiplier, to: base.value))
                guard score.value > 0 else { continue }

                raise(
                    ResolvedThreat(
                        threat: threat,
                        severity: threat.severity,
                        source: .component(
                            id: component.id,
                            name: component.customName ?? technology.name,
                            providerId: technology.provider
                        ),
                        sensitivity: component.sensitivity,
                        score: score,
                        controls: Self.controls(for: threat, on: technology),
                        context: technology.threatContext[threat.id],
                        isTlsMitigated: false
                    )
                )
            }
        }

        for connection in model.connections {
            guard let source = model.component(connection.source),
                  let target = model.component(connection.target) else { continue }
            guard source.threatsDisabled == false, target.threatsDisabled == false else { continue }

            let sourceTechnology = catalogue.findById(source.technologyId)
            let targetTechnology = catalogue.findById(target.technologyId)
            let sensitivity = SensitivityLadder.higher(source.sensitivity, target.sensitivity)
            let multiplier = ZoneMultiplier.valueForConnection(
                sourceZone: zonesByComponent[source.id],
                targetZone: zonesByComponent[target.id]
            )

            for threat in catalogue.connectionThreats() {
                let base = RiskScore(severity: threat.severity, sensitivity: sensitivity)
                let score = RiskScore(value: ZoneMultiplier.apply(multiplier, to: base.value))
                guard score.value > 0 else { continue }

                raise(
                    ResolvedThreat(
                        threat: threat,
                        severity: threat.severity,
                        source: .connection(
                            id: connection.id,
                            sourceName: Self.name(of: source, as: sourceTechnology),
                            targetName: Self.name(of: target, as: targetTechnology)
                        ),
                        sensitivity: sensitivity,
                        score: score,
                        // Spec section 5.3: a link always uses the threat's own
                        // controls, never a technology's mitigations.
                        controls: threat.controls.map {
                            ResolvedControl(description: $0.description, isTechnologySpecific: false)
                        },
                        context: nil,
                        isTlsMitigated: ConnectionEncryption.isTlsMitigated(
                            threat: threat,
                            source: sourceTechnology,
                            target: targetTechnology
                        )
                    )
                )
            }
        }

        // Spec section 5.3: raised once per private zone, scored against a
        // fixed internal sensitivity, and reduced by that zone's own
        // multiplier. A public zone raises none.
        for zone in model.zones where zone.networkZone == .privateZone {
            let multiplier = ZoneMultiplier.value(for: zone)

            for threat in catalogue.zoneThreats() {
                let base = RiskScore(severity: threat.severity, sensitivity: .internalData)
                let score = RiskScore(value: ZoneMultiplier.apply(multiplier, to: base.value))
                guard score.value > 0 else { continue }

                raise(
                    ResolvedThreat(
                        threat: threat,
                        severity: threat.severity,
                        source: .zone(id: zone.id, name: zone.displayName),
                        sensitivity: .internalData,
                        score: score,
                        controls: threat.controls.map {
                            ResolvedControl(description: $0.description, isTechnologySpecific: false)
                        },
                        context: threat.zoneContext,
                        isTlsMitigated: false
                    )
                )
            }
        }

        return resolved.sorted(by: Self.ordering)
    }

    /// A link still raises its threats when an end's technology has left the
    /// catalogue: the threats belong to the link, and the sensitivity is stored
    /// on the component. The technology id stands in for the missing name.
    private static func name(of component: Component, as technology: Technology?) -> String {
        component.customName ?? technology?.name ?? component.technologyId.value
    }

    private static func controls(for threat: Threat, on technology: Technology) -> [ResolvedControl] {
        if let specific = technology.threatMitigations[threat.id], specific.isEmpty == false {
            return specific.map { ResolvedControl(description: $0, isTechnologySpecific: true) }
        }
        return threat.controls.map {
            ResolvedControl(description: $0.description, isTechnologySpecific: false)
        }
    }

    private static func ordering(_ a: ResolvedThreat, _ b: ResolvedThreat) -> Bool {
        if a.score.value != b.score.value { return a.score.value > b.score.value }
        if a.threat.id != b.threat.id { return a.threat.id.value < b.threat.id.value }
        return a.source.id < b.source.id
    }
}
```

- [ ] **Step 2: Make `AssessThreatModel` read it**

Replace the whole `public struct AssessThreatModel: AssessThreatModelUseCase { ... }` block:

```swift
/// Lists every threat the model raises, as plain values.
public struct AssessThreatModel: AssessThreatModelUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: AssessThreatModelRequest) -> AssessThreatModelResponse {
        let resolved = ThreatResolver(model: models.current(), catalogue: catalogue).resolve()

        return AssessThreatModelResponse(
            threats: resolved.map { threat in
                AssessedThreat(
                    threatId: threat.threat.id.value,
                    name: threat.threat.name,
                    description: threat.threat.description,
                    severityId: threat.severity.id,
                    severityLabel: threat.severity.label,
                    stride: threat.threat.stride.map(\.value),
                    mitreTechniques: threat.threat.mitreTechniques.map {
                        AssessedMitreTechnique(id: $0.id, name: $0.name, tactic: $0.tactic)
                    },
                    controls: threat.controls.map {
                        AssessedControl(
                            description: $0.description,
                            isTechnologySpecific: $0.isTechnologySpecific
                        )
                    },
                    source: Self.source(threat.source),
                    sensitivityId: threat.sensitivity.rawValue,
                    riskScore: threat.score.value,
                    riskLevel: threat.score.level.rawValue,
                    context: threat.context,
                    isTlsMitigated: threat.isTlsMitigated
                )
            }
        )
    }

    private static func source(_ source: ResolvedSource) -> AssessedThreatSource {
        switch source {
        case .component(let id, let name, let providerId):
            .component(id: id.value, name: name, providerId: providerId.value)
        case .connection(let id, let sourceName, let targetName):
            .connection(id: id.value, sourceName: sourceName, targetName: targetName)
        case .zone(let id, let name):
            .zone(id: id.value, name: name)
        }
    }
}
```

- [ ] **Step 3: Run every suite to verify nothing changed**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

Expected: PASS. Every score, order, control and flag is what it was; only where the work happens moved.

- [ ] **Step 4: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit
git commit -m "refactor: move the threat resolution into ThreatResolver

SummariseRisk must count exactly what the sidebar lists, so the resolution
moves into one place both use cases read. No behaviour changed."
```

---

### Task 4: Every control carries its key and whether it is recorded

**Files:**
- Modify: `.../assessment/domain/ThreatResolver.swift`
- Modify: `.../assessment/usecase/AssessThreatModel.swift`
- Modify: `ThreatModelKit/Tests/UnitTests/AssessThreatModelTests.swift`

**Interfaces:**
- Consumes: `ControlIdentity`, `SeverityOverrideKey`, `ThreatModel.implementedControls`.
- Produces: `ResolvedControl.key: ControlKey` and `.isImplemented: Bool`; `ResolvedThreat.overrideKey: SeverityOverrideKey`; `AssessedControl.key: String` and `.isImplemented: Bool`; `AssessedThreat.overrideKey: String`.

- [ ] **Step 1: Write the failing test**

Add to `AssessThreatModelTests`:

```swift
    @Test func givesEveryComponentControlItsOwnKey() throws {
        let response = assess(ThreatModel(components: [ec2(id: "c1")]))

        let theft = try #require(response.threats.first { $0.threatId == "credential-theft" })
        // EC2 declares its own mitigations for this threat, so they are marked
        // technology-specific and keyed apart from a generic control.
        #expect(theft.controls.allSatisfy { $0.key.hasPrefix("node:c1:credential-theft:tech::") })
        #expect(theft.controls.allSatisfy { $0.isImplemented == false })
        #expect(Set(theft.controls.map(\.key)).count == theft.controls.count)

        let misconfiguration = try #require(response.threats.first {
            $0.threatId == "misconfiguration" && $0.source.id == "component:c1"
        })
        #expect(misconfiguration.controls.allSatisfy {
            $0.key.hasPrefix("node:c1:misconfiguration::")
        })
    }

    @Test func consolidatesALinkControlAndAZoneControlAcrossTheirOwners() throws {
        let response = assess(
            ThreatModel(
                components: [ec2(id: "c1", sensitivity: .internalData), rds(sensitivity: .internalData)],
                connections: [link("k1", "c1", "c2")],
                zones: [privateZone("z1")]
            )
        )

        let mitm = try #require(response.threats.first { $0.threatId == "connection-mitm" })
        #expect(mitm.controls.allSatisfy { $0.key.hasPrefix("connection:connection-mitm::") })

        let lateral = try #require(response.threats.first { $0.threatId == "lateral-movement" })
        #expect(lateral.controls.allSatisfy { $0.key.hasPrefix("zone:lateral-movement::") })
    }

    @Test func marksAControlTheModelRecords() throws {
        let key = ControlIdentity.componentControl(
            componentId: ComponentId("c1"),
            threatId: ThreatId("credential-theft"),
            description: "Use IAM roles with minimal permissions",
            isTechnologySpecific: true
        )
        let response = assess(
            ThreatModel(components: [ec2(id: "c1")], implementedControls: [key])
        )

        let theft = try #require(response.threats.first { $0.threatId == "credential-theft" })
        let recorded = try #require(theft.controls.first { $0.key == key.value })
        #expect(recorded.isImplemented)
        #expect(theft.controls.filter(\.isImplemented).count == 1)
    }

    @Test func namesTheOverrideKeyForEachKindOfSource() throws {
        let response = assess(
            ThreatModel(
                components: [ec2(id: "c1", sensitivity: .internalData), rds(sensitivity: .internalData)],
                connections: [link("k1", "c1", "c2")],
                zones: [privateZone("z1")]
            )
        )

        // Keyed by technology, not by component. Spec section 5.3.
        #expect(try #require(response.threats.first { $0.threatId == "credential-theft" }).overrideKey
                == "aws-ec2::credential-theft")
        #expect(try #require(response.threats.first { $0.threatId == "connection-mitm" }).overrideKey
                == "connection::connection-mitm")
        #expect(try #require(response.threats.first { $0.threatId == "lateral-movement" }).overrideKey
                == "zone::lateral-movement")
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter AssessThreatModelTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `value of type 'AssessedControl' has no member 'key'`.

- [ ] **Step 3: Mint the keys in the resolver**

In `ThreatResolver.swift`, give `ResolvedControl` its key and flag:

```swift
public struct ResolvedControl: Equatable, Sendable {
    public let description: String
    /// True when the control came from the technology rather than the threat.
    public let isTechnologySpecific: Bool
    public let key: ControlKey
    /// True when the model records this control as in place.
    public let isImplemented: Bool

    public init(description: String, isTechnologySpecific: Bool, key: ControlKey, isImplemented: Bool) {
        self.description = description
        self.isTechnologySpecific = isTechnologySpecific
        self.key = key
        self.isImplemented = isImplemented
    }
}
```

Give `ResolvedThreat` its override key, as the last stored property and the last initialiser parameter:

```swift
    /// The key an override for this threat is recorded under. Spec section 5.3
    /// keys a component threat by its technology, so every component of that
    /// technology shares one override.
    public let overrideKey: SeverityOverrideKey
```

Replace the resolver's `controls(for:on:)` helper with one that mints keys, and add the two consolidated helpers:

```swift
    private func componentControls(
        for threat: Threat,
        on technology: Technology,
        componentId: ComponentId
    ) -> [ResolvedControl] {
        let specific = technology.threatMitigations[threat.id] ?? []
        let descriptions: [(String, Bool)] = specific.isEmpty
            ? threat.controls.map { ($0.description, false) }
            : specific.map { ($0, true) }

        return descriptions.map { description, isTechnologySpecific in
            let key = ControlIdentity.componentControl(
                componentId: componentId,
                threatId: threat.id,
                description: description,
                isTechnologySpecific: isTechnologySpecific
            )
            return ResolvedControl(
                description: description,
                isTechnologySpecific: isTechnologySpecific,
                key: key,
                isImplemented: model.implementedControls.contains(key)
            )
        }
    }

    private func sharedControls(for threat: Threat, keyedBy make: (ThreatId, String) -> ControlKey)
        -> [ResolvedControl] {
        threat.controls.map { control in
            let key = make(threat.id, control.description)
            return ResolvedControl(
                description: control.description,
                isTechnologySpecific: false,
                key: key,
                isImplemented: model.implementedControls.contains(key)
            )
        }
    }
```

At each of the three `raise(...)` calls, pass the right controls and override key:

```swift
                        controls: componentControls(for: threat, on: technology, componentId: component.id),
                        …
                        overrideKey: .forComponent(technologyId: component.technologyId, threatId: threat.id)
```

```swift
                        controls: sharedControls(for: threat, keyedBy: ControlIdentity.connectionControl),
                        …
                        overrideKey: .forConnection(threatId: threat.id)
```

```swift
                        controls: sharedControls(for: threat, keyedBy: ControlIdentity.zoneControl),
                        …
                        overrideKey: .forZone(threatId: threat.id)
```

`ControlIdentity.connectionControl` and `.zoneControl` already take `(threatId:description:)`, so both match the `make` parameter when referenced as `ControlIdentity.connectionControl(threatId:description:)`. Write the reference in full if the shorthand does not type-check.

- [ ] **Step 4: Carry them onto the response**

In `AssessThreatModel.swift`, add to `AssessedControl` the two fields and initialiser parameters:

```swift
    /// The key `RecordControlImplemented` takes. Minted by the core.
    public let key: String
    public let isImplemented: Bool
```

Add to `AssessedThreat`, after `isTlsMitigated`:

```swift
    /// The key `OverrideThreatSeverity` takes. Minted by the core.
    public let overrideKey: String
```

And map them in `execute`:

```swift
                    controls: threat.controls.map {
                        AssessedControl(
                            description: $0.description,
                            isTechnologySpecific: $0.isTechnologySpecific,
                            key: $0.key.value,
                            isImplemented: $0.isImplemented
                        )
                    },
```

```swift
                    isTlsMitigated: threat.isTlsMitigated,
                    overrideKey: threat.overrideKey.value
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
git commit -m "feat: hand out a key for every control and every override

The core mints the keys of spec section 5.3 and returns them, so a write use
case takes a key it was given and no view ever builds one."
```

---

### Task 5: An override changes the severity a threat is scored with

**Files:**
- Modify: `.../assessment/domain/ThreatResolver.swift`
- Modify: `.../assessment/usecase/AssessThreatModel.swift`
- Modify: `ThreatModelKit/Tests/UnitTests/AssessThreatModelTests.swift`

**Interfaces:**
- Consumes: `ThreatModel.severityOverrides`, `Taxonomy.severity(id:)`.
- Produces: `ResolvedThreat.overriddenSeverityId: String?`; `AssessedThreat.overriddenSeverityId: String?`.

- [ ] **Step 1: Write the failing test**

Add to `AssessThreatModelTests`:

```swift
    @Test func scoresAThreatWithTheSeverityTheUserOverrodeItTo() throws {
        let key = SeverityOverrideKey.forComponent(
            technologyId: TechnologyId("aws-ec2"),
            threatId: ThreatId("credential-theft")
        )
        let response = assess(
            ThreatModel(components: [ec2(id: "c1")], severityOverrides: [key: "low"])
        )

        // Low (1) against confidential data (3) is 3, not critical's 12.
        let theft = try #require(response.threats.first { $0.threatId == "credential-theft" })
        #expect(theft.severityId == "low")
        #expect(theft.severityLabel == "Low")
        #expect(theft.riskScore == 3)
        #expect(theft.riskLevel == "low")
        #expect(theft.overriddenSeverityId == "low")
    }

    @Test func leavesAThreatWithoutAnOverrideAlone() throws {
        let response = assess(ThreatModel(components: [ec2(id: "c1")]))

        let theft = try #require(response.threats.first { $0.threatId == "credential-theft" })
        #expect(theft.severityId == "critical")
        #expect(theft.overriddenSeverityId == nil)
    }

    @Test func appliesOneOverrideToEveryComponentOfThatTechnology() {
        // Spec section 5.3 keys a component override by technology.
        let key = SeverityOverrideKey.forComponent(
            technologyId: TechnologyId("aws-ec2"),
            threatId: ThreatId("credential-theft")
        )
        let response = assess(
            ThreatModel(components: [ec2(id: "c1"), ec2(id: "c2")], severityOverrides: [key: "low"])
        )

        let theft = response.threats.filter { $0.threatId == "credential-theft" }
        #expect(theft.count == 2)
        #expect(theft.allSatisfy { $0.severityId == "low" })
    }

    @Test func appliesTheZoneMultiplierAfterTheOverride() throws {
        let key = SeverityOverrideKey.forComponent(
            technologyId: TechnologyId("aws-ec2"),
            threatId: ThreatId("credential-theft")
        )
        let response = assess(
            ThreatModel(
                components: [ec2(id: "c1")],
                zones: [privateZone(reduction: 50)],
                severityOverrides: [key: "high"]
            )
        )

        // High (3) against confidential (3) is 9; a half reduction leaves 4.5,
        // which rounds away from zero to 5.
        #expect(try #require(response.threats.first { $0.threatId == "credential-theft" }).riskScore == 5)
    }

    @Test func ignoresAnOverrideToASeverityTheTaxonomyDoesNotHave() throws {
        let key = SeverityOverrideKey.forComponent(
            technologyId: TechnologyId("aws-ec2"),
            threatId: ThreatId("credential-theft")
        )
        let response = assess(
            ThreatModel(components: [ec2(id: "c1")], severityOverrides: [key: "catastrophic"])
        )

        let theft = try #require(response.threats.first { $0.threatId == "credential-theft" })
        #expect(theft.severityId == "critical")
        #expect(theft.overriddenSeverityId == nil)
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter AssessThreatModelTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `value of type 'AssessedThreat' has no member 'overriddenSeverityId'`.

- [ ] **Step 3: Apply the override in the resolver**

Add to `ResolvedThreat`, after `overrideKey`:

```swift
    /// The severity id the user overrode this threat to, or nil. When set,
    /// `severity` is that severity rather than the threat's own.
    public let overriddenSeverityId: String?
```

Add one helper to `ThreatResolver`:

```swift
    /// The severity a threat is scored with: the one the user overrode it to
    /// when the taxonomy knows that id, else the threat's own. An override to
    /// an id the taxonomy has never heard of is ignored rather than trusted;
    /// a catalogue update can retire a severity.
    private func severity(for threat: Threat, overrideKey: SeverityOverrideKey)
        -> (severity: ThreatSeverity, overriddenId: String?) {
        guard let overriddenId = model.severityOverrides[overrideKey],
              let overridden = catalogue.taxonomy().severity(id: overriddenId) else {
            return (threat.severity, nil)
        }
        return (overridden, overriddenId)
    }
```

At each of the three raise sites, work the severity out before the score and use it for both:

```swift
                let overrideKey = SeverityOverrideKey.forComponent(
                    technologyId: component.technologyId,
                    threatId: threat.id
                )
                let (severity, overriddenId) = severity(for: threat, overrideKey: overrideKey)
                let base = RiskScore(severity: severity, sensitivity: component.sensitivity)
```

and pass `severity: severity`, `overrideKey: overrideKey`, `overriddenSeverityId: overriddenId`. Do the same at the link site with `.forConnection(threatId:)` and at the zone site with `.forZone(threatId:)`.

- [ ] **Step 4: Carry it onto the response**

Add to `AssessedThreat` after `overrideKey`:

```swift
    /// The severity id the user overrode this threat to, or nil.
    public let overriddenSeverityId: String?
```

and map `overriddenSeverityId: threat.overriddenSeverityId` in `execute`.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit
git commit -m "feat: score a threat with the severity the user overrode it to

The override replaces the severity before the score, so the rank, the score
and the level all follow it, and the zone multiplier applies afterwards. An
override to a severity the taxonomy has retired is ignored."
```

---

### Task 6: `OverrideThreatSeverity` and `ClearSeverityOverride`

**Files:**
- Create: `.../assessment/usecase/OverrideThreatSeverity.swift`
- Create: `.../assessment/usecase/ClearSeverityOverride.swift`
- Modify: `.../UseCaseFactory.swift`, `.../TestDependencies.swift`, `threatmodeller/Dependencies.swift`
- Test: `ThreatModelKit/Tests/UnitTests/OverrideThreatSeverityTests.swift`

**Interfaces:**
- Consumes: `ThreatModelGateway`, `TechnologyCatalogue.taxonomy()`, `SeverityOverrideKey`.
- Produces: `OverrideThreatSeverityUseCase`, `OverrideThreatSeverityRequest(overrideKey:severityId:)`, `OverrideThreatSeverityResponse` (`.overridden`, `.unknownSeverity`); `ClearSeverityOverrideUseCase`, `ClearSeverityOverrideRequest(overrideKey:)`, `ClearSeverityOverrideResponse` (`.cleared`, `.noOverride`).

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/OverrideThreatSeverityTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct OverrideThreatSeverityTests {
    private let models = InMemoryThreatModelGateway()
    private let catalogue = CatalogueFixture.catalogue()

    private let key = SeverityOverrideKey.forComponent(
        technologyId: TechnologyId("aws-ec2"),
        threatId: ThreatId("credential-theft")
    )

    private func override(_ keyValue: String, to severityId: String) -> OverrideThreatSeverityResponse {
        OverrideThreatSeverity(models: models, catalogue: catalogue)
            .execute(OverrideThreatSeverityRequest(overrideKey: keyValue, severityId: severityId))
    }

    private func clear(_ keyValue: String) -> ClearSeverityOverrideResponse {
        ClearSeverityOverride(models: models)
            .execute(ClearSeverityOverrideRequest(overrideKey: keyValue))
    }

    @Test func recordsTheOverride() {
        #expect(override(key.value, to: "low") == .overridden)

        #expect(models.current().severityOverrides == [key: "low"])
    }

    @Test func replacesAnOverrideAlreadyThere() {
        _ = override(key.value, to: "low")

        #expect(override(key.value, to: "high") == .overridden)
        #expect(models.current().severityOverrides == [key: "high"])
    }

    @Test func refusesASeverityTheTaxonomyDoesNotHave() {
        #expect(override(key.value, to: "catastrophic") == .unknownSeverity)
        #expect(models.current().severityOverrides.isEmpty)
    }

    @Test func acceptsEverySeverityTheTaxonomyHas() {
        for severity in catalogue.taxonomy().severities {
            #expect(override(key.value, to: severity.id) == .overridden)
        }
    }

    @Test func acceptsAnyKeyShapeTheResponseHandedOut() {
        #expect(override("connection::connection-mitm", to: "high") == .overridden)
        #expect(override("zone::lateral-movement", to: "low") == .overridden)
        #expect(models.current().severityOverrides.count == 2)
    }

    @Test func clearsAnOverride() {
        _ = override(key.value, to: "low")

        #expect(clear(key.value) == .cleared)
        #expect(models.current().severityOverrides.isEmpty)
    }

    @Test func saysSoWhenThereIsNothingToClear() {
        #expect(clear(key.value) == .noOverride)
    }

    @Test func clearsOnlyTheKeyNamed() {
        _ = override(key.value, to: "low")
        _ = override("zone::lateral-movement", to: "high")

        #expect(clear(key.value) == .cleared)
        #expect(models.current().severityOverrides
                == [SeverityOverrideKey("zone::lateral-movement"): "high"])
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter OverrideThreatSeverityTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'OverrideThreatSeverity' in scope`.

- [ ] **Step 3: Write both use cases**

Create `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/OverrideThreatSeverity.swift`:

```swift
public protocol OverrideThreatSeverityUseCase {
    func execute(_ request: OverrideThreatSeverityRequest) -> OverrideThreatSeverityResponse
}

public struct OverrideThreatSeverityRequest: Equatable, Sendable {
    /// A key `AssessThreatModel` handed out. The core mints every key, so a
    /// delivery mechanism only ever echoes one it was given.
    public let overrideKey: String
    public let severityId: String

    public init(overrideKey: String, severityId: String) {
        self.overrideKey = overrideKey
        self.severityId = severityId
    }
}

public enum OverrideThreatSeverityResponse: Equatable, Sendable {
    case overridden
    case unknownSeverity
}

/// Records the severity the user judges a threat to carry on their system.
///
/// WARNING: spec section 5.3 keys a component threat by its technology, so one
/// override applies to every component of that technology, and a link or zone
/// override applies to every link or every zone. The key comes from the
/// response, so this use case simply records what it is given.
public struct OverrideThreatSeverity: OverrideThreatSeverityUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: OverrideThreatSeverityRequest) -> OverrideThreatSeverityResponse {
        guard catalogue.taxonomy().severity(id: request.severityId) != nil else {
            return .unknownSeverity
        }

        var model = models.current()
        model.severityOverrides[SeverityOverrideKey(request.overrideKey)] = request.severityId
        models.save(model)

        return .overridden
    }
}
```

Create `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/ClearSeverityOverride.swift`:

```swift
public protocol ClearSeverityOverrideUseCase {
    func execute(_ request: ClearSeverityOverrideRequest) -> ClearSeverityOverrideResponse
}

public struct ClearSeverityOverrideRequest: Equatable, Sendable {
    public let overrideKey: String

    public init(overrideKey: String) {
        self.overrideKey = overrideKey
    }
}

public enum ClearSeverityOverrideResponse: Equatable, Sendable {
    case cleared
    case noOverride
}

/// Puts a threat back to the severity the catalogue gives it.
public struct ClearSeverityOverride: ClearSeverityOverrideUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: ClearSeverityOverrideRequest) -> ClearSeverityOverrideResponse {
        let key = SeverityOverrideKey(request.overrideKey)

        var model = models.current()
        guard model.severityOverrides[key] != nil else { return .noOverride }

        model.severityOverrides[key] = nil
        models.save(model)

        return .cleared
    }
}
```

- [ ] **Step 4: Vend them from both composition roots**

Add to `UseCaseFactory`:

```swift
    func overrideThreatSeverity() -> OverrideThreatSeverityUseCase
    func clearSeverityOverride() -> ClearSeverityOverrideUseCase
```

Add to `TestDependencies` and `Dependencies`, each with its own access level:

```swift
    func overrideThreatSeverity() -> OverrideThreatSeverityUseCase {
        OverrideThreatSeverity(models: models, catalogue: catalogue)
    }

    func clearSeverityOverride() -> ClearSeverityOverrideUseCase {
        ClearSeverityOverride(models: models)
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
git add ThreatModelKit threatmodeller/Dependencies.swift
git commit -m "feat: add OverrideThreatSeverity and ClearSeverityOverride

Both take a key the assessment handed out, so no delivery mechanism builds
one. An override to a severity the taxonomy does not have is refused."
```

---

### Task 7: `RecordControlImplemented` and `RecordControlNotImplemented`

**Files:**
- Create: `.../assessment/usecase/RecordControlImplemented.swift`
- Create: `.../assessment/usecase/RecordControlNotImplemented.swift`
- Modify: `.../UseCaseFactory.swift`, `.../TestDependencies.swift`, `threatmodeller/Dependencies.swift`
- Test: `ThreatModelKit/Tests/UnitTests/RecordControlTests.swift`

**Interfaces:**
- Consumes: `ThreatModelGateway`, `ControlKey`.
- Produces: `RecordControlImplementedUseCase` with `RecordControlImplementedRequest(controlKey:)` and `RecordControlImplementedResponse.recorded`; `RecordControlNotImplementedUseCase` with `RecordControlNotImplementedRequest(controlKey:)` and `RecordControlNotImplementedResponse.recorded`.

Both are idempotent and neither can fail. A tick that is already ticked stays ticked; unticking something never ticked is not an error. Spec §5.3 gives a control no scoring rule, so neither changes a score.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/RecordControlTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct RecordControlTests {
    private let models = InMemoryThreatModelGateway()
    private let key = ControlIdentity.componentControl(
        componentId: ComponentId("c1"),
        threatId: ThreatId("credential-theft"),
        description: "Rotate credentials regularly",
        isTechnologySpecific: false
    )
    private let other = ControlIdentity.connectionControl(
        threatId: ThreatId("connection-mitm"),
        description: "Enforce TLS on every hop"
    )

    private func record(_ key: ControlKey) -> RecordControlImplementedResponse {
        RecordControlImplemented(models: models)
            .execute(RecordControlImplementedRequest(controlKey: key.value))
    }

    private func unrecord(_ key: ControlKey) -> RecordControlNotImplementedResponse {
        RecordControlNotImplemented(models: models)
            .execute(RecordControlNotImplementedRequest(controlKey: key.value))
    }

    @Test func recordsAControlAsInPlace() {
        #expect(record(key) == .recorded)

        #expect(models.current().implementedControls == [key])
    }

    @Test func recordingTwiceIsRecordingOnce() {
        _ = record(key)

        #expect(record(key) == .recorded)
        #expect(models.current().implementedControls == [key])
    }

    @Test func takesAControlBackOut() {
        _ = record(key)

        #expect(unrecord(key) == .recorded)
        #expect(models.current().implementedControls.isEmpty)
    }

    @Test func takingOutSomethingNeverRecordedIsNotAnError() {
        #expect(unrecord(key) == .recorded)
        #expect(models.current().implementedControls.isEmpty)
    }

    @Test func touchesNoOtherControl() {
        _ = record(key)
        _ = record(other)

        _ = unrecord(key)

        #expect(models.current().implementedControls == [other])
    }

    @Test func changesNoScore() {
        let catalogue = CatalogueFixture.catalogue()
        let seeded = InMemoryThreatModelGateway(
            ThreatModel(components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .confidential
                )
            ])
        )
        let assess = AssessThreatModel(models: seeded, catalogue: catalogue)
        let before = assess.execute(AssessThreatModelRequest()).threats.map(\.riskScore)

        _ = RecordControlImplemented(models: seeded).execute(
            RecordControlImplementedRequest(
                controlKey: ControlIdentity.componentControl(
                    componentId: ComponentId("c1"),
                    threatId: ThreatId("credential-theft"),
                    description: "Use IAM roles with minimal permissions",
                    isTechnologySpecific: true
                ).value
            )
        )

        #expect(assess.execute(AssessThreatModelRequest()).threats.map(\.riskScore) == before)
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter RecordControlTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'RecordControlImplemented' in scope`.

- [ ] **Step 3: Write both use cases**

Create `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/RecordControlImplemented.swift`:

```swift
public protocol RecordControlImplementedUseCase {
    func execute(_ request: RecordControlImplementedRequest) -> RecordControlImplementedResponse
}

public struct RecordControlImplementedRequest: Equatable, Sendable {
    /// A key `AssessThreatModel` handed out.
    public let controlKey: String

    public init(controlKey: String) {
        self.controlKey = controlKey
    }
}

public enum RecordControlImplementedResponse: Equatable, Sendable {
    case recorded
}

/// Records that a control is in place.
///
/// Idempotent, and it cannot fail: the key came from the assessment, and
/// recording something twice is recording it once. Spec section 5.3 gives a
/// control no scoring rule, so this changes no score.
public struct RecordControlImplemented: RecordControlImplementedUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RecordControlImplementedRequest) -> RecordControlImplementedResponse {
        var model = models.current()
        model.implementedControls.insert(ControlKey(request.controlKey))
        models.save(model)

        return .recorded
    }
}
```

Create `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/RecordControlNotImplemented.swift`:

```swift
public protocol RecordControlNotImplementedUseCase {
    func execute(_ request: RecordControlNotImplementedRequest) -> RecordControlNotImplementedResponse
}

public struct RecordControlNotImplementedRequest: Equatable, Sendable {
    public let controlKey: String

    public init(controlKey: String) {
        self.controlKey = controlKey
    }
}

public enum RecordControlNotImplementedResponse: Equatable, Sendable {
    case recorded
}

/// Records that a control is not in place.
///
/// Idempotent, and it cannot fail: taking out something never recorded leaves
/// the model as it was.
public struct RecordControlNotImplemented: RecordControlNotImplementedUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(
        _ request: RecordControlNotImplementedRequest
    ) -> RecordControlNotImplementedResponse {
        var model = models.current()
        model.implementedControls.remove(ControlKey(request.controlKey))
        models.save(model)

        return .recorded
    }
}
```

- [ ] **Step 4: Vend them from both composition roots**

Add to `UseCaseFactory`:

```swift
    func recordControlImplemented() -> RecordControlImplementedUseCase
    func recordControlNotImplemented() -> RecordControlNotImplementedUseCase
```

Add to `TestDependencies` and `Dependencies`:

```swift
    func recordControlImplemented() -> RecordControlImplementedUseCase {
        RecordControlImplemented(models: models)
    }

    func recordControlNotImplemented() -> RecordControlNotImplementedUseCase {
        RecordControlNotImplemented(models: models)
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
git add ThreatModelKit threatmodeller/Dependencies.swift
git commit -m "feat: record whether a control is in place

Both use cases are idempotent and neither can fail. A control is a record of
work done; the spec gives it no scoring rule, so neither changes a score."
```

---

### Task 8: `SummariseRisk`

**Files:**
- Create: `.../assessment/usecase/SummariseRisk.swift`
- Modify: `.../assessment/domain/RiskScore.swift` — `RiskLevel` gains a label
- Modify: `.../UseCaseFactory.swift`, `.../TestDependencies.swift`, `threatmodeller/Dependencies.swift`
- Test: `ThreatModelKit/Tests/UnitTests/SummariseRiskTests.swift`

**Interfaces:**
- Consumes: `ThreatResolver`, `Taxonomy.stride`.
- Produces: `RiskLevel.label`; `SummariseRiskUseCase`, `SummariseRiskRequest()`, `SummariseRiskResponse(totalThreats:byLevel:byStride:controlsOffered:controlsRecorded:)`, `RiskLevelCount(levelId:label:count:)`, `StrideCount(strideId:label:count:)`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/SummariseRiskTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct SummariseRiskTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func summarise(_ model: ThreatModel) -> SummariseRiskResponse {
        SummariseRisk(models: InMemoryThreatModelGateway(model), catalogue: catalogue)
            .execute(SummariseRiskRequest())
    }

    private func ec2(_ id: String, sensitivity: DataSensitivity = .confidential) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: sensitivity
        )
    }

    @Test func summarisesAnEmptyModelAsNothing() {
        let summary = summarise(ThreatModel())

        #expect(summary.totalThreats == 0)
        #expect(summary.byLevel.allSatisfy { $0.count == 0 })
        #expect(summary.byStride.allSatisfy { $0.count == 0 })
        #expect(summary.controlsOffered == 0)
        #expect(summary.controlsRecorded == 0)
    }

    @Test func countsEveryLevelWorstFirst() {
        // EC2 at confidential raises credential-theft 12 (critical),
        // misconfiguration 6 (medium) and dos-attack 3 (low).
        let summary = summarise(ThreatModel(components: [ec2("c1")]))

        #expect(summary.totalThreats == 3)
        #expect(summary.byLevel.map(\.levelId) == ["critical", "high", "medium", "low"])
        #expect(summary.byLevel.map(\.label) == ["Critical", "High", "Medium", "Low"])
        #expect(summary.byLevel.map(\.count) == [1, 0, 1, 1])
    }

    @Test func countsEveryStrideCategoryInTaxonomyOrder() {
        let summary = summarise(ThreatModel(components: [ec2("c1")]))

        #expect(summary.byStride.map(\.strideId) == catalogue.taxonomy().stride.map(\.id.value))
        #expect(summary.byStride.map(\.label) == catalogue.taxonomy().stride.map(\.label))

        // credential-theft is spoofing, misconfiguration is tampering,
        // dos-attack is denial-of-service.
        let counts = Dictionary(
            uniqueKeysWithValues: summary.byStride.map { ($0.strideId, $0.count) }
        )
        #expect(counts["spoofing"] == 1)
        #expect(counts["tampering"] == 1)
        #expect(counts["denial-of-service"] == 1)
        #expect(counts["repudiation"] == 0)
    }

    @Test func countsAThreatOnceInEveryCategoryItCarries() {
        // connection-mitm carries both tampering and information-disclosure.
        let summary = summarise(
            ThreatModel(
                components: [ec2("c1", sensitivity: .internalData), ec2("c2", sensitivity: .internalData)],
                connections: [Connection(id: ConnectionId("k1"), source: ComponentId("c1"), target: ComponentId("c2"))]
            )
        )

        let counts = Dictionary(
            uniqueKeysWithValues: summary.byStride.map { ($0.strideId, $0.count) }
        )
        #expect(counts["information-disclosure"] == 1)
        #expect((counts["tampering"] ?? 0) >= 1)
    }

    @Test func talliesTheControlsOfferedAndTheOnesRecorded() throws {
        let plain = summarise(ThreatModel(components: [ec2("c1")]))
        #expect(plain.controlsOffered > 0)
        #expect(plain.controlsRecorded == 0)

        let key = ControlIdentity.componentControl(
            componentId: ComponentId("c1"),
            threatId: ThreatId("credential-theft"),
            description: "Use IAM roles with minimal permissions",
            isTechnologySpecific: true
        )
        let recorded = summarise(
            ThreatModel(components: [ec2("c1")], implementedControls: [key])
        )
        #expect(recorded.controlsOffered == plain.controlsOffered)
        #expect(recorded.controlsRecorded == 1)
    }

    @Test func countsAConsolidatedControlOnceAcrossItsOwners() {
        // Two links share one connection control key, so the tally counts one.
        let model = ThreatModel(
            components: [
                ec2("c1", sensitivity: .internalData),
                ec2("c2", sensitivity: .internalData),
                ec2("c3", sensitivity: .internalData)
            ],
            connections: [
                Connection(id: ConnectionId("k1"), source: ComponentId("c1"), target: ComponentId("c2")),
                Connection(id: ConnectionId("k2"), source: ComponentId("c1"), target: ComponentId("c3"))
            ]
        )

        let one = summarise(
            ThreatModel(
                components: [ec2("c1", sensitivity: .internalData), ec2("c2", sensitivity: .internalData)],
                connections: [Connection(id: ConnectionId("k1"), source: ComponentId("c1"), target: ComponentId("c2"))]
            )
        )
        let two = summarise(model)

        // The second link raises more threats but offers no new control keys
        // beyond the third component's own.
        #expect(two.totalThreats > one.totalThreats)
        #expect(two.controlsOffered > one.controlsOffered)
    }

    @Test func agreesWithWhatTheSidebarLists() {
        let model = ThreatModel(
            components: [ec2("c1"), ec2("c2", sensitivity: .publicData)],
            zones: [Zone(id: ZoneId("z1"), rect: Rect(x: -100, y: -100, width: 800, height: 700))]
        )
        let listed = AssessThreatModel(models: InMemoryThreatModelGateway(model), catalogue: catalogue)
            .execute(AssessThreatModelRequest()).threats

        #expect(summarise(model).totalThreats == listed.count)
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter SummariseRiskTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'SummariseRisk' in scope`.

- [ ] **Step 3: Give `RiskLevel` a label**

In `.../assessment/domain/RiskScore.swift`:

```swift
public enum RiskLevel: String, CaseIterable, Equatable, Sendable {
    case low
    case medium
    case high
    case critical

    public var label: String {
        switch self {
        case .low: "Low"
        case .medium: "Medium"
        case .high: "High"
        case .critical: "Critical"
        }
    }
}
```

- [ ] **Step 4: Write the use case**

Create `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/SummariseRisk.swift`:

```swift
public protocol SummariseRiskUseCase {
    func execute(_ request: SummariseRiskRequest) -> SummariseRiskResponse
}

public struct SummariseRiskRequest: Equatable, Sendable {
    public init() {}
}

public struct RiskLevelCount: Equatable, Sendable {
    public let levelId: String
    public let label: String
    public let count: Int

    public init(levelId: String, label: String, count: Int) {
        self.levelId = levelId
        self.label = label
        self.count = count
    }
}

public struct StrideCount: Equatable, Sendable {
    public let strideId: String
    public let label: String
    public let count: Int

    public init(strideId: String, label: String, count: Int) {
        self.strideId = strideId
        self.label = label
        self.count = count
    }
}

public struct SummariseRiskResponse: Equatable, Sendable {
    public let totalThreats: Int
    /// Worst first: critical, high, medium, low. Every level appears, even at
    /// zero, so the strip does not change shape as the model changes.
    public let byLevel: [RiskLevelCount]
    /// In taxonomy order. Every category appears, even at zero. A threat
    /// carrying two categories is counted once in each.
    public let byStride: [StrideCount]
    /// Distinct control keys the model offers, and how many are recorded. A
    /// control consolidated across links or zones counts once.
    public let controlsOffered: Int
    public let controlsRecorded: Int

    public init(
        totalThreats: Int,
        byLevel: [RiskLevelCount],
        byStride: [StrideCount],
        controlsOffered: Int,
        controlsRecorded: Int
    ) {
        self.totalThreats = totalThreats
        self.byLevel = byLevel
        self.byStride = byStride
        self.controlsOffered = controlsOffered
        self.controlsRecorded = controlsRecorded
    }
}

/// Counts what the model raises.
///
/// It reads the same `ThreatResolver` the sidebar's list reads, so a count can
/// never disagree with the rows beneath it.
public struct SummariseRisk: SummariseRiskUseCase {
    private static let worstFirst: [RiskLevel] = [.critical, .high, .medium, .low]

    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: SummariseRiskRequest) -> SummariseRiskResponse {
        let resolved = ThreatResolver(model: models.current(), catalogue: catalogue).resolve()

        var levels: [RiskLevel: Int] = [:]
        var stride: [StrideId: Int] = [:]
        var offered: Set<ControlKey> = []
        var recorded: Set<ControlKey> = []

        for threat in resolved {
            levels[threat.score.level, default: 0] += 1
            for category in Set(threat.threat.stride) {
                stride[category, default: 0] += 1
            }
            for control in threat.controls {
                offered.insert(control.key)
                if control.isImplemented { recorded.insert(control.key) }
            }
        }

        return SummariseRiskResponse(
            totalThreats: resolved.count,
            byLevel: Self.worstFirst.map {
                RiskLevelCount(levelId: $0.rawValue, label: $0.label, count: levels[$0] ?? 0)
            },
            byStride: catalogue.taxonomy().stride.map {
                StrideCount(strideId: $0.id.value, label: $0.label, count: stride[$0.id] ?? 0)
            },
            controlsOffered: offered.count,
            controlsRecorded: recorded.count
        )
    }
}
```

- [ ] **Step 5: Vend it from both composition roots**

Add to `UseCaseFactory`:

```swift
    func summariseRisk() -> SummariseRiskUseCase
```

Add to `TestDependencies` and `Dependencies`:

```swift
    func summariseRisk() -> SummariseRiskUseCase {
        SummariseRisk(models: models, catalogue: catalogue)
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
git commit -m "feat: add SummariseRisk

Counts by risk level and by STRIDE category, plus a control tally. It reads
the same resolver the list reads, so a count can never disagree with the rows
beneath it."
```

---

### Task 9: The acceptance test

**Files:**
- Create: `ThreatModelKit/Tests/AcceptanceTests/ReadingAndAnsweringThreatsTests.swift`

- [ ] **Step 1: Write the test**

Create `ThreatModelKit/Tests/AcceptanceTests/ReadingAndAnsweringThreatsTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

/// Given threats raised against my model
/// When I record the controls I have and correct a severity
/// Then the summary and the cards follow
struct ReadingAndAnsweringThreatsTests {
    private let app = TestDependencies()

    private func add(_ technologyId: String, sensitivity: String) -> String {
        let response = app.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: 100, y: 100, sensitivity: sensitivity)
        )
        guard case .added(let componentId) = response else {
            Issue.record("Expected the component to be added, got \(response)")
            return ""
        }
        return componentId
    }

    private func threats() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    private func threat(_ threatId: String) throws -> AssessedThreat {
        try #require(threats().first { $0.threatId == threatId })
    }

    private func summary() -> SummariseRiskResponse {
        app.summariseRisk().execute(SummariseRiskRequest())
    }

    @Test func showsEveryThreatWithItsTagsTechniquesAndControls() throws {
        _ = add("aws-ec2", sensitivity: "confidential")

        let theft = try threat("credential-theft")
        #expect(theft.severityLabel == "Critical")
        #expect(theft.riskScore == 12)
        #expect(theft.stride == ["spoofing"])
        #expect(theft.mitreTechniques.map(\.id) == ["T1552"])
        #expect(theft.controls.map(\.description) == [
            "Enforce IMDSv2 to block SSRF-based credential theft",
            "Use IAM roles with minimal permissions"
        ])
        #expect(theft.controls.allSatisfy { $0.isImplemented == false })
        #expect(theft.controls.allSatisfy { $0.key.isEmpty == false })
    }

    @Test func recordsAControlTheUserTicks() throws {
        _ = add("aws-ec2", sensitivity: "confidential")
        let control = try #require(try threat("credential-theft").controls.first)

        #expect(app.recordControlImplemented().execute(
            RecordControlImplementedRequest(controlKey: control.key)
        ) == .recorded)

        let after = try threat("credential-theft")
        #expect(after.controls.first?.isImplemented == true)
        #expect(after.riskScore == 12)
        #expect(summary().controlsRecorded == 1)

        #expect(app.recordControlNotImplemented().execute(
            RecordControlNotImplementedRequest(controlKey: control.key)
        ) == .recorded)
        #expect(try threat("credential-theft").controls.first?.isImplemented == false)
        #expect(summary().controlsRecorded == 0)
    }

    @Test func correctsASeverityTheCatalogueGotWrongForThisSystem() throws {
        _ = add("aws-ec2", sensitivity: "confidential")
        let key = try threat("credential-theft").overrideKey

        #expect(app.overrideThreatSeverity().execute(
            OverrideThreatSeverityRequest(overrideKey: key, severityId: "low")
        ) == .overridden)

        let lowered = try threat("credential-theft")
        #expect(lowered.severityLabel == "Low")
        #expect(lowered.riskScore == 3)
        #expect(lowered.riskLevel == "low")
        #expect(lowered.overriddenSeverityId == "low")
        #expect(summary().byLevel.first { $0.levelId == "critical" }?.count == 0)

        #expect(app.clearSeverityOverride().execute(
            ClearSeverityOverrideRequest(overrideKey: key)
        ) == .cleared)
        #expect(try threat("credential-theft").riskScore == 12)
    }

    @Test func appliesOneOverrideToEveryComponentOfThatTechnology() throws {
        _ = add("aws-ec2", sensitivity: "confidential")
        _ = add("aws-ec2", sensitivity: "confidential")
        let key = try threat("credential-theft").overrideKey

        _ = app.overrideThreatSeverity().execute(
            OverrideThreatSeverityRequest(overrideKey: key, severityId: "low")
        )

        let theft = threats().filter { $0.threatId == "credential-theft" }
        #expect(theft.count == 2)
        #expect(theft.allSatisfy { $0.severityLabel == "Low" })
    }

    @Test func summarisesTheWholeModel() throws {
        _ = add("aws-ec2", sensitivity: "confidential")

        let counted = summary()
        #expect(counted.totalThreats == threats().count)
        #expect(counted.byLevel.map(\.levelId) == ["critical", "high", "medium", "low"])
        #expect(counted.byLevel.first { $0.levelId == "critical" }?.count == 1)
        #expect(counted.byStride.first { $0.strideId == "spoofing" }?.count == 1)
        #expect(counted.controlsOffered > 0)
    }

    @Test func forgetsAComponentsTicksWhenItIsRemoved() throws {
        let web = add("aws-ec2", sensitivity: "confidential")
        let control = try #require(try threat("credential-theft").controls.first)
        _ = app.recordControlImplemented().execute(
            RecordControlImplementedRequest(controlKey: control.key)
        )
        #expect(summary().controlsRecorded == 1)

        _ = app.removeComponents().execute(RemoveComponentsRequest(componentIds: [web]))

        #expect(summary().controlsRecorded == 0)
        #expect(summary().totalThreats == 0)
    }
}
```

- [ ] **Step 2: Run it, then the whole suite**

Tasks 1–8 exist to make this pass.

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter ReadingAndAnsweringThreatsTests 2>&1 | tail -5
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && time swift test 2>&1 | tail -3
```

Expected: PASS, whole suite under 30 seconds.

- [ ] **Step 3: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit/Tests/AcceptanceTests/ReadingAndAnsweringThreatsTests.swift
git commit -m "test: accept the milestone 4 core at the use case boundary

Every threat arrives with its tags, techniques and controls. Ticking a
control records it and changes no score. Overriding a severity rescores the
threat and every other component of that technology. Removing a component
forgets its ticks."
```

---

### Task 10: The session carries the summary and the three new commands

**Files:**
- Modify: `.../assessment/usecase/AssessThreatModel.swift` — the response gains the severity choices
- Modify: `threatmodeller/ThreatModelSession.swift`
- Modify: `threatmodellerTests/threatmodellerTests.swift`

**Interfaces:**
- Consumes: the five use cases from Tasks 6–8.
- Produces: `AssessedSeverity(id:label:)` and `AssessThreatModelResponse.severities: [AssessedSeverity]`; `ThreatModelSession.summary`, `.severityChoices`, `.setControl(key:implemented:)`, `.overrideSeverity(overrideKey:severityId:)`, `.clearOverride(overrideKey:)`.

The card's override menu has to list the severities to choose from, and nothing else on the boundary carries them. They belong to the assessment, so `AssessThreatModelResponse` carries them in taxonomy order.

- [ ] **Step 1: Write the failing test**

Add to `threatmodellerTests/threatmodellerTests.swift`:

```swift
    @Test func summarisesWhatTheSidebarLists() {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)

        #expect(session.summary.totalThreats == session.threats.count)
        #expect(session.summary.byLevel.map(\.levelId) == ["critical", "high", "medium", "low"])
        #expect(session.summary.controlsOffered > 0)
        #expect(session.summary.controlsRecorded == 0)
    }

    @Test func offersEverySeverityTheUserCanOverrideTo() {
        let session = session()

        #expect(session.severityChoices.map(\.id) == ["low", "medium", "high", "critical"])
        #expect(session.severityChoices.map(\.label) == ["Low", "Medium", "High", "Critical"])
    }

    @Test func ticksAndUnticksAControl() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        let control = try #require(
            session.threats.first { $0.threatId == "credential-theft" }?.controls.first
        )

        session.setControl(key: control.key, implemented: true)
        #expect(session.summary.controlsRecorded == 1)
        #expect(session.errorMessage == nil)

        session.setControl(key: control.key, implemented: false)
        #expect(session.summary.controlsRecorded == 0)
    }

    @Test func overridesAndRestoresASeverity() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        let key = try #require(session.threats.first { $0.threatId == "credential-theft" }).overrideKey

        session.overrideSeverity(overrideKey: key, severityId: "low")
        #expect(try #require(session.threats.first { $0.threatId == "credential-theft" }).severityId == "low")

        session.clearOverride(overrideKey: key)
        #expect(try #require(session.threats.first { $0.threatId == "credential-theft" }).severityId == "critical")
        #expect(session.errorMessage == nil)
    }

    @Test func reportsASeverityItDoesNotKnow() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        let key = try #require(session.threats.first { $0.threatId == "credential-theft" }).overrideKey

        session.overrideSeverity(overrideKey: key, severityId: "catastrophic")

        #expect(session.errorMessage == "That severity is not in the catalogue.")
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `value of type 'ThreatModelSession' has no member 'summary'`.

- [ ] **Step 3: Carry the severity choices on the assessment response**

In `AssessThreatModel.swift`, add the value type above `AssessThreatModelResponse`:

```swift
/// A severity the user can override a threat to. In taxonomy order, weakest
/// first, which is the order the ranks run in.
public struct AssessedSeverity: Equatable, Sendable {
    public let id: String
    public let label: String

    public init(id: String, label: String) {
        self.id = id
        self.label = label
    }
}
```

Add `severities` to `AssessThreatModelResponse` as the last stored property and initialiser parameter, and fill it in `execute`:

```swift
            severities: catalogue.taxonomy().severities.map {
                AssessedSeverity(id: $0.id, label: $0.label)
            }
```

- [ ] **Step 4: Give the session the summary and the commands**

In `threatmodeller/ThreatModelSession.swift`, add the published values beside `threats`:

```swift
    private(set) var summary = SummariseRiskResponse(
        totalThreats: 0,
        byLevel: [],
        byStride: [],
        controlsOffered: 0,
        controlsRecorded: 0
    )
    /// The severities the override menu offers.
    private(set) var severityChoices: [AssessedSeverity] = []
```

Add the three commands beside the zone ones:

```swift
    func setControl(key: String, implemented: Bool) {
        if implemented {
            _ = useCases.recordControlImplemented().execute(
                RecordControlImplementedRequest(controlKey: key)
            )
        } else {
            _ = useCases.recordControlNotImplemented().execute(
                RecordControlNotImplementedRequest(controlKey: key)
            )
        }

        errorMessage = nil
        refresh()
    }

    func overrideSeverity(overrideKey: String, severityId: String) {
        switch useCases.overrideThreatSeverity().execute(
            OverrideThreatSeverityRequest(overrideKey: overrideKey, severityId: severityId)
        ) {
        case .overridden:
            errorMessage = nil
        case .unknownSeverity:
            errorMessage = "That severity is not in the catalogue."
        }

        refresh()
    }

    func clearOverride(overrideKey: String) {
        // Clearing something that is not overridden is not worth a message: the
        // card only offers the command when there is an override to clear.
        _ = useCases.clearSeverityOverride().execute(
            ClearSeverityOverrideRequest(overrideKey: overrideKey)
        )

        errorMessage = nil
        refresh()
    }
```

And extend `refresh`:

```swift
    private func refresh() {
        canvas = useCases.viewThreatModel().execute(ViewThreatModelRequest())
        let assessment = useCases.assessThreatModel().execute(AssessThreatModelRequest())
        threats = assessment.threats
        severityChoices = assessment.severities
        summary = useCases.summariseRisk().execute(SummariseRiskRequest())
    }
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'Failing tests|\*\* TEST' -A3 | head -6
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit threatmodeller threatmodellerTests
git commit -m "feat: publish the risk summary and the three sidebar commands

The session carries the summary and the severities the override menu offers,
and gains one method per new use case."
```

---

### Task 11: The threat sidebar

**Files:**
- Create: `threatmodeller/sidebar/RiskSummaryView.swift`
- Create: `threatmodeller/sidebar/ThreatCard.swift`
- Create: `threatmodeller/sidebar/ThreatSidebar.swift`
- Modify: `threatmodeller/ContentView.swift`

**Interfaces:**
- Consumes: `ThreatModelSession.threats`, `.summary`, `.severityChoices`, `.setControl(key:implemented:)`, `.overrideSeverity(overrideKey:severityId:)`, `.clearOverride(overrideKey:)`.
- Produces: `ThreatSidebar(session:)`; accessibility identifiers `risk-summary`, `threat-group-<sourceId>`, `threat-card-<threatId>#<sourceId>`, `control-<key>`, `override-<overrideKey>`.

The layout is the one you chose: a risk summary strip, then one collapsible group per source, each holding that source's cards worst first.

- [ ] **Step 1: Write the summary strip**

Create `threatmodeller/sidebar/RiskSummaryView.swift`:

```swift
import SwiftUI
import ThreatModelKit

/// Counts over the whole model, above the cards they count.
struct RiskSummaryView: View {
    let summary: SummariseRiskResponse

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                ForEach(summary.byLevel, id: \.levelId) { level in
                    VStack(spacing: 1) {
                        Text("\(level.count)")
                            .font(.title3.monospacedDigit())
                            .foregroundStyle(level.count == 0 ? .secondary : Self.colour(level.levelId))
                        Text(level.label)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                }
            }

            if summary.controlsOffered > 0 {
                ProgressView(
                    value: Double(summary.controlsRecorded),
                    total: Double(summary.controlsOffered)
                ) {
                    Text("\(summary.controlsRecorded) of \(summary.controlsOffered) controls in place")
                        .font(.caption)
                }
            }

            HStack(spacing: 6) {
                ForEach(summary.byStride, id: \.strideId) { category in
                    Text("\(Self.initial(category.label)) \(category.count)")
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(category.count == 0 ? .tertiary : .secondary)
                        .help("\(category.label): \(category.count)")
                }
            }
        }
        .padding(12)
        .accessibilityIdentifier("risk-summary")
    }

    private static func colour(_ levelId: String) -> Color {
        switch levelId {
        case "critical": .red
        case "high": .orange
        case "medium": .yellow
        default: .secondary
        }
    }

    /// STRIDE reads as six initials. The full label is on the tooltip.
    private static func initial(_ label: String) -> String {
        String(label.prefix(1))
    }
}
```

- [ ] **Step 2: Write the card**

Create `threatmodeller/sidebar/ThreatCard.swift`:

```swift
import SwiftUI
import ThreatModelKit

/// One threat: what it is, how bad it is here, and what answers it.
struct ThreatCard: View {
    let threat: AssessedThreat
    let severityChoices: [AssessedSeverity]
    let onSetControl: (_ key: String, _ implemented: Bool) -> Void
    let onOverride: (_ severityId: String) -> Void
    let onClearOverride: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            header
            tags

            Text(threat.context ?? threat.description)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)

            if threat.mitreTechniques.isEmpty == false {
                ForEach(threat.mitreTechniques, id: \.id) { technique in
                    Text("\(technique.id) · \(technique.name) · \(technique.tactic)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            if threat.controls.isEmpty == false {
                Divider()
                ForEach(threat.controls, id: \.key) { control in
                    Toggle(isOn: Binding(
                        get: { control.isImplemented },
                        set: { onSetControl(control.key, $0) }
                    )) {
                        Text(control.description)
                            .font(.caption)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .toggleStyle(.checkbox)
                    .accessibilityIdentifier("control-\(control.key)")
                }
            }
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .controlBackgroundColor)))
        .overlay(
            RoundedRectangle(cornerRadius: 8).strokeBorder(Color.secondary.opacity(0.25), lineWidth: 1)
        )
        .accessibilityIdentifier("threat-card-\(threat.threatId)#\(threat.source.id)")
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(threat.name)
                .font(.headline)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            Text("\(threat.riskLevel.capitalized) · \(threat.riskScore)")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
        }
    }

    private var tags: some View {
        HStack(spacing: 6) {
            severityMenu

            ForEach(threat.stride, id: \.self) { category in
                Text(category.replacingOccurrences(of: "-", with: " ").capitalized)
                    .font(.caption2)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Capsule().fill(Color.secondary.opacity(0.15)))
            }

            if threat.isTlsMitigated {
                Label("TLS", systemImage: "lock")
                    .font(.caption2)
                    .help("An endpoint enforces encryption. This does not change the score.")
            }

            Spacer(minLength: 0)
        }
    }

    /// The severity is a menu, because it is both a label and the one number
    /// on the card the user is allowed to disagree with.
    private var severityMenu: some View {
        Menu {
            ForEach(severityChoices, id: \.id) { severity in
                Button(severity.label) { onOverride(severity.id) }
            }
            if threat.overriddenSeverityId != nil {
                Divider()
                Button("Use the catalogue's severity") { onClearOverride() }
            }
        } label: {
            HStack(spacing: 3) {
                Text(threat.severityLabel)
                if threat.overriddenSeverityId != nil {
                    Image(systemName: "pencil").font(.caption2)
                }
            }
            .font(.caption2)
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .accessibilityIdentifier("override-\(threat.overrideKey)")
        .help(threat.overriddenSeverityId == nil
              ? "The catalogue's severity"
              : "You set this severity. It applies everywhere this threat is raised from the same source kind.")
    }
}
```

- [ ] **Step 3: Write the sidebar**

Create `threatmodeller/sidebar/ThreatSidebar.swift`:

```swift
import SwiftUI
import ThreatModelKit

/// The threat list: a summary, then one group per source, worst first.
struct ThreatSidebar: View {
    let session: ThreatModelSession

    @State private var collapsed: Set<String> = []

    /// One group per source, each holding that source's threats. Groups are
    /// ordered by their worst threat, so the component needing most attention
    /// is at the top. `session.threats` is already worst first, so the first
    /// time a source appears is its worst threat.
    private var groups: [(id: String, name: String, threats: [AssessedThreat])] {
        var order: [String] = []
        var bySource: [String: [AssessedThreat]] = [:]
        var names: [String: String] = [:]

        for threat in session.threats {
            let id = threat.source.id
            if bySource[id] == nil {
                order.append(id)
                names[id] = threat.source.displayName
            }
            bySource[id, default: []].append(threat)
        }

        return order.map { (id: $0, name: names[$0] ?? $0, threats: bySource[$0] ?? []) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let errorMessage = session.errorMessage {
                Text(errorMessage)
                    .foregroundStyle(.red)
                    .padding(.horizontal, 12)
                    .padding(.top, 8)
            }

            if session.threats.isEmpty {
                ContentUnavailableView(
                    "No threats yet",
                    systemImage: "shield",
                    description: Text("Add a technology from the palette to see the threats it carries.")
                )
            } else {
                RiskSummaryView(summary: session.summary)
                Divider()
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 10, pinnedViews: [.sectionHeaders]) {
                        ForEach(groups, id: \.id) { group in
                            Section {
                                if collapsed.contains(group.id) == false {
                                    ForEach(group.threats, id: \.rowIdentity) { threat in
                                        ThreatCard(
                                            threat: threat,
                                            severityChoices: session.severityChoices,
                                            onSetControl: { key, implemented in
                                                session.setControl(key: key, implemented: implemented)
                                            },
                                            onOverride: { severityId in
                                                session.overrideSeverity(
                                                    overrideKey: threat.overrideKey,
                                                    severityId: severityId
                                                )
                                            },
                                            onClearOverride: {
                                                session.clearOverride(overrideKey: threat.overrideKey)
                                            }
                                        )
                                    }
                                }
                            } header: {
                                groupHeader(group)
                            }
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                }
            }
        }
        .navigationTitle("Threats")
    }

    private func groupHeader(_ group: (id: String, name: String, threats: [AssessedThreat])) -> some View {
        let isCollapsed = collapsed.contains(group.id)

        return Button {
            if isCollapsed { collapsed.remove(group.id) } else { collapsed.insert(group.id) }
        } label: {
            HStack(spacing: 6) {
                Image(systemName: isCollapsed ? "chevron.right" : "chevron.down")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .frame(width: 10)
                Text(group.name)
                    .font(.subheadline.weight(.semibold))
                    .lineLimit(1)
                Spacer(minLength: 4)
                Text("\(group.threats.count)")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            .padding(.vertical, 4)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .background(.bar)
        .accessibilityIdentifier("threat-group-\(group.id)")
    }
}
```

- [ ] **Step 4: Put it in the window**

In `threatmodeller/ContentView.swift`, delete the old `ThreatListView` struct and the `rowIdentity` extension it held, move that extension to `ThreatSidebar.swift`, and change `ModelView`'s detail column:

```swift
        } detail: {
            ThreatSidebar(session: session)
                .navigationSplitViewColumnWidth(min: 300, ideal: 380)
        }
```

The extension moves verbatim into `ThreatSidebar.swift`:

```swift
private extension AssessedThreat {
    /// Row key for the sidebar. `AssessedThreat` carries no identity field of
    /// its own, so two equal threats would collide as one row. The pair of
    /// `threatId` and the source's id identifies a row.
    var rowIdentity: String { "\(threatId)#\(source.id)" }
}
```

WARNING: the app saves its split-view arrangement in its container preferences. A saved arrangement wider than the window leaves the sidebar column collapsed, so the palette renders nothing and `XCUIApplication` reports no window at all. Milestone 2's 20000-point window defect wrote one such arrangement. If the user interface suite fails at the very first assertion, clear it and re-run:

```bash
osascript -e 'tell application "threatmodeller" to quit' 2>/dev/null
defaults delete uk.craigbass.threatmodeller 2>/dev/null
rm -rf ~/Library/"Saved Application State"/uk.craigbass.threatmodeller.savedState
```

- [ ] **Step 5: Build, run the suites, and look at it**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'error:|Failing tests|\*\* TEST' -A3 | head -8
```

Expected: PASS.

Then open the app and check by eye: the summary counts match the cards below it; a group collapses and opens; a control ticks and the summary's tally follows; the severity menu changes the score and the level; "Use the catalogue's severity" puts it back.

- [ ] **Step 6: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add threatmodeller
git commit -m "feat: rebuild the threat list as a sidebar of cards

A risk summary over the whole model, then one collapsible group per source
holding its threats worst first. Each card carries its STRIDE tags, its MITRE
techniques, a checkbox per control and a severity menu."
```

---

### Task 12: The user interface journey

**Files:**
- Modify: `threatmodellerUITests/threatmodellerUITests.swift`

- [ ] **Step 1: Extend the journey**

After the zone assertions, add:

```swift
        // Tick a control on a card and see the summary follow.
        mark("ticking a control")
        let summaryStrip = app.descendants(matching: .any)["risk-summary"].firstMatch
        XCTAssertTrue(
            summaryStrip.waitForExistence(timeout: 5),
            "The risk summary never appeared above the threat cards."
        )

        let firstCheckbox = app.checkBoxes.firstMatch
        XCTAssertTrue(
            firstCheckbox.waitForExistence(timeout: 5),
            "No control checkbox appeared on any threat card."
        )
        XCTAssertEqual(firstCheckbox.value as? Int, 0, "The control started ticked.")
        firstCheckbox.click()

        let expectation = XCTNSPredicateExpectation(
            predicate: NSPredicate(format: "value == 1"),
            object: firstCheckbox
        )
        XCTAssertEqual(
            XCTWaiter().wait(for: [expectation], timeout: 10),
            .completed,
            "Clicking the control did not record it."
        )
        mark("control recorded")
```

WARNING: if `app.checkBoxes` is empty, the toggle may report as a button. Dump the tree with `print(app.debugDescription)` at that point, read which element kind the checkbox is, and query that kind. Remove the dump before committing.

- [ ] **Step 2: Run the user interface suite**

```bash
cd /Users/craigjbass/Projects/threat-modeller
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
git commit -m "test: walk the journey as far as ticking a control

The journey now reads the risk summary and ticks a control on a threat card."
```

---

## Milestone complete

- [ ] `swift test` from `ThreatModelKit/` is green and runs in under 30 seconds.
- [ ] `xcodebuild ... test` is green, including the user interface suite.
- [ ] No view builds a control key or an override key: `grep -rn 'node:\|connection:\|zone:' threatmodeller/` finds only accessibility identifiers.
- [ ] `SummariseRisk` and `AssessThreatModel` both read `ThreatResolver`, so a count cannot disagree with a list.
- [ ] The catalogue tag is still `v1.0.1`.
- [ ] A card shows its severity, score, level, STRIDE tags, MITRE techniques and controls.
- [ ] Ticking a control records it, changes no score, and moves the summary's tally.
- [ ] Overriding a severity rescores the threat and every other threat sharing its key.
- [ ] Clearing an override puts the catalogue's severity back.
- [ ] Removing a component forgets that component's ticks and leaves every override.
- [ ] Groups collapse and open, and are ordered by their worst threat.

Then write `docs/superpowers/specs/MILESTONE-5-CARRY-FORWARD.md` and start the Milestone 5 plan.

Deferred, with the trigger unchanged: the non-atomic gateway append; the three catalogue faults tied to a tag bump; the missing `IdentityGenerator` and `ThreatModelGateway` contracts; the fixed `internal` sensitivity; `String(describing: error)` on the catalogue failure; the palette's missing keyboard path; the fixed 20000 point drawing square; the unmeasured anchor, path and containment arithmetic; the single-zone selection; the zone drawing order; the un-debounced zone name field; the missing undo; and the gestures no user interface test reaches.

New and deferred from this milestone: nothing prunes a control key whose description has left the catalogue, and a technology literally named `connection` or `zone` would collide with the link and zone override key shapes. Neither is reachable with the vendored catalogue at `v1.0.1`.
