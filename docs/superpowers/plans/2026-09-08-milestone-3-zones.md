# Milestone 3: Zones — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The user draws network trust zones on the canvas, moves and resizes them, and sees the components they capture score lower, the links between two private zones score lower, and each private zone raise its own zone threats.

**Architecture:** Zone membership is derived, never stored. `Zone` holds a rectangle and its properties; a `ZoneContainment` domain object answers which zone holds a component from the geometry alone, and `AssessThreatModel` and `ViewThreatModel` call it. `ZoneMultiplier` owns the scoring reduction. The app target gains `ZoneBox` and `ZoneHandle` geometry, a zone layer painted under everything else, a zone drawing mode, and a zone panel.

**Tech Stack:** Swift 6.3 (Swift 6 language mode in the package and the app target), Swift Package Manager, Swift Testing, SwiftUI, macOS 26.

**Spec:** `docs/superpowers/specs/2026-09-07-native-macos-threat-modeller-design.md`

**Carry-forward:** `docs/superpowers/specs/MILESTONE-3-CARRY-FORWARD.md`

**Read Task 12 before starting Task 1.** Task 12 is the acceptance test — the outer loop. Swift cannot compile a test that names types which do not yet exist, so it is written after the types, but Tasks 1–11 exist to make it pass.

## Global Constraints

- Minimum deployment target: macOS 26. The package declares `platforms: [.macOS(.v26)]`.
- Package manifest uses `// swift-tools-version: 6.2`. The app target builds with `SWIFT_VERSION = 6.0`.
- WARNING: the app target sets `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`, so every type declared there is main-actor isolated unless it says `nonisolated`. Every geometry struct is `nonisolated`.
- WARNING: two source files in one module may not share a basename. `Identifiers.swift` is taken by the catalogue; the modelling one is `ModellingIdentifiers.swift`.
- WARNING: a key path passed to a `rethrows` method inside an `#expect` macro fails to compile. Use a closure: `#expect(xs.allSatisfy { $0.flag })`.
- `ThreatModelKit` must not `import SwiftUI`, `import AppKit`, `import CoreGraphics`, or read from disk.
- Domain objects never cross a use case boundary. Every `Request` and `Response` type contains only `String`, `Int`, `Double`, `Bool`, arrays, enums of those, and other Response structs.
- Use cases take collaborators in `init` and the request in `execute`. One use case per file. Protocol named `<Name>UseCase`, concrete type named `<Name>`.
- Catalogue pinned at `jib1337/threat-model-library` tag **v1.0.1**. Do not raise the tag in this milestone.
- Risk score = severity rank × sensitivity rank, then the zone multiplier, then `round()`. Risk level from the multiplied score: `>= 12` critical, `>= 8` high, `>= 4` medium, otherwise low. Any threat scoring 0 is filtered out.
- Zone multiplier: 1.0 for a public zone or no zone; 1.0 for a private zone with risk reduction off; else `(100 − reductionPercent) / 100`. Default reduction 20 per cent.
- A link takes a multiplier only when both ends sit in private zones, and then the **lower** of the two reduction percentages.
- Zone threats are scored against a fixed `internal` sensitivity, raised once per **private** zone, and take that zone's own multiplier.
- Connection and zone threats always use the threat's generic controls, never a technology's mitigations.
- Zone containment: the component's centre inside the zone rectangle with its 40 point header band removed. Later zones win over earlier ones.
- Commit after every task. Never commit a red suite.

## Out of scope for this milestone

Pathway mitigations, severity overrides, implemented controls, threat cards grouped by source, undo/redo, documents, copy and paste, custom technologies, external actors, exports, samples, connection labels, and the component property panel. `RenameComponent`, `SetComponentSensitivity` and `DisableComponentThreats` stay out, so `ThreatModelSession` still fixes `sensitivity: "internal"`.

Everything else on `MILESTONE-3-CARRY-FORWARD.md` keeps the trigger already recorded against it. Only item 9 — `CanvasView` holding gestures, hit test and layout in one file — is closed here, by Task 13, and it is done **before** any zone view is written.

## File Structure

**Created:**

| Path | Responsibility |
|---|---|
| `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Rect.swift` | `Size`, `Rect` |
| `.../modelling/domain/Zone.swift` | `Zone`, `NetworkZone`, `ZoneNetworkType` |
| `.../modelling/usecase/AddZone.swift` | `AddZone` and its Request/Response |
| `.../modelling/usecase/ResizeZone.swift` | `ResizeZone` and its Request/Response |
| `.../modelling/usecase/SetZoneProperties.swift` | `SetZoneProperties` and its Request/Response |
| `.../modelling/usecase/RemoveZone.swift` | `RemoveZone` and its Request/Response |
| `.../assessment/domain/ZoneContainment.swift` | Which zone holds a component |
| `.../assessment/domain/ZoneMultiplier.swift` | The scoring reduction |
| `ThreatModelKit/Tests/UnitTests/RectTests.swift` | Geometry values |
| `.../UnitTests/ZoneTests.swift` | `Zone.displayName` and the vocabulary |
| `.../UnitTests/ZoneContainmentTests.swift` | Containment |
| `.../UnitTests/ZoneMultiplierTests.swift` | The multiplier and the link rule |
| `.../UnitTests/AddZoneTests.swift`, `ResizeZoneTests.swift`, `SetZonePropertiesTests.swift`, `RemoveZoneTests.swift` | One per use case |
| `ThreatModelKit/Tests/AcceptanceTests/GroupingComponentsIntoZonesTests.swift` | The milestone's outer loop |
| `threatmodeller/canvas/CanvasHitTest.swift` | Pure hit testing over the viewed model |
| `threatmodeller/canvas/CanvasGestures.swift` | Every gesture the canvas installs |
| `threatmodeller/canvas/ZoneBox.swift` | `ZoneHandle`, `ZoneBox` |
| `threatmodeller/canvas/ZoneView.swift` | One zone, its header and its handles |
| `threatmodeller/canvas/ZonePanel.swift` | The bar under the canvas |
| `threatmodellerTests/canvas/CanvasHitTestTests.swift` | Hit testing |
| `threatmodellerTests/canvas/ZoneBoxTests.swift` | Zone geometry and resizing |

**Modified:**

- `.../modelling/domain/ModellingIdentifiers.swift` — gains `ZoneId`
- `.../modelling/domain/Component.swift` — gains the footprint size and `centre`
- `.../modelling/domain/ThreatModel.swift` — gains `zones` and `zone(_:)`
- `.../modelling/usecase/ViewThreatModel.swift` — gains `ViewedZone` and a component's zone
- `.../catalogue/gateway/TechnologyCatalogue.swift` — gains `zoneThreats()`
- `.../assessment/usecase/AssessThreatModel.swift` — the zone case, the multipliers, zone threats
- `ThreatModelKit/Sources/CatalogueGateways/BundledTechnologyCatalogue.swift` — `zoneThreats()`
- `ThreatModelKit/Sources/TestSupport/` — the fake, the fixture, the contract, `TestDependencies`
- `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift` — four more use cases
- `threatmodeller/Dependencies.swift` — four more use cases
- `threatmodeller/ThreatModelSession.swift` — four zone methods
- `threatmodeller/canvas/CanvasState.swift` — zone selection, drawing mode, resize in flight, pan anchor
- `threatmodeller/canvas/CanvasView.swift` — layout only after Task 13; then the zone layer
- `threatmodeller/canvas/ComponentBox.swift` — reads its size from the core
- `threatmodeller/canvas/ComponentNodeView.swift` — the zone badge
- `threatmodeller/ContentView.swift` — the zone panel under the canvas
- `threatmodellerUITests/threatmodellerUITests.swift` — the journey draws a zone

---

### Task 1: The zone domain

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Rect.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Zone.swift`
- Modify: `.../modelling/domain/ModellingIdentifiers.swift`
- Modify: `.../modelling/domain/Component.swift`
- Modify: `.../modelling/domain/ThreatModel.swift`
- Test: `ThreatModelKit/Tests/UnitTests/RectTests.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ZoneTests.swift`

**Interfaces:**
- Consumes: `Point`, `ComponentId`, `Component`.
- Produces: `ZoneId`; `Size(width:height:)`; `Rect(x:y:width:height:)` with `origin`, `size`, `minX`, `minY`, `maxX`, `maxY`, `contains(_:)`, `insetFromTop(by:)`; `NetworkZone` (`.publicZone`, `.privateZone`) with `label`; `ZoneNetworkType` (7 cases) with `label`; `Zone(id:rect:name:networkZone:networkType:riskReductionEnabled:riskReductionPercent:)` with `displayName`, `Zone.defaultRiskReductionPercent`, `Zone.minimumSize`; `Component.size`, `Component.centre`; `ThreatModel(name:components:connections:zones:)`, `ThreatModel.zone(_:)`.

- [ ] **Step 1: Write the failing tests**

Create `ThreatModelKit/Tests/UnitTests/RectTests.swift`:

```swift
import Testing
import ThreatModelKit

struct RectTests {
    private let rect = Rect(x: 10, y: 20, width: 100, height: 50)

    @Test func reportsItsEdges() {
        #expect(rect.origin == Point(x: 10, y: 20))
        #expect(rect.size == Size(width: 100, height: 50))
        #expect(rect.minX == 10)
        #expect(rect.minY == 20)
        #expect(rect.maxX == 110)
        #expect(rect.maxY == 70)
    }

    @Test func containsAPointInsideIt() {
        #expect(rect.contains(Point(x: 50, y: 40)))
        #expect(rect.contains(Point(x: 10, y: 20)))
    }

    @Test func excludesAPointOnItsFarEdges() {
        // Half-open, the way CGRect behaves: the near edges are inside and the
        // far edges are outside, so two rectangles sharing an edge never both
        // claim the same point.
        #expect(rect.contains(Point(x: 110, y: 40)) == false)
        #expect(rect.contains(Point(x: 50, y: 70)) == false)
    }

    @Test func excludesAPointOutsideIt() {
        #expect(rect.contains(Point(x: 9, y: 40)) == false)
        #expect(rect.contains(Point(x: 50, y: 19)) == false)
    }

    @Test func removesABandFromItsTop() {
        let inset = rect.insetFromTop(by: 40)

        #expect(inset.minY == 60)
        #expect(inset.maxY == 70)
        #expect(inset.minX == 10)
        #expect(inset.size.width == 100)
    }

    @Test func neverInsetsPastItsOwnBottom() {
        let inset = rect.insetFromTop(by: 500)

        #expect(inset.size.height == 0)
        #expect(inset.minY == 70)
    }
}
```

Create `ThreatModelKit/Tests/UnitTests/ZoneTests.swift`:

```swift
import Testing
import ThreatModelKit

struct ZoneTests {
    private func zone(
        name: String? = nil,
        networkZone: NetworkZone = .privateZone,
        networkType: ZoneNetworkType = .generic
    ) -> Zone {
        Zone(
            id: ZoneId("z1"),
            rect: Rect(x: 0, y: 0, width: 400, height: 300),
            name: name,
            networkZone: networkZone,
            networkType: networkType
        )
    }

    @Test func prefersTheUsersOwnName() {
        #expect(zone(name: "Payments VPC", networkType: .vpc).displayName == "Payments VPC")
    }

    @Test func fallsBackToTheNetworkTypeLabel() {
        #expect(zone(networkType: .vpc).displayName == "VPC")
        #expect(zone(networkType: .onPremises).displayName == "On-Premises")
    }

    @Test func fallsBackToTheZoneLabelForAGenericNetwork() {
        #expect(zone(networkZone: .privateZone, networkType: .generic).displayName == "Private Zone")
        #expect(zone(networkZone: .publicZone, networkType: .generic).displayName == "Public Zone")
    }

    @Test func treatsAnEmptyNameAsNoName() {
        #expect(zone(name: "", networkType: .vpc).displayName == "VPC")
        #expect(zone(name: "   ", networkType: .vpc).displayName == "VPC")
    }

    @Test func defaultsToAPrivateGenericZoneThatReducesRisk() {
        let plain = Zone(id: ZoneId("z1"), rect: Rect(x: 0, y: 0, width: 400, height: 300))

        #expect(plain.networkZone == .privateZone)
        #expect(plain.networkType == .generic)
        #expect(plain.riskReductionEnabled)
        #expect(plain.riskReductionPercent == Zone.defaultRiskReductionPercent)
        #expect(Zone.defaultRiskReductionPercent == 20)
    }

    @Test func namesEveryValueTheUserCanChoose() {
        #expect(NetworkZone.allCases.map(\.rawValue) == ["public", "private"])
        #expect(ZoneNetworkType.allCases.map(\.rawValue) == [
            "generic", "vpc", "subnet", "on-premises", "dmz", "management", "data"
        ])
        #expect(ZoneNetworkType.allCases.allSatisfy { $0.label.isEmpty == false })
    }

    @Test func findsTheCentreOfAComponentsFootprint() {
        let component = Component(
            id: ComponentId("c1"),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 100, y: 200),
            sensitivity: .internalData
        )

        #expect(component.centre == Point(
            x: 100 + Component.size.width / 2,
            y: 200 + Component.size.height / 2
        ))
    }

    @Test func findsAZoneById() {
        let model = ThreatModel(zones: [zone()])

        #expect(model.zone(ZoneId("z1"))?.id == ZoneId("z1"))
        #expect(model.zone(ZoneId("z9")) == nil)
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter ZoneTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'Zone' in scope`.

- [ ] **Step 3: Write `Rect`**

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Rect.swift`:

```swift
public struct Size: Equatable, Sendable {
    public let width: Double
    public let height: Double

    public init(width: Double, height: Double) {
        self.width = width
        self.height = height
    }
}

/// An axis-aligned rectangle in model coordinates. The origin is the top-left
/// corner, the same corner a component's position names.
public struct Rect: Equatable, Sendable {
    public let origin: Point
    public let size: Size

    public init(origin: Point, size: Size) {
        self.origin = origin
        self.size = size
    }

    public init(x: Double, y: Double, width: Double, height: Double) {
        self.init(origin: Point(x: x, y: y), size: Size(width: width, height: height))
    }

    public var minX: Double { origin.x }
    public var minY: Double { origin.y }
    public var maxX: Double { origin.x + size.width }
    public var maxY: Double { origin.y + size.height }

    /// Half-open, the way `CGRect` behaves: the near edges are inside and the
    /// far edges are outside. Two rectangles sharing an edge never both claim
    /// the same point.
    public func contains(_ point: Point) -> Bool {
        point.x >= minX && point.x < maxX && point.y >= minY && point.y < maxY
    }

    /// The rectangle with a band removed from its top edge, never shrinking
    /// past its own bottom. Zone containment ignores the zone's header band.
    public func insetFromTop(by amount: Double) -> Rect {
        let removed = min(max(amount, 0), size.height)
        return Rect(
            x: origin.x,
            y: origin.y + removed,
            width: size.width,
            height: size.height - removed
        )
    }
}
```

- [ ] **Step 4: Write `Zone` and its vocabulary**

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Zone.swift`:

```swift
/// Whether a zone is exposed or protected.
///
/// Application-owned, as `DataSensitivity` is: the catalogue carries no zone
/// vocabulary. Only a private zone reduces risk and only a private zone raises
/// zone threats.
public enum NetworkZone: String, CaseIterable, Equatable, Sendable {
    case publicZone = "public"
    case privateZone = "private"

    public var label: String {
        switch self {
        case .publicZone: "Public Zone"
        case .privateZone: "Private Zone"
        }
    }
}

/// The kind of network a zone stands for. Application-owned.
public enum ZoneNetworkType: String, CaseIterable, Equatable, Sendable {
    case generic
    case vpc
    case subnet
    case onPremises = "on-premises"
    case dmz
    case management
    case data

    public var label: String {
        switch self {
        case .generic: "Generic Network"
        case .vpc: "VPC"
        case .subnet: "Subnet"
        case .onPremises: "On-Premises"
        case .dmz: "DMZ"
        case .management: "Management Network"
        case .data: "Data Network"
        }
    }
}

/// A network trust zone drawn on the diagram.
///
/// A zone stores its rectangle and its properties and nothing else. Which
/// components it holds is derived from the geometry by `ZoneContainment`, so
/// there is no stored membership to go stale when a component or a zone moves.
public struct Zone: Equatable, Sendable {
    public static let defaultRiskReductionPercent = 20
    public static let minimumSize = Size(width: 120, height: 100)

    public let id: ZoneId
    public var rect: Rect
    public var name: String?
    public var networkZone: NetworkZone
    public var networkType: ZoneNetworkType
    public var riskReductionEnabled: Bool
    public var riskReductionPercent: Int

    public init(
        id: ZoneId,
        rect: Rect,
        name: String? = nil,
        networkZone: NetworkZone = .privateZone,
        networkType: ZoneNetworkType = .generic,
        riskReductionEnabled: Bool = true,
        riskReductionPercent: Int = Zone.defaultRiskReductionPercent
    ) {
        self.id = id
        self.rect = rect
        self.name = name
        self.networkZone = networkZone
        self.networkType = networkType
        self.riskReductionEnabled = riskReductionEnabled
        self.riskReductionPercent = riskReductionPercent
    }

    /// Spec section 5.3: the user's own name, else the network type label when
    /// the type is not `generic`, else the network zone label.
    public var displayName: String {
        if let name, name.trimmingWhitespace().isEmpty == false {
            return name.trimmingWhitespace()
        }
        if networkType != .generic { return networkType.label }
        return networkZone.label
    }
}

extension String {
    /// `Foundation.trimmingCharacters` is not used here: the core imports
    /// Foundation for value types only, and this is the whole need.
    func trimmingWhitespace() -> String {
        var characters = Array(self)
        while let first = characters.first, first.isWhitespace { characters.removeFirst() }
        while let last = characters.last, last.isWhitespace { characters.removeLast() }
        return String(characters)
    }
}
```

- [ ] **Step 5: Add `ZoneId`, the component footprint, and the aggregate's zones**

Append to `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/ModellingIdentifiers.swift`:

```swift
public struct ZoneId: Hashable, Sendable, CustomStringConvertible {
    public let value: String
    public init(_ value: String) { self.value = value }
    public var description: String { value }
}
```

Add to `Component`, inside the struct:

```swift
    /// The footprint a component occupies on the diagram.
    ///
    /// The core owns this because zone containment tests a component's centre,
    /// and a centre needs an extent. The canvas draws at this size rather than
    /// holding a second constant of its own.
    public static let size = Size(width: 160, height: 72)

    /// The centre of the footprint. `ZoneContainment` tests this point.
    public var centre: Point {
        Point(x: position.x + Self.size.width / 2, y: position.y + Self.size.height / 2)
    }
```

Replace `ThreatModel` so it carries zones:

```swift
/// The aggregate a threat model is assessed from. Overrides and implemented
/// controls join it in later milestones.
public struct ThreatModel: Equatable, Sendable {
    public var name: String
    public var components: [Component]
    public var connections: [Connection]
    /// In drawing order. A zone later in this list wins over an earlier one
    /// where they overlap.
    public var zones: [Zone]

    public init(
        name: String = "Untitled",
        components: [Component] = [],
        connections: [Connection] = [],
        zones: [Zone] = []
    ) {
        self.name = name
        self.components = components
        self.connections = connections
        self.zones = zones
    }

    /// The component with that identifier, or nil. Every write use case checks
    /// a component exists before it changes anything.
    public func component(_ id: ComponentId) -> Component? {
        components.first { $0.id == id }
    }

    public func zone(_ id: ZoneId) -> Zone? {
        zones.first { $0.id == id }
    }
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
git add ThreatModelKit
git commit -m "feat: add Zone to the modelling domain

A zone stores its rectangle and its properties and nothing else. Which
components it holds is derived from the geometry, so nothing can go stale.
The component footprint moves into the core, because containment tests a
centre and a centre needs an extent."
```

---

### Task 2: `ZoneContainment` and `ZoneMultiplier`

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ZoneContainment.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ZoneMultiplier.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ZoneContainmentTests.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ZoneMultiplierTests.swift`

**Interfaces:**
- Consumes: `Zone`, `Point`, `Rect`.
- Produces: `ZoneContainment.headerHeight`, `ZoneContainment.zone(holding:in:) -> Zone?`; `ZoneMultiplier.value(for:) -> Double`, `ZoneMultiplier.valueForConnection(sourceZone:targetZone:) -> Double`, `ZoneMultiplier.apply(_:to:) -> Int`.

- [ ] **Step 1: Write the failing tests**

Create `ThreatModelKit/Tests/UnitTests/ZoneContainmentTests.swift`:

```swift
import Testing
import ThreatModelKit

struct ZoneContainmentTests {
    private func zone(_ id: String, x: Double, y: Double, width: Double = 400, height: Double = 300) -> Zone {
        Zone(id: ZoneId(id), rect: Rect(x: x, y: y, width: width, height: height))
    }

    @Test func holdsAPointBelowTheHeaderBand() {
        let zones = [zone("z1", x: 0, y: 0)]

        #expect(ZoneContainment.zone(holding: Point(x: 200, y: 150), in: zones)?.id == ZoneId("z1"))
    }

    @Test func ignoresAPointInsideTheHeaderBand() {
        let zones = [zone("z1", x: 0, y: 0)]

        #expect(ZoneContainment.headerHeight == 40)
        #expect(ZoneContainment.zone(holding: Point(x: 200, y: 39), in: zones) == nil)
        #expect(ZoneContainment.zone(holding: Point(x: 200, y: 40), in: zones)?.id == ZoneId("z1"))
    }

    @Test func ignoresAPointOutsideEveryZone() {
        #expect(ZoneContainment.zone(holding: Point(x: 900, y: 900), in: [zone("z1", x: 0, y: 0)]) == nil)
    }

    @Test func holdsNothingWhenThereAreNoZones() {
        #expect(ZoneContainment.zone(holding: Point(x: 10, y: 10), in: []) == nil)
    }

    @Test func givesTheLaterZoneThePointWhenTwoOverlap() {
        let zones = [zone("z1", x: 0, y: 0), zone("z2", x: 100, y: 100)]

        #expect(ZoneContainment.zone(holding: Point(x: 200, y: 200), in: zones)?.id == ZoneId("z2"))
    }

    @Test func fallsBackToTheEarlierZoneOutsideTheLaterOne() {
        let zones = [zone("z1", x: 0, y: 0), zone("z2", x: 100, y: 100)]

        #expect(ZoneContainment.zone(holding: Point(x: 50, y: 50), in: zones)?.id == ZoneId("z1"))
    }

    @Test func holdsNothingInsideAZoneShorterThanItsHeader() {
        let squashed = Zone(id: ZoneId("z1"), rect: Rect(x: 0, y: 0, width: 400, height: 20))

        #expect(ZoneContainment.zone(holding: Point(x: 200, y: 10), in: [squashed]) == nil)
    }
}
```

Create `ThreatModelKit/Tests/UnitTests/ZoneMultiplierTests.swift`:

```swift
import Testing
import ThreatModelKit

struct ZoneMultiplierTests {
    private func zone(
        _ networkZone: NetworkZone = .privateZone,
        reduction: Int = 20,
        enabled: Bool = true
    ) -> Zone {
        Zone(
            id: ZoneId("z1"),
            rect: Rect(x: 0, y: 0, width: 400, height: 300),
            networkZone: networkZone,
            riskReductionEnabled: enabled,
            riskReductionPercent: reduction
        )
    }

    @Test func leavesAScoreAloneOutsideEveryZone() {
        #expect(ZoneMultiplier.value(for: nil) == 1.0)
    }

    @Test func leavesAScoreAloneInAPublicZone() {
        #expect(ZoneMultiplier.value(for: zone(.publicZone)) == 1.0)
    }

    @Test func leavesAScoreAloneInAPrivateZoneWithReductionOff() {
        #expect(ZoneMultiplier.value(for: zone(reduction: 50, enabled: false)) == 1.0)
    }

    @Test func reducesAScoreInAPrivateZone() {
        #expect(ZoneMultiplier.value(for: zone(reduction: 20)) == 0.8)
        #expect(ZoneMultiplier.value(for: zone(reduction: 50)) == 0.5)
        #expect(ZoneMultiplier.value(for: zone(reduction: 0)) == 1.0)
        #expect(ZoneMultiplier.value(for: zone(reduction: 100)) == 0.0)
    }

    @Test func roundsTheReducedScore() {
        #expect(ZoneMultiplier.apply(0.8, to: 12) == 10)   // 9.6 rounds to 10
        #expect(ZoneMultiplier.apply(0.8, to: 3) == 2)     // 2.4 rounds to 2
        #expect(ZoneMultiplier.apply(0.5, to: 5) == 3)     // 2.5 rounds away from zero
        #expect(ZoneMultiplier.apply(1.0, to: 7) == 7)
    }

    @Test func leavesALinkAloneUnlessBothEndsAreInPrivateZones() {
        #expect(ZoneMultiplier.valueForConnection(sourceZone: nil, targetZone: zone()) == 1.0)
        #expect(ZoneMultiplier.valueForConnection(sourceZone: zone(), targetZone: nil) == 1.0)
        #expect(ZoneMultiplier.valueForConnection(sourceZone: zone(.publicZone), targetZone: zone()) == 1.0)
    }

    @Test func givesALinkTheLowerOfTheTwoReductions() {
        let gentle = zone(reduction: 10)
        let strong = zone(reduction: 60)

        // 10 per cent is the lower reduction, so the multiplier is 0.9.
        #expect(ZoneMultiplier.valueForConnection(sourceZone: gentle, targetZone: strong) == 0.9)
        #expect(ZoneMultiplier.valueForConnection(sourceZone: strong, targetZone: gentle) == 0.9)
    }

    @Test func treatsAnEndWithReductionOffAsNoReductionForTheLink() {
        let off = zone(reduction: 90, enabled: false)
        let strong = zone(reduction: 60)

        #expect(ZoneMultiplier.valueForConnection(sourceZone: off, targetZone: strong) == 1.0)
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter ZoneMultiplierTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'ZoneMultiplier' in scope`.

- [ ] **Step 3: Write `ZoneContainment`**

Create `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ZoneContainment.swift`:

```swift
/// Which zone holds a component.
///
/// Spec section 5.2: the component's centre must lie inside the zone rectangle
/// with the header band removed, and a later zone wins over an earlier one, so
/// a zone drawn on top of another captures what it covers.
///
/// Nothing stores the answer. A component records a position and a zone records
/// a rectangle, so the two can never disagree.
public enum ZoneContainment {
    /// The band at the top of a zone that holds its name and its controls.
    /// A component whose centre sits in the band is not inside the zone.
    public static let headerHeight = 40.0

    public static func zone(holding centre: Point, in zones: [Zone]) -> Zone? {
        zones.last { $0.rect.insetFromTop(by: headerHeight).contains(centre) }
    }
}
```

- [ ] **Step 4: Write `ZoneMultiplier`**

Create `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ZoneMultiplier.swift`:

```swift
import Foundation

/// How much a zone reduces the risk of what it holds. Spec section 5.3.
public enum ZoneMultiplier {
    /// 1.0 outside every zone, 1.0 in a public zone, 1.0 in a private zone
    /// with risk reduction off, else `(100 − reductionPercent) / 100`.
    public static func value(for zone: Zone?) -> Double {
        guard let zone,
              zone.networkZone == .privateZone,
              zone.riskReductionEnabled else { return 1.0 }
        return Double(100 - zone.riskReductionPercent) / 100
    }

    /// The multiplier a link takes.
    ///
    /// A link takes one only when both ends sit in private zones, and then it
    /// takes the lower of the two reduction percentages — which is the higher
    /// of the two multipliers. An end with reduction off counts as no
    /// reduction, so the link takes none.
    public static func valueForConnection(sourceZone: Zone?, targetZone: Zone?) -> Double {
        guard let sourceZone, let targetZone,
              sourceZone.networkZone == .privateZone,
              targetZone.networkZone == .privateZone else { return 1.0 }
        return max(value(for: sourceZone), value(for: targetZone))
    }

    /// The score after the multiplier, rounded. Spec section 5.3.
    public static func apply(_ multiplier: Double, to score: Int) -> Int {
        Int((Double(score) * multiplier).rounded())
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
git commit -m "feat: add ZoneContainment and ZoneMultiplier

Containment is derived from the geometry, so nothing stores a membership
that could go stale. A link takes a multiplier only when both ends sit in
private zones, and then the lower of the two reductions."
```

---

### Task 3: `AddZone`

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/AddZone.swift`
- Modify: `.../ThreatModelKit/UseCaseFactory.swift`, `.../TestSupport/TestDependencies.swift`, `threatmodeller/Dependencies.swift`
- Test: `ThreatModelKit/Tests/UnitTests/AddZoneTests.swift`

**Interfaces:**
- Consumes: `ThreatModelGateway`, `IdentityGenerator`, `Zone`, `Rect`.
- Produces: `AddZoneUseCase`, `AddZoneRequest(x:y:width:height:)`, `AddZoneResponse` with `.added(zoneId:)` and `.tooSmall`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/AddZoneTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct AddZoneTests {
    private let models = InMemoryThreatModelGateway()
    private let ids = SequentialIdentityGenerator()

    private func add(x: Double = 0, y: Double = 0, width: Double = 400, height: Double = 300) -> AddZoneResponse {
        AddZone(models: models, ids: ids)
            .execute(AddZoneRequest(x: x, y: y, width: width, height: height))
    }

    @Test func addsAZoneAtTheRectangleGiven() throws {
        #expect(add(x: 40, y: 60, width: 500, height: 400) == .added(zoneId: "id-1"))

        let zone = try #require(models.current().zones.first)
        #expect(zone.rect == Rect(x: 40, y: 60, width: 500, height: 400))
    }

    @Test func startsAZonePrivateGenericAndReducingRisk() throws {
        _ = add()

        let zone = try #require(models.current().zones.first)
        #expect(zone.name == nil)
        #expect(zone.networkZone == .privateZone)
        #expect(zone.networkType == .generic)
        #expect(zone.riskReductionEnabled)
        #expect(zone.riskReductionPercent == 20)
        #expect(zone.displayName == "Private Zone")
    }

    @Test func keepsZonesInDrawingOrder() {
        _ = add()
        _ = add(x: 100, y: 100)

        #expect(models.current().zones.map(\.id.value) == ["id-1", "id-2"])
    }

    @Test func refusesARectangleSmallerThanTheMinimum() {
        #expect(add(width: Zone.minimumSize.width - 1, height: 300) == .tooSmall)
        #expect(add(width: 400, height: Zone.minimumSize.height - 1) == .tooSmall)
        #expect(models.current().zones.isEmpty)
    }

    @Test func acceptsARectangleExactlyTheMinimum() {
        #expect(add(width: Zone.minimumSize.width, height: Zone.minimumSize.height)
                == .added(zoneId: "id-1"))
    }

    @Test func spendsNoIdentifierOnAZoneItRefuses() {
        _ = add(width: 10, height: 10)

        #expect(add() == .added(zoneId: "id-1"))
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter AddZoneTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'AddZone' in scope`.

- [ ] **Step 3: Write the use case**

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/AddZone.swift`:

```swift
public protocol AddZoneUseCase {
    func execute(_ request: AddZoneRequest) -> AddZoneResponse
}

public struct AddZoneRequest: Equatable, Sendable {
    public let x: Double
    public let y: Double
    public let width: Double
    public let height: Double

    public init(x: Double, y: Double, width: Double, height: Double) {
        self.x = x
        self.y = y
        self.width = width
        self.height = height
    }
}

public enum AddZoneResponse: Equatable, Sendable {
    case added(zoneId: String)
    /// Smaller than `Zone.minimumSize`. A drag that barely moves would
    /// otherwise leave a zone too small to see or to grab.
    case tooSmall
}

/// Draws a new zone.
///
/// A new zone is private, generic and reducing risk by the default
/// percentage, because that is the zone a threat modeller draws most often.
/// `SetZoneProperties` changes any of it. The zone goes on the end of the
/// list, so it wins over the zones already drawn where they overlap.
public struct AddZone: AddZoneUseCase {
    private let models: ThreatModelGateway
    private let ids: IdentityGenerator

    public init(models: ThreatModelGateway, ids: IdentityGenerator) {
        self.models = models
        self.ids = ids
    }

    public func execute(_ request: AddZoneRequest) -> AddZoneResponse {
        guard request.width >= Zone.minimumSize.width,
              request.height >= Zone.minimumSize.height else {
            return .tooSmall
        }

        let zone = Zone(
            id: ZoneId(ids.next()),
            rect: Rect(x: request.x, y: request.y, width: request.width, height: request.height)
        )

        var model = models.current()
        model.zones.append(zone)
        models.save(model)

        return .added(zoneId: zone.id.value)
    }
}
```

- [ ] **Step 4: Vend it from both composition roots**

Add to `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`, after `removeConnection()`:

```swift
    func addZone() -> AddZoneUseCase
```

Add to `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`:

```swift
    public func addZone() -> AddZoneUseCase {
        AddZone(models: models, ids: ids)
    }
```

Add to `threatmodeller/Dependencies.swift`:

```swift
    func addZone() -> AddZoneUseCase {
        AddZone(models: models, ids: ids)
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
git commit -m "feat: add AddZone

A new zone is private, generic and reducing risk by 20 per cent, and goes on
the end of the list so it wins where it overlaps an earlier zone."
```

---

### Task 4: `ResizeZone`

Moving a zone and resizing a zone are the same change to the same rectangle, so one use case covers both. Spec §4 lists no `MoveZone`.

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/ResizeZone.swift`
- Modify: `.../UseCaseFactory.swift`, `.../TestDependencies.swift`, `threatmodeller/Dependencies.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ResizeZoneTests.swift`

**Interfaces:**
- Consumes: `ThreatModelGateway`, `Zone`, `Rect`, `ThreatModel.zone(_:)`.
- Produces: `ResizeZoneUseCase`, `ResizeZoneRequest(zoneId:x:y:width:height:)`, `ResizeZoneResponse` with `.resized`, `.unknownZone`, `.tooSmall`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/ResizeZoneTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct ResizeZoneTests {
    private let models = InMemoryThreatModelGateway(
        ThreatModel(zones: [
            Zone(id: ZoneId("z1"), rect: Rect(x: 0, y: 0, width: 400, height: 300), name: "Payments"),
            Zone(id: ZoneId("z2"), rect: Rect(x: 500, y: 0, width: 400, height: 300))
        ])
    )

    private func resize(
        _ id: String,
        x: Double = 10,
        y: Double = 20,
        width: Double = 600,
        height: Double = 500
    ) -> ResizeZoneResponse {
        ResizeZone(models: models)
            .execute(ResizeZoneRequest(zoneId: id, x: x, y: y, width: width, height: height))
    }

    private func rect(_ id: String) -> Rect? {
        models.current().zone(ZoneId(id))?.rect
    }

    @Test func putsTheZoneAtTheNewRectangle() {
        #expect(resize("z1") == .resized)

        #expect(rect("z1") == Rect(x: 10, y: 20, width: 600, height: 500))
        #expect(rect("z2") == Rect(x: 500, y: 0, width: 400, height: 300))
    }

    @Test func movesAZoneWhenTheSizeIsUnchanged() {
        #expect(resize("z1", x: 300, y: 400, width: 400, height: 300) == .resized)

        #expect(rect("z1") == Rect(x: 300, y: 400, width: 400, height: 300))
    }

    @Test func keepsEveryOtherProperty() throws {
        _ = resize("z1")

        let zone = try #require(models.current().zone(ZoneId("z1")))
        #expect(zone.name == "Payments")
        #expect(zone.networkZone == .privateZone)
        #expect(zone.riskReductionPercent == 20)
    }

    @Test func keepsTheDrawingOrder() {
        _ = resize("z1")

        #expect(models.current().zones.map(\.id.value) == ["z1", "z2"])
    }

    @Test func refusesAZoneTheModelDoesNotHold() {
        #expect(resize("z9") == .unknownZone)
        #expect(rect("z1") == Rect(x: 0, y: 0, width: 400, height: 300))
    }

    @Test func refusesARectangleSmallerThanTheMinimum() {
        #expect(resize("z1", width: Zone.minimumSize.width - 1, height: 300) == .tooSmall)
        #expect(rect("z1") == Rect(x: 0, y: 0, width: 400, height: 300))
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter ResizeZoneTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'ResizeZone' in scope`.

- [ ] **Step 3: Write the use case**

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/ResizeZone.swift`:

```swift
public protocol ResizeZoneUseCase {
    func execute(_ request: ResizeZoneRequest) -> ResizeZoneResponse
}

public struct ResizeZoneRequest: Equatable, Sendable {
    public let zoneId: String
    public let x: Double
    public let y: Double
    public let width: Double
    public let height: Double

    public init(zoneId: String, x: Double, y: Double, width: Double, height: Double) {
        self.zoneId = zoneId
        self.x = x
        self.y = y
        self.width = width
        self.height = height
    }
}

public enum ResizeZoneResponse: Equatable, Sendable {
    case resized
    case unknownZone
    case tooSmall
}

/// Puts a zone at a new rectangle.
///
/// Moving and resizing are the same change to the same rectangle, so one use
/// case covers both: a move keeps the width and the height. The rectangle is
/// absolute, so the same request applied twice leaves the same model. The
/// zone's other properties and its place in the drawing order do not change.
public struct ResizeZone: ResizeZoneUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: ResizeZoneRequest) -> ResizeZoneResponse {
        let id = ZoneId(request.zoneId)

        var model = models.current()
        guard let index = model.zones.firstIndex(where: { $0.id == id }) else {
            return .unknownZone
        }
        guard request.width >= Zone.minimumSize.width,
              request.height >= Zone.minimumSize.height else {
            return .tooSmall
        }

        model.zones[index].rect = Rect(
            x: request.x,
            y: request.y,
            width: request.width,
            height: request.height
        )
        models.save(model)

        return .resized
    }
}
```

- [ ] **Step 4: Vend it from both composition roots**

Add to `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`:

```swift
    func resizeZone() -> ResizeZoneUseCase
```

Add to `TestDependencies` and to `Dependencies`, each with its own access level:

```swift
    func resizeZone() -> ResizeZoneUseCase {
        ResizeZone(models: models)
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
git commit -m "feat: add ResizeZone

Moving and resizing are the same change to the same rectangle, so one use
case covers both. The rectangle is absolute, so a repeated request leaves
the same model."
```

---

### Task 5: `SetZoneProperties`

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/SetZoneProperties.swift`
- Modify: `.../UseCaseFactory.swift`, `.../TestDependencies.swift`, `threatmodeller/Dependencies.swift`
- Test: `ThreatModelKit/Tests/UnitTests/SetZonePropertiesTests.swift`

**Interfaces:**
- Consumes: `ThreatModelGateway`, `Zone`, `NetworkZone`, `ZoneNetworkType`.
- Produces: `SetZonePropertiesUseCase`, `SetZonePropertiesRequest(zoneId:name:networkZone:networkType:riskReductionEnabled:riskReductionPercent:)`, `SetZonePropertiesResponse` with `.updated`, `.unknownZone`, `.unknownNetworkZone`, `.unknownNetworkType`, `.reductionOutOfRange`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/SetZonePropertiesTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct SetZonePropertiesTests {
    private let models = InMemoryThreatModelGateway(
        ThreatModel(zones: [
            Zone(id: ZoneId("z1"), rect: Rect(x: 0, y: 0, width: 400, height: 300))
        ])
    )

    private func set(
        _ id: String = "z1",
        name: String? = "Payments",
        networkZone: String = "private",
        networkType: String = "vpc",
        enabled: Bool = true,
        percent: Int = 40
    ) -> SetZonePropertiesResponse {
        SetZoneProperties(models: models).execute(
            SetZonePropertiesRequest(
                zoneId: id,
                name: name,
                networkZone: networkZone,
                networkType: networkType,
                riskReductionEnabled: enabled,
                riskReductionPercent: percent
            )
        )
    }

    private func zone() -> Zone? { models.current().zone(ZoneId("z1")) }

    @Test func setsEveryProperty() throws {
        #expect(set() == .updated)

        let changed = try #require(zone())
        #expect(changed.name == "Payments")
        #expect(changed.networkZone == .privateZone)
        #expect(changed.networkType == .vpc)
        #expect(changed.riskReductionEnabled)
        #expect(changed.riskReductionPercent == 40)
        #expect(changed.displayName == "Payments")
    }

    @Test func keepsTheRectangle() throws {
        _ = set()

        #expect(try #require(zone()).rect == Rect(x: 0, y: 0, width: 400, height: 300))
    }

    @Test func treatsAnEmptyNameAsNoName() throws {
        #expect(set(name: "   ") == .updated)

        #expect(try #require(zone()).name == nil)
        #expect(try #require(zone()).displayName == "VPC")
    }

    @Test func trimsTheNameItIsGiven() throws {
        _ = set(name: "  Payments  ")

        #expect(try #require(zone()).name == "Payments")
    }

    @Test func refusesAZoneTheModelDoesNotHold() {
        #expect(set("z9") == .unknownZone)
        #expect(zone()?.name == nil)
    }

    @Test func refusesAZoneKindItDoesNotKnow() {
        #expect(set(networkZone: "semi-private") == .unknownNetworkZone)
        #expect(zone()?.name == nil)
    }

    @Test func refusesANetworkTypeItDoesNotKnow() {
        #expect(set(networkType: "mainframe") == .unknownNetworkType)
        #expect(zone()?.name == nil)
    }

    @Test func refusesAReductionOutsideZeroToOneHundred() {
        #expect(set(percent: -1) == .reductionOutOfRange)
        #expect(set(percent: 101) == .reductionOutOfRange)
        #expect(zone()?.name == nil)
    }

    @Test func acceptsBothEndsOfTheReductionRange() {
        #expect(set(percent: 0) == .updated)
        #expect(set(percent: 100) == .updated)
        #expect(zone()?.riskReductionPercent == 100)
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter SetZonePropertiesTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'SetZoneProperties' in scope`.

- [ ] **Step 3: Write the use case**

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/SetZoneProperties.swift`:

```swift
public protocol SetZonePropertiesUseCase {
    func execute(_ request: SetZonePropertiesRequest) -> SetZonePropertiesResponse
}

public struct SetZonePropertiesRequest: Equatable, Sendable {
    public let zoneId: String
    /// Whitespace is trimmed. An empty name means the zone has none, and its
    /// display name falls back to the network type or the zone kind.
    public let name: String?
    public let networkZone: String
    public let networkType: String
    public let riskReductionEnabled: Bool
    /// 0 to 100 inclusive.
    public let riskReductionPercent: Int

    public init(
        zoneId: String,
        name: String?,
        networkZone: String,
        networkType: String,
        riskReductionEnabled: Bool,
        riskReductionPercent: Int
    ) {
        self.zoneId = zoneId
        self.name = name
        self.networkZone = networkZone
        self.networkType = networkType
        self.riskReductionEnabled = riskReductionEnabled
        self.riskReductionPercent = riskReductionPercent
    }
}

public enum SetZonePropertiesResponse: Equatable, Sendable {
    case updated
    case unknownZone
    case unknownNetworkZone
    case unknownNetworkType
    case reductionOutOfRange
}

/// Sets everything about a zone except its rectangle.
///
/// The change is all or nothing: one bad value leaves every property as it
/// was, so a rejected form never half-applies.
public struct SetZoneProperties: SetZonePropertiesUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetZonePropertiesRequest) -> SetZonePropertiesResponse {
        let id = ZoneId(request.zoneId)

        var model = models.current()
        guard let index = model.zones.firstIndex(where: { $0.id == id }) else {
            return .unknownZone
        }
        guard let networkZone = NetworkZone(rawValue: request.networkZone) else {
            return .unknownNetworkZone
        }
        guard let networkType = ZoneNetworkType(rawValue: request.networkType) else {
            return .unknownNetworkType
        }
        guard (0...100).contains(request.riskReductionPercent) else {
            return .reductionOutOfRange
        }

        let trimmed = request.name?.trimmingWhitespace()

        model.zones[index].name = (trimmed?.isEmpty == false) ? trimmed : nil
        model.zones[index].networkZone = networkZone
        model.zones[index].networkType = networkType
        model.zones[index].riskReductionEnabled = request.riskReductionEnabled
        model.zones[index].riskReductionPercent = request.riskReductionPercent
        models.save(model)

        return .updated
    }
}
```

- [ ] **Step 4: Vend it from both composition roots**

Add to `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`:

```swift
    func setZoneProperties() -> SetZonePropertiesUseCase
```

Add to `TestDependencies` and to `Dependencies`, each with its own access level:

```swift
    func setZoneProperties() -> SetZonePropertiesUseCase {
        SetZoneProperties(models: models)
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
git commit -m "feat: add SetZoneProperties

Name, kind, network type and risk reduction, all or nothing: one bad value
leaves every property as it was."
```

---

### Task 6: `RemoveZone`

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/RemoveZone.swift`
- Modify: `.../UseCaseFactory.swift`, `.../TestDependencies.swift`, `threatmodeller/Dependencies.swift`
- Test: `ThreatModelKit/Tests/UnitTests/RemoveZoneTests.swift`

**Interfaces:**
- Consumes: `ThreatModelGateway`, `Zone`.
- Produces: `RemoveZoneUseCase`, `RemoveZoneRequest(zoneId:)`, `RemoveZoneResponse` with `.removed` and `.unknownZone`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/RemoveZoneTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct RemoveZoneTests {
    private let models = InMemoryThreatModelGateway(
        ThreatModel(
            components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 100, y: 100),
                    sensitivity: .internalData
                )
            ],
            zones: [
                Zone(id: ZoneId("z1"), rect: Rect(x: 0, y: 0, width: 400, height: 300)),
                Zone(id: ZoneId("z2"), rect: Rect(x: 500, y: 0, width: 400, height: 300))
            ]
        )
    )

    private func remove(_ id: String) -> RemoveZoneResponse {
        RemoveZone(models: models).execute(RemoveZoneRequest(zoneId: id))
    }

    @Test func removesTheNamedZoneAndLeavesTheOther() {
        #expect(remove("z1") == .removed)

        #expect(models.current().zones.map(\.id.value) == ["z2"])
    }

    @Test func leavesEveryComponentTheZoneHeld() {
        _ = remove("z1")

        #expect(models.current().components.map(\.id.value) == ["c1"])
        #expect(models.current().components.first?.position == Point(x: 100, y: 100))
    }

    @Test func refusesAZoneTheModelDoesNotHold() {
        #expect(remove("z9") == .unknownZone)
        #expect(models.current().zones.count == 2)
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter RemoveZoneTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'RemoveZone' in scope`.

- [ ] **Step 3: Write the use case**

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/RemoveZone.swift`:

```swift
public protocol RemoveZoneUseCase {
    func execute(_ request: RemoveZoneRequest) -> RemoveZoneResponse
}

public struct RemoveZoneRequest: Equatable, Sendable {
    public let zoneId: String

    public init(zoneId: String) {
        self.zoneId = zoneId
    }
}

public enum RemoveZoneResponse: Equatable, Sendable {
    case removed
    case unknownZone
}

/// Removes one zone.
///
/// Every component the zone held stays on the model, where it was. A zone
/// holds nothing: membership is derived from the geometry, so removing the
/// zone simply leaves those components in no zone.
public struct RemoveZone: RemoveZoneUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RemoveZoneRequest) -> RemoveZoneResponse {
        let id = ZoneId(request.zoneId)

        var model = models.current()
        guard model.zones.contains(where: { $0.id == id }) else {
            return .unknownZone
        }

        model.zones.removeAll { $0.id == id }
        models.save(model)

        return .removed
    }
}
```

- [ ] **Step 4: Vend it from both composition roots**

Add to `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`:

```swift
    func removeZone() -> RemoveZoneUseCase
```

Add to `TestDependencies` and to `Dependencies`, each with its own access level:

```swift
    func removeZone() -> RemoveZoneUseCase {
        RemoveZone(models: models)
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
git commit -m "feat: add RemoveZone

Every component the zone held stays where it was. Membership is derived, so
removing the zone leaves those components in no zone."
```

---

### Task 7: Zones in `ViewThreatModel`

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/ViewThreatModel.swift`
- Modify: `ThreatModelKit/Tests/UnitTests/ViewThreatModelTests.swift`

**Interfaces:**
- Consumes: `ZoneContainment`, `Component.centre`, `Zone.displayName`.
- Produces: `ViewedZone(id:name:customName:networkZoneId:networkTypeId:riskReductionEnabled:riskReductionPercent:x:y:width:height:)`; `ViewedComponent.zoneId: String?` as the last initialiser argument; `ViewThreatModelResponse(name:components:connections:zones:)`.

- [ ] **Step 1: Write the failing test**

Add to `ThreatModelKit/Tests/UnitTests/ViewThreatModelTests.swift`, inside the struct:

```swift
    private func zone(
        _ id: String,
        x: Double = 0,
        y: Double = 0,
        name: String? = nil,
        networkZone: NetworkZone = .privateZone
    ) -> Zone {
        Zone(
            id: ZoneId(id),
            rect: Rect(x: x, y: y, width: 400, height: 300),
            name: name,
            networkZone: networkZone,
            networkType: .vpc,
            riskReductionEnabled: true,
            riskReductionPercent: 35
        )
    }

    @Test func describesAZoneForDrawing() throws {
        let response = view(ThreatModel(zones: [zone("z1", x: 20, y: 30, name: "Payments")]))

        let drawn = try #require(response.zones.first)
        #expect(drawn.id == "z1")
        #expect(drawn.name == "Payments")
        #expect(drawn.customName == "Payments")
        #expect(drawn.networkZoneId == "private")
        #expect(drawn.networkTypeId == "vpc")
        #expect(drawn.riskReductionEnabled)
        #expect(drawn.riskReductionPercent == 35)
        #expect(drawn.x == 20)
        #expect(drawn.y == 30)
        #expect(drawn.width == 400)
        #expect(drawn.height == 300)
    }

    @Test func showsTheFallbackNameForAZoneWithoutOne() throws {
        let response = view(ThreatModel(zones: [zone("z1")]))

        let drawn = try #require(response.zones.first)
        #expect(drawn.name == "VPC")
        #expect(drawn.customName == nil)
    }

    @Test func listsZonesInDrawingOrder() {
        let response = view(ThreatModel(zones: [zone("z1"), zone("z2", x: 500)]))

        #expect(response.zones.map(\.id) == ["z1", "z2"])
    }

    @Test func tellsTheCanvasWhichZoneHoldsAComponent() throws {
        // The component sits at 100,100 and its centre is 80 by 36 further on,
        // so it is inside the zone rectangle below the 40 point header.
        let response = view(
            ThreatModel(components: [component("c1", x: 100, y: 100)], zones: [zone("z1")])
        )

        #expect(try #require(response.components.first).zoneId == "z1")
    }

    @Test func reportsNoZoneForAComponentOutsideEveryZone() throws {
        let response = view(
            ThreatModel(components: [component("c1", x: 900, y: 900)], zones: [zone("z1")])
        )

        #expect(try #require(response.components.first).zoneId == nil)
    }

    @Test func givesAComponentTheLaterOfTwoOverlappingZones() throws {
        let response = view(
            ThreatModel(
                components: [component("c1", x: 100, y: 100)],
                zones: [zone("z1"), zone("z2")]
            )
        )

        #expect(try #require(response.components.first).zoneId == "z2")
    }
```

Every existing `#expect` in that file keeps working; `ViewedComponent` only gains a field.

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter ViewThreatModelTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `value of type 'ViewThreatModelResponse' has no member 'zones'`.

- [ ] **Step 3: Add `ViewedZone` and the component's zone**

In `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/ViewThreatModel.swift`, add the field to `ViewedComponent` after `isUnknownTechnology`, add the matching initialiser parameter in the same position, and assign it:

```swift
    /// The zone whose rectangle holds this component's centre, or nil.
    /// Derived from the geometry every time; nothing stores it.
    public let zoneId: String?
```

Add the new response type above `ViewThreatModelResponse`:

```swift
public struct ViewedZone: Equatable, Sendable {
    public let id: String
    /// What the canvas shows in the zone header: the user's own name, else the
    /// network type, else the zone kind.
    public let name: String
    /// The user's own name, or nil when they have not set one. The panel edits
    /// this, not `name`.
    public let customName: String?
    public let networkZoneId: String
    public let networkTypeId: String
    public let riskReductionEnabled: Bool
    public let riskReductionPercent: Int
    public let x: Double
    public let y: Double
    public let width: Double
    public let height: Double

    public init(
        id: String,
        name: String,
        customName: String?,
        networkZoneId: String,
        networkTypeId: String,
        riskReductionEnabled: Bool,
        riskReductionPercent: Int,
        x: Double,
        y: Double,
        width: Double,
        height: Double
    ) {
        self.id = id
        self.name = name
        self.customName = customName
        self.networkZoneId = networkZoneId
        self.networkTypeId = networkTypeId
        self.riskReductionEnabled = riskReductionEnabled
        self.riskReductionPercent = riskReductionPercent
        self.x = x
        self.y = y
        self.width = width
        self.height = height
    }
}
```

Add `zones` to `ViewThreatModelResponse` as the last stored property and the last initialiser parameter.

Replace the body of `execute`:

```swift
    public func execute(_ request: ViewThreatModelRequest) -> ViewThreatModelResponse {
        let model = models.current()

        return ViewThreatModelResponse(
            name: model.name,
            components: model.components.map { component in
                let technology = catalogue.findById(component.technologyId)
                return ViewedComponent(
                    id: component.id.value,
                    technologyId: component.technologyId.value,
                    name: component.customName ?? technology?.name ?? component.technologyId.value,
                    providerId: technology?.provider.value ?? "",
                    categoryId: technology?.category.value ?? "",
                    x: component.position.x,
                    y: component.position.y,
                    sensitivityId: component.sensitivity.rawValue,
                    threatsDisabled: component.threatsDisabled,
                    isUnknownTechnology: technology == nil,
                    zoneId: ZoneContainment.zone(holding: component.centre, in: model.zones)?.id.value
                )
            },
            connections: model.connections.map {
                ViewedConnection(
                    id: $0.id.value,
                    sourceComponentId: $0.source.value,
                    targetComponentId: $0.target.value
                )
            },
            zones: model.zones.map {
                ViewedZone(
                    id: $0.id.value,
                    name: $0.displayName,
                    customName: $0.name,
                    networkZoneId: $0.networkZone.rawValue,
                    networkTypeId: $0.networkType.rawValue,
                    riskReductionEnabled: $0.riskReductionEnabled,
                    riskReductionPercent: $0.riskReductionPercent,
                    x: $0.rect.origin.x,
                    y: $0.rect.origin.y,
                    width: $0.rect.size.width,
                    height: $0.rect.size.height
                )
            }
        )
    }
```

- [ ] **Step 4: Fix the two call sites that build an empty response**

`ThreatModelSession` builds a starting value. Change it to include zones:

```swift
    private(set) var canvas = ViewThreatModelResponse(
        name: "Untitled",
        components: [],
        connections: [],
        zones: []
    )
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
cd /Users/craigjbass/Projects/threat-modeller && xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' build 2>&1 | grep -E 'error:|BUILD' | head -5
```

Expected: PASS, and the app builds.

- [ ] **Step 6: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit threatmodeller
git commit -m "feat: show zones and each component's zone on the canvas snapshot

The canvas gets the zone rectangles to draw and the zone each component falls
in, so the containment rule is visible instead of only affecting scores."
```

---

### Task 8: `zoneThreats()` on the catalogue port

Extends the port, the fake, the fixture, the shared contract and the real gateway together, exactly as `connectionThreats()` was extended in Milestone 2.

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/catalogue/gateway/TechnologyCatalogue.swift`
- Modify: `ThreatModelKit/Sources/TestSupport/InMemoryTechnologyCatalogue.swift`
- Modify: `ThreatModelKit/Sources/TestSupport/CatalogueFixture.swift`
- Modify: `ThreatModelKit/Sources/TestSupport/TechnologyCatalogueContract.swift`
- Modify: `ThreatModelKit/Sources/CatalogueGateways/BundledTechnologyCatalogue.swift`
- Modify: `ThreatModelKit/Tests/GatewayIntegrationTests/BundledTechnologyCatalogueTests.swift`

**Interfaces:**
- Consumes: `Threat.isZoneThreat`, `Threat.zoneContext`.
- Produces: `TechnologyCatalogue.zoneThreats() -> [Threat]`; `CatalogueFixture.zoneThreats()` returning `lateral-movement` (high). `CatalogueFixture.ec2Threats()`'s `misconfiguration` also becomes a zone threat.

WARNING: unlike a connection threat, a zone threat may also be a technology's own threat. `misconfiguration` is both in the vendored data. The contract must not require the two sets to be disjoint.

- [ ] **Step 1: Write the failing test**

Add to the end of `verifyTechnologyCatalogueContract` in `ThreatModelKit/Sources/TestSupport/TechnologyCatalogueContract.swift`:

```swift
    let zoneThreats = subject.zoneThreats()
    #expect(zoneThreats.isEmpty == false)
    #expect(zoneThreats.allSatisfy { $0.isZoneThreat })
    #expect(Set(zoneThreats.map(\.id)).count == zoneThreats.count)
    for threat in zoneThreats {
        #expect(taxonomy.severity(id: threat.severity.id) == threat.severity)
        #expect(threat.controls.isEmpty == false)
        // A zone threat carries its own wording, because the same threat read
        // against a whole network zone says something different from the same
        // threat read against one service.
        #expect(threat.zoneContext?.isEmpty == false)
    }

    // A zone threat MAY also be a technology's own threat. `misconfiguration`
    // is both. The two sets are deliberately not disjoint, unlike connection
    // threats, which belong to the link alone.
    #expect(zoneThreats.allSatisfy { $0.isConnectionThreat == false })
```

Add to `ThreatModelKit/Tests/GatewayIntegrationTests/BundledTechnologyCatalogueTests.swift`:

```swift
    @Test func listsTheZoneThreatsTheVendoredDataFlags() throws {
        let catalogue = try BundledTechnologyCatalogue()

        #expect(catalogue.zoneThreats().map(\.id.value) == [
            "unauthorized-access",
            "misconfiguration",
            "data-exfiltration",
            "audit-logging-bypass",
            "network-misconfiguration",
            "lateral-movement"
        ])
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter TechnologyCatalogueContractTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `value of type 'any TechnologyCatalogue' has no member 'zoneThreats'`.

- [ ] **Step 3: Add the method to the port**

In `TechnologyCatalogue.swift`, add after `connectionThreats()` and shorten the doc comment:

```swift
/// Reads the technology and threat catalogue.
///
/// A later milestone extends this port with `pathwayMitigations()`. Do not add
/// it before the milestone that needs it.
public protocol TechnologyCatalogue {
    func all() -> [Technology]
    func findById(_ id: TechnologyId) -> Technology?
    /// The technology's threats, in the order the technology declares them.
    /// Empty for an unknown technology.
    func threatsFor(technologyId: TechnologyId) -> [Threat]
    /// Every threat the catalogue flags as belonging to a link between two
    /// components, in catalogue order. These threats belong to no technology.
    func connectionThreats() -> [Threat]
    /// Every threat the catalogue flags as belonging to a network zone, in
    /// catalogue order. A zone threat may also be a technology's own threat.
    func zoneThreats() -> [Threat]
    func taxonomy() -> Taxonomy
    func providers() -> [Provider]
}
```

- [ ] **Step 4: Implement it on the fake**

In `InMemoryTechnologyCatalogue.swift`, beside `connectionThreats()`:

```swift
    public func zoneThreats() -> [Threat] {
        orderedThreats.filter(\.isZoneThreat)
    }
```

- [ ] **Step 5: Give the fixture its zone threats**

In `CatalogueFixture.swift`, change the `misconfiguration` entry inside `ec2Threats()` so it is a zone threat as well, matching the vendored data:

```swift
            Threat(
                id: ThreatId("misconfiguration"),
                name: "Misconfiguration",
                description: "Insecure defaults or drift leave the service exposed",
                severity: medium,
                stride: [StrideId("tampering")],
                controls: [Control(id: "ctrl-misc-1", description: "Scan configuration continuously")],
                isZoneThreat: true,
                zoneContext: "Insecure zone-level configuration such as permissive defaults"
            ),
```

Add a zone-only threat after `connectionThreats()`:

```swift
    /// One zone-only threat. `misconfiguration` in `ec2Threats()` is a zone
    /// threat too, so a test can tell a threat raised by a component from the
    /// same threat raised by a zone.
    public static func zoneThreats() -> [Threat] {
        [
            Threat(
                id: ThreatId("lateral-movement"),
                name: "Lateral Movement",
                description: "Attacker pivots between resources inside the network zone",
                severity: high,
                stride: [StrideId("elevation-of-privilege")],
                controls: [Control(id: "ctrl-zone-1", description: "Segment the network and restrict east-west traffic")],
                isZoneThreat: true,
                zoneContext: "Pivoting between resources inside the network zone"
            )
        ]
    }
```

Change the `catalogue()` factory so the zone threats reach the fake:

```swift
    public static func catalogue() -> InMemoryTechnologyCatalogue {
        InMemoryTechnologyCatalogue(
            technologies: [ec2(), rds(), bigQuery()],
            threats: ec2Threats() + connectionThreats() + zoneThreats(),
            taxonomy: taxonomy(),
            providers: providers()
        )
    }
```

- [ ] **Step 6: Implement it on the real gateway**

In `BundledTechnologyCatalogue.swift`, add a stored property beside `connectionThreatsValue`:

```swift
    private let zoneThreatsValue: [Threat]
```

In the decoding loop, add the collection beside the connection one:

```swift
        var connectionThreatList: [Threat] = []
        var zoneThreatList: [Threat] = []
```

```swift
            threats[threat.id] = threat
            if threat.isConnectionThreat {
                connectionThreatList.append(threat)
            }
            if threat.isZoneThreat {
                zoneThreatList.append(threat)
            }
        }
        threatsById = threats
        connectionThreatsValue = connectionThreatList
        zoneThreatsValue = zoneThreatList
```

And the method, beside `connectionThreats()`:

```swift
    public func zoneThreats() -> [Threat] { zoneThreatsValue }
```

- [ ] **Step 7: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

Expected: PASS. Both the fake and the bundled gateway honour the extended contract.

WARNING: making `misconfiguration` a zone threat in the fixture does not change any Milestone 2 expectation, because nothing raises zone threats until Task 11.

- [ ] **Step 8: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit
git commit -m "feat: read zone threats from the catalogue

The port, the fake, the shared contract and the bundled gateway gain
zoneThreats() together. Unlike a connection threat, a zone threat may also be
a technology's own threat, so the contract does not require the two sets to
be disjoint."
```

---

### Task 9: The zone source and the multiplier on component threats

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/AssessThreatModel.swift`
- Modify: `ThreatModelKit/Tests/UnitTests/AssessThreatModelTests.swift`

**Interfaces:**
- Consumes: `ZoneContainment`, `ZoneMultiplier`, `Component.centre`.
- Produces: `AssessedThreatSource.zone(id:name:)`, whose `id` is `"zone:<id>"` and whose `displayName` is the zone's own display name.

- [ ] **Step 1: Write the failing test**

Add to `ThreatModelKit/Tests/UnitTests/AssessThreatModelTests.swift`, inside the struct. A helper first:

```swift
    /// A zone that captures a component left at the origin. Its top edge sits
    /// above the origin, because containment ignores the top 40 points and a
    /// component at 0,0 has its centre at 80,36.
    private func privateZone(
        _ id: String = "z1",
        x: Double = -100,
        y: Double = -100,
        reduction: Int = 20,
        enabled: Bool = true,
        kind: NetworkZone = .privateZone
    ) -> Zone {
        Zone(
            id: ZoneId(id),
            rect: Rect(x: x, y: y, width: 800, height: 700),
            networkZone: kind,
            riskReductionEnabled: enabled,
            riskReductionPercent: reduction
        )
    }
```

Then the cases:

```swift
    @Test func reducesAComponentThreatInsideAPrivateZone() throws {
        // Credential theft is critical (4) against confidential data (3), so 12
        // before the zone. A 20 per cent reduction leaves 9.6, which rounds to
        // 10 and drops the level from critical to high.
        let response = assess(
            ThreatModel(components: [ec2(id: "c1")], zones: [privateZone()])
        )

        let theft = try #require(response.threats.first { $0.threatId == "credential-theft" })
        #expect(theft.riskScore == 10)
        #expect(theft.riskLevel == "high")
    }

    @Test func leavesAComponentThreatAloneOutsideEveryZone() throws {
        let response = assess(
            ThreatModel(components: [ec2(id: "c1", position: Point(x: 2000, y: 2000))],
                        zones: [privateZone()])
        )

        #expect(try #require(response.threats.first { $0.threatId == "credential-theft" }).riskScore == 12)
    }

    @Test func leavesAComponentThreatAloneInAPublicZone() throws {
        let response = assess(
            ThreatModel(components: [ec2(id: "c1")], zones: [privateZone(kind: .publicZone)])
        )

        #expect(try #require(response.threats.first { $0.threatId == "credential-theft" }).riskScore == 12)
    }

    @Test func leavesAComponentThreatAloneWhenReductionIsOff() throws {
        let response = assess(
            ThreatModel(components: [ec2(id: "c1")], zones: [privateZone(reduction: 90, enabled: false)])
        )

        #expect(try #require(response.threats.first { $0.threatId == "credential-theft" }).riskScore == 12)
    }

    @Test func dropsAComponentThreatTheZoneReducesToNothing() {
        // Denial of service is low (1) against confidential data (3), so 3.
        // A 90 per cent reduction leaves 0.3, which rounds to 0 and is filtered.
        let response = assess(
            ThreatModel(components: [ec2(id: "c1")], zones: [privateZone(reduction: 90)])
        )

        #expect(response.threats.contains { $0.threatId == "dos-attack" } == false)
    }

    @Test func usesTheLaterOfTwoOverlappingZones() throws {
        let response = assess(
            ThreatModel(
                components: [ec2(id: "c1")],
                zones: [privateZone("z1", reduction: 0), privateZone("z2", reduction: 50)]
            )
        )

        #expect(try #require(response.threats.first { $0.threatId == "credential-theft" }).riskScore == 6)
    }
```

`ec2(...)` needs a position argument. Change the existing helper so it takes one, defaulting to the origin:

```swift
    private func ec2(
        id: String = "c1",
        sensitivity: DataSensitivity = .confidential,
        customName: String? = nil,
        threatsDisabled: Bool = false,
        position: Point = Point(x: 0, y: 0)
    ) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-ec2"),
            position: position,
            sensitivity: sensitivity,
            customName: customName,
            threatsDisabled: threatsDisabled
        )
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter AssessThreatModelTests 2>&1 | grep -E 'error:|✘' | head -5
```

Expected: FAIL — the reduced scores come back unreduced.

- [ ] **Step 3: Add the zone case to the source enum**

In `AssessThreatModel.swift`, add the case and extend both computed properties:

```swift
public enum AssessedThreatSource: Hashable, Sendable {
    case component(id: String, name: String, providerId: String)
    case connection(id: String, sourceName: String, targetName: String)
    case zone(id: String, name: String)

    /// The label the user reads on the threat row.
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
    /// share one. Used to order rows and to raise a duplicate pair once.
    public var id: String {
        switch self {
        case .component(let id, _, _):
            "component:\(id)"
        case .connection(let id, _, _):
            "connection:\(id)"
        case .zone(let id, _):
            "zone:\(id)"
        }
    }
}
```

- [ ] **Step 4: Apply the multiplier to component threats**

In `execute`, above the component loop, work out each component's zone once:

```swift
        // Derived, never stored. Spec section 5.2.
        var zonesByComponent: [ComponentId: Zone] = [:]
        for component in model.components {
            zonesByComponent[component.id] = ZoneContainment.zone(
                holding: component.centre,
                in: model.zones
            )
        }
```

Inside the component loop, replace the scoring lines. Where the loop reads:

```swift
            for threat in catalogue.threatsFor(technologyId: component.technologyId) {
                let score = RiskScore(severity: threat.severity, sensitivity: component.sensitivity)
                guard score.value > 0 else { continue }
```

write:

```swift
            let multiplier = ZoneMultiplier.value(for: zonesByComponent[component.id])

            for threat in catalogue.threatsFor(technologyId: component.technologyId) {
                let base = RiskScore(severity: threat.severity, sensitivity: component.sensitivity)
                let score = RiskScore(value: ZoneMultiplier.apply(multiplier, to: base.value))
                guard score.value > 0 else { continue }
```

The `riskScore: score.value` and `riskLevel: score.level.rawValue` arguments below need no change: `score` is now the multiplied score, and the level follows it.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit
git commit -m "feat: reduce a component's threats inside a private zone

The score is multiplied and rounded, and the level follows the multiplied
score. A threat the zone reduces to nothing is filtered out. The source enum
gains its zone case ahead of the zone threats themselves."
```

---

### Task 10: The multiplier on connection threats

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/AssessThreatModel.swift`
- Modify: `ThreatModelKit/Tests/UnitTests/AssessThreatModelTests.swift`

**Interfaces:**
- Consumes: `ZoneMultiplier.valueForConnection(sourceZone:targetZone:)`.
- Produces: nothing new.

- [ ] **Step 1: Write the failing test**

Add to `AssessThreatModelTests`:

```swift
    @Test func reducesALinkOnlyWhenBothEndsAreInPrivateZones() throws {
        // Man-in-the-middle is medium (2) against internal data (2), so 4.
        let bothInside = assess(
            ThreatModel(
                components: [
                    ec2(id: "c1", sensitivity: .internalData, position: Point(x: 0, y: 100)),
                    rds(sensitivity: .internalData)
                ],
                connections: [link("k1", "c1", "c2")],
                zones: [privateZone(reduction: 50)]
            )
        )
        #expect(try #require(bothInside.threats.first { $0.threatId == "connection-mitm" }).riskScore == 2)

        let oneOutside = assess(
            ThreatModel(
                components: [
                    ec2(id: "c1", sensitivity: .internalData, position: Point(x: 0, y: 100)),
                    rds(sensitivity: .internalData, position: Point(x: 3000, y: 3000))
                ],
                connections: [link("k1", "c1", "c2")],
                zones: [privateZone(reduction: 50)]
            )
        )
        #expect(try #require(oneOutside.threats.first { $0.threatId == "connection-mitm" }).riskScore == 4)
    }

    @Test func givesALinkTheLowerOfTheTwoZoneReductions() throws {
        let response = assess(
            ThreatModel(
                components: [
                    ec2(id: "c1", sensitivity: .internalData, position: Point(x: 0, y: 100)),
                    rds(sensitivity: .internalData, position: Point(x: 1000, y: 100))
                ],
                connections: [link("k1", "c1", "c2")],
                zones: [
                    privateZone("z1", x: 0, y: 0, reduction: 25),
                    privateZone("z2", x: 900, y: 0, reduction: 75)
                ]
            )
        )

        // 25 per cent is the lower reduction, so 4 becomes 3.
        #expect(try #require(response.threats.first { $0.threatId == "connection-mitm" }).riskScore == 3)
    }

    @Test func givesALinkNoReductionWhenOneEndsZoneHasReductionOff() throws {
        let response = assess(
            ThreatModel(
                components: [
                    ec2(id: "c1", sensitivity: .internalData, position: Point(x: 0, y: 100)),
                    rds(sensitivity: .internalData, position: Point(x: 1000, y: 100))
                ],
                connections: [link("k1", "c1", "c2")],
                zones: [
                    privateZone("z1", x: 0, y: 0, reduction: 90, enabled: false),
                    privateZone("z2", x: 900, y: 0, reduction: 75)
                ]
            )
        )

        #expect(try #require(response.threats.first { $0.threatId == "connection-mitm" }).riskScore == 4)
    }
```

`rds(...)` needs a position argument too. Change its helper the same way as `ec2`, defaulting to `Point(x: 0, y: 0)`.

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter AssessThreatModelTests 2>&1 | grep -E '✘' | head -5
```

Expected: FAIL — every link score comes back unreduced.

- [ ] **Step 3: Apply the multiplier to connection threats**

In the connection loop, add the multiplier beside the sensitivity, then use it. Where the loop reads:

```swift
            let sensitivity = SensitivityLadder.higher(source.sensitivity, target.sensitivity)

            for threat in catalogue.connectionThreats() {
                let score = RiskScore(severity: threat.severity, sensitivity: sensitivity)
                guard score.value > 0 else { continue }
```

write:

```swift
            let sensitivity = SensitivityLadder.higher(source.sensitivity, target.sensitivity)
            let multiplier = ZoneMultiplier.valueForConnection(
                sourceZone: zonesByComponent[source.id],
                targetZone: zonesByComponent[target.id]
            )

            for threat in catalogue.connectionThreats() {
                let base = RiskScore(severity: threat.severity, sensitivity: sensitivity)
                let score = RiskScore(value: ZoneMultiplier.apply(multiplier, to: base.value))
                guard score.value > 0 else { continue }
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
git commit -m "feat: reduce a link only when both ends sit in private zones

The link takes the lower of the two reductions. An end whose zone has
reduction off gives the link no reduction at all."
```

---

### Task 11: Zone threats

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/AssessThreatModel.swift`
- Modify: `ThreatModelKit/Tests/UnitTests/AssessThreatModelTests.swift`

**Interfaces:**
- Consumes: `TechnologyCatalogue.zoneThreats()`, `Zone.displayName`, `Threat.zoneContext`.
- Produces: nothing new.

- [ ] **Step 1: Write the failing test**

Add to `AssessThreatModelTests`:

```swift
    private func zoneThreats(_ response: AssessThreatModelResponse) -> [AssessedThreat] {
        response.threats.filter {
            if case .zone = $0.source { return true } else { return false }
        }
    }

    @Test func raisesEveryZoneThreatOncePerPrivateZone() {
        let response = assess(ThreatModel(zones: [privateZone("z1"), privateZone("z2", x: 2000)]))

        let raised = zoneThreats(response)
        #expect(Set(raised.map(\.threatId)) == ["misconfiguration", "lateral-movement"])
        #expect(Set(raised.map(\.source.id)) == ["zone:z1", "zone:z2"])
        #expect(raised.count == 4)
    }

    @Test func raisesNoZoneThreatsForAPublicZone() {
        let response = assess(ThreatModel(zones: [privateZone(kind: .publicZone)]))

        #expect(zoneThreats(response).isEmpty)
    }

    @Test func scoresAZoneThreatAgainstInternalDataAndTheZonesOwnReduction() throws {
        // Lateral movement is high (3) against internal data (2), so 6.
        // A 20 per cent reduction leaves 4.8, which rounds to 5.
        let response = assess(ThreatModel(zones: [privateZone(reduction: 20)]))

        let lateral = try #require(zoneThreats(response).first { $0.threatId == "lateral-movement" })
        #expect(lateral.sensitivityId == "internal")
        #expect(lateral.riskScore == 5)
        #expect(lateral.riskLevel == "medium")

        let unreduced = assess(ThreatModel(zones: [privateZone(enabled: false)]))
        #expect(try #require(zoneThreats(unreduced).first { $0.threatId == "lateral-movement" }).riskScore == 6)
    }

    @Test func showsTheZonesDisplayNameAndTheThreatsZoneWording() throws {
        let named = Zone(
            id: ZoneId("z1"),
            rect: Rect(x: 0, y: 0, width: 600, height: 500),
            name: "Payments"
        )
        let response = assess(ThreatModel(zones: [named]))

        let lateral = try #require(zoneThreats(response).first { $0.threatId == "lateral-movement" })
        #expect(lateral.source == .zone(id: "z1", name: "Payments"))
        #expect(lateral.source.displayName == "Payments")
        #expect(lateral.context == "Pivoting between resources inside the network zone")
        #expect(lateral.isTlsMitigated == false)
    }

    @Test func alwaysUsesTheThreatsOwnControlsOnAZone() throws {
        let response = assess(ThreatModel(zones: [privateZone()]))

        let misconfiguration = try #require(
            zoneThreats(response).first { $0.threatId == "misconfiguration" }
        )
        #expect(misconfiguration.controls.map(\.description) == ["Scan configuration continuously"])
        #expect(misconfiguration.controls.contains(where: \.isTechnologySpecific) == false)
    }

    @Test func tellsAComponentThreatApartFromTheSameThreatOnItsZone() {
        // EC2 declares misconfiguration and the zone raises it too. Two rows,
        // two sources, and the deduplication rule leaves both alone.
        let response = assess(
            ThreatModel(components: [ec2(id: "c1")], zones: [privateZone("z1")])
        )

        let rows = response.threats.filter { $0.threatId == "misconfiguration" }
        #expect(rows.map(\.source.id).sorted() == ["component:c1", "zone:z1"])
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter AssessThreatModelTests 2>&1 | grep -E '✘' | head -5
```

Expected: FAIL — no zone threat is raised at all.

- [ ] **Step 3: Raise the zone threats**

In `execute`, after the connection loop and before the `return`:

```swift
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
                    AssessedThreat(
                        threatId: threat.id.value,
                        name: threat.name,
                        description: threat.description,
                        severityId: threat.severity.id,
                        severityLabel: threat.severity.label,
                        stride: threat.stride.map(\.value),
                        mitreTechniques: threat.mitreTechniques.map {
                            AssessedMitreTechnique(id: $0.id, name: $0.name, tactic: $0.tactic)
                        },
                        // Spec section 5.3: a zone always uses the threat's own
                        // controls, never a technology's mitigations.
                        controls: threat.controls.map {
                            AssessedControl(description: $0.description, isTechnologySpecific: false)
                        },
                        source: .zone(id: zone.id.value, name: zone.displayName),
                        sensitivityId: DataSensitivity.internalData.rawValue,
                        riskScore: score.value,
                        riskLevel: score.level.rawValue,
                        context: threat.zoneContext,
                        isTlsMitigated: false
                    )
                )
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
git commit -m "feat: raise a private zone's own threats

One row per private zone per zone threat, scored against internal data and
reduced by that zone's own multiplier, using the threat's zone wording. A
public zone raises none. The same threat raised by a component and by a zone
is two rows with two sources."
```

---

### Task 12: The acceptance test

**Files:**
- Create: `ThreatModelKit/Tests/AcceptanceTests/GroupingComponentsIntoZonesTests.swift`

**Interfaces:**
- Consumes: `TestDependencies` and every use case it vends.
- Produces: nothing. It is the milestone's definition of done.

Fixture facts this test relies on: EC2 is `aws`/`compute` with `credential-theft` (critical), `misconfiguration` (medium, also a zone threat) and `dos-attack` (low). RDS declares `misconfiguration` only and enforces encryption. Zone threats are `misconfiguration` (medium) and `lateral-movement` (high). `Component.size` is 160 by 72, so a component at `100, 100` has its centre at `180, 136`. `SequentialIdentityGenerator` issues `id-1`, `id-2`, … in call order.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/AcceptanceTests/GroupingComponentsIntoZonesTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

/// Given components on my threat model
/// When I draw a private network zone around them
/// Then their risk falls, and the zone raises threats of its own
struct GroupingComponentsIntoZonesTests {
    private let app = TestDependencies()

    private func add(_ technologyId: String, x: Double, y: Double, sensitivity: String) -> String {
        let response = app.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: x, y: y, sensitivity: sensitivity)
        )
        guard case .added(let componentId) = response else {
            Issue.record("Expected the component to be added, got \(response)")
            return ""
        }
        return componentId
    }

    private func addZone(x: Double, y: Double, width: Double, height: Double) -> String {
        let response = app.addZone().execute(
            AddZoneRequest(x: x, y: y, width: width, height: height)
        )
        guard case .added(let zoneId) = response else {
            Issue.record("Expected the zone to be added, got \(response)")
            return ""
        }
        return zoneId
    }

    private func assess() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    private func score(_ threatId: String, from sourceId: String) -> Int? {
        assess().first { $0.threatId == threatId && $0.source.id == sourceId }?.riskScore
    }

    private func zoneThreats() -> [AssessedThreat] {
        assess().filter {
            if case .zone = $0.source { return true } else { return false }
        }
    }

    @Test func lowersTheRiskOfAComponentTheZoneCaptures() throws {
        let web = add("aws-ec2", x: 100, y: 100, sensitivity: "confidential")
        #expect(score("credential-theft", from: "component:\(web)") == 12)

        _ = addZone(x: 0, y: 0, width: 600, height: 500)

        // 12 reduced by the default 20 per cent is 9.6, which rounds to 10.
        #expect(score("credential-theft", from: "component:\(web)") == 10)
        let theft = try #require(assess().first { $0.threatId == "credential-theft" })
        #expect(theft.riskLevel == "high")
    }

    @Test func raisesTheZonesOwnThreatsForAPrivateZone() throws {
        let zone = addZone(x: 0, y: 0, width: 600, height: 500)

        let raised = zoneThreats()
        #expect(raised.map(\.threatId).sorted() == ["lateral-movement", "misconfiguration"])
        #expect(raised.allSatisfy { $0.source.id == "zone:\(zone)" })
        #expect(raised.allSatisfy { $0.source.displayName == "Private Zone" })
        #expect(raised.allSatisfy { $0.sensitivityId == "internal" })

        let lateral = try #require(raised.first { $0.threatId == "lateral-movement" })
        #expect(lateral.riskScore == 5)
        #expect(lateral.context == "Pivoting between resources inside the network zone")
    }

    @Test func leavesEverythingAloneForAPublicZone() throws {
        let web = add("aws-ec2", x: 100, y: 100, sensitivity: "confidential")
        let zone = addZone(x: 0, y: 0, width: 600, height: 500)

        #expect(app.setZoneProperties().execute(
            SetZonePropertiesRequest(
                zoneId: zone,
                name: "Internet",
                networkZone: "public",
                networkType: "generic",
                riskReductionEnabled: true,
                riskReductionPercent: 20
            )
        ) == .updated)

        #expect(score("credential-theft", from: "component:\(web)") == 12)
        #expect(zoneThreats().isEmpty)
    }

    @Test func lowersALinkOnlyWhenBothEndsAreInPrivateZones() throws {
        let web = add("aws-ec2", x: 100, y: 100, sensitivity: "internal")
        let database = add("aws-rds", x: 1100, y: 100, sensitivity: "internal")
        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: web, targetComponentId: database)
        )
        let link = try #require(
            app.viewThreatModel().execute(ViewThreatModelRequest()).connections.first
        ).id

        // Man-in-the-middle is medium (2) against internal data (2), so 4.
        #expect(score("connection-mitm", from: "connection:\(link)") == 4)

        // One end inside a private zone changes nothing.
        let left = addZone(x: 0, y: 0, width: 600, height: 500)
        #expect(score("connection-mitm", from: "connection:\(link)") == 4)

        // Both ends inside private zones takes the lower of the two reductions.
        let right = addZone(x: 1000, y: 0, width: 600, height: 500)
        _ = app.setZoneProperties().execute(
            SetZonePropertiesRequest(
                zoneId: left, name: nil, networkZone: "private", networkType: "vpc",
                riskReductionEnabled: true, riskReductionPercent: 25
            )
        )
        _ = app.setZoneProperties().execute(
            SetZonePropertiesRequest(
                zoneId: right, name: nil, networkZone: "private", networkType: "subnet",
                riskReductionEnabled: true, riskReductionPercent: 75
            )
        )

        // 25 per cent is the lower reduction, so 4 becomes 3.
        #expect(score("connection-mitm", from: "connection:\(link)") == 3)
    }

    @Test func restoresTheRiskWhenAComponentMovesOutOfTheZone() throws {
        let web = add("aws-ec2", x: 100, y: 100, sensitivity: "confidential")
        _ = addZone(x: 0, y: 0, width: 600, height: 500)
        #expect(score("credential-theft", from: "component:\(web)") == 10)

        #expect(app.moveComponents().execute(
            MoveComponentsRequest(moves: [ComponentMove(componentId: web, x: 2000, y: 2000)])
        ) == .moved(count: 1))

        #expect(score("credential-theft", from: "component:\(web)") == 12)
        #expect(app.viewThreatModel().execute(ViewThreatModelRequest())
                    .components.first?.zoneId == nil)
    }

    @Test func restoresTheRiskWhenTheZoneMovesOffTheComponent() throws {
        let web = add("aws-ec2", x: 100, y: 100, sensitivity: "confidential")
        let zone = addZone(x: 0, y: 0, width: 600, height: 500)
        #expect(score("credential-theft", from: "component:\(web)") == 10)

        #expect(app.resizeZone().execute(
            ResizeZoneRequest(zoneId: zone, x: 3000, y: 3000, width: 600, height: 500)
        ) == .resized)

        #expect(score("credential-theft", from: "component:\(web)") == 12)
    }

    @Test func leavesTheComponentsBehindWhenTheZoneIsRemoved() throws {
        let web = add("aws-ec2", x: 100, y: 100, sensitivity: "confidential")
        let zone = addZone(x: 0, y: 0, width: 600, height: 500)

        #expect(app.removeZone().execute(RemoveZoneRequest(zoneId: zone)) == .removed)

        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(canvas.zones.isEmpty)
        #expect(canvas.components.map(\.id) == [web])
        #expect(canvas.components.first?.zoneId == nil)
        #expect(score("credential-theft", from: "component:\(web)") == 12)
        #expect(zoneThreats().isEmpty)
    }

    @Test func showsTheZoneOnTheCanvasAsItIsDrawn() throws {
        let web = add("aws-ec2", x: 100, y: 100, sensitivity: "confidential")
        let zone = addZone(x: 0, y: 0, width: 600, height: 500)

        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())
        let drawn = try #require(canvas.zones.first)
        #expect(drawn.id == zone)
        #expect(drawn.name == "Private Zone")
        #expect(drawn.x == 0)
        #expect(drawn.width == 600)
        #expect(canvas.components.first { $0.id == web }?.zoneId == zone)
    }
}
```

- [ ] **Step 2: Run it to verify it passes**

Tasks 1–11 exist to make this test pass, so it should be green the first time.

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter GroupingComponentsIntoZonesTests 2>&1 | tail -5
```

Expected: PASS. If a case fails, the fault is in Tasks 1–11, not in this test.

- [ ] **Step 3: Run the whole package suite and time it**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && time swift test 2>&1 | tail -5
```

Expected: PASS, under 30 seconds. Spec §10 sets that target.

- [ ] **Step 4: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit/Tests/AcceptanceTests/GroupingComponentsIntoZonesTests.swift
git commit -m "test: accept the milestone 3 core at the use case boundary

Drawing a private zone lowers the risk of what it captures and raises the
zone's own threats. A public zone does neither. A link is lowered only when
both ends are inside private zones, by the lower of the two reductions.
Moving either the component or the zone restores the risk."
```

---

### Task 13: Split `CanvasView`

Closes `MILESTONE-3-CARRY-FORWARD.md` item 9, which says to split this file **before** zones land. `CanvasView.swift` holds the layout, every gesture and the hit test in 255 lines; zones would add a layer, three more gestures and two more hit tests to the same file.

The split also turns the hit test into a pure function with its own tests, which no test reached before.

**Files:**
- Create: `threatmodeller/canvas/CanvasHitTest.swift`
- Create: `threatmodeller/canvas/CanvasGestures.swift`
- Modify: `threatmodeller/canvas/CanvasView.swift`
- Modify: `threatmodeller/canvas/CanvasState.swift`
- Test: `threatmodellerTests/canvas/CanvasHitTestTests.swift`

**Interfaces:**
- Consumes: `ComponentBox`, `AnchorGeometry`, `ConnectionPath`, `MarqueeSelection`, `ViewedComponent`, `ViewedConnection`.
- Produces:
  - `CanvasHitTest.boxes(for:selected:dragTranslation:)`, `.path(for:boxes:)`, `.connection(under:connections:boxes:)`, `.component(under:components:)`
  - `CanvasGestures(session:canvas:)` with `backgroundTap`, `backgroundDrag`, `selectComponent(_:addingToSelection:)`, `nodeDragChanged(_:_:)`, `nodeDragEnded(_:)`, `anchorDragChanged(_:_:)`, `anchorDragEnded(_:_:)`, `deleteSelection()`, `zoom(by:about:)`
  - `CanvasState.lastPanTranslation: CGSize`

WARNING: this task changes one behaviour. `connection(under:)` used to return the **first** link whose curve the click touched; it now returns the **last**, so the link drawn on top is the one selected. That matches how the canvas paints and how zones will behave.

- [ ] **Step 1: Write the failing test**

Create `threatmodellerTests/canvas/CanvasHitTestTests.swift`:

```swift
import CoreGraphics
import Testing
import ThreatModelKit
@testable import threatmodeller

struct CanvasHitTestTests {
    private func component(_ id: String, x: Double, y: Double) -> ViewedComponent {
        ViewedComponent(
            id: id,
            technologyId: "aws-ec2",
            name: "EC2",
            providerId: "aws",
            categoryId: "compute",
            x: x,
            y: y,
            sensitivityId: "internal",
            threatsDisabled: false,
            isUnknownTechnology: false,
            zoneId: nil
        )
    }

    private func link(_ id: String, _ source: String, _ target: String) -> ViewedConnection {
        ViewedConnection(id: id, sourceComponentId: source, targetComponentId: target)
    }

    @Test func placesEachComponentAtItsOwnPosition() throws {
        let boxes = CanvasHitTest.boxes(
            for: [component("c1", x: 10, y: 20), component("c2", x: 300, y: 40)],
            selected: [],
            dragTranslation: .zero
        )

        #expect(boxes.count == 2)
        #expect(try #require(boxes["c1"]).origin == CGPoint(x: 10, y: 20))
        #expect(try #require(boxes["c2"]).origin == CGPoint(x: 300, y: 40))
    }

    @Test func shiftsOnlyTheSelectedComponentsByTheDragInFlight() throws {
        let boxes = CanvasHitTest.boxes(
            for: [component("c1", x: 10, y: 20), component("c2", x: 300, y: 40)],
            selected: ["c1"],
            dragTranslation: CGSize(width: 5, height: -7)
        )

        #expect(try #require(boxes["c1"]).origin == CGPoint(x: 15, y: 13))
        #expect(try #require(boxes["c2"]).origin == CGPoint(x: 300, y: 40))
    }

    @Test func findsTheComponentUnderAPoint() {
        let components = [component("c1", x: 0, y: 0), component("c2", x: 400, y: 0)]

        #expect(CanvasHitTest.component(under: CGPoint(x: 20, y: 20), components: components) == "c1")
        #expect(CanvasHitTest.component(under: CGPoint(x: 420, y: 20), components: components) == "c2")
        #expect(CanvasHitTest.component(under: CGPoint(x: 900, y: 900), components: components) == nil)
    }

    @Test func givesALaterComponentThePointWhenTwoOverlap() {
        let components = [component("c1", x: 0, y: 0), component("c2", x: 10, y: 10)]

        #expect(CanvasHitTest.component(under: CGPoint(x: 40, y: 40), components: components) == "c2")
    }

    @Test func findsTheLinkUnderAPoint() throws {
        let components = [component("c1", x: 0, y: 0), component("c2", x: 500, y: 0)]
        let boxes = CanvasHitTest.boxes(for: components, selected: [], dragTranslation: .zero)
        let connections = [link("k1", "c1", "c2")]

        let path = try #require(CanvasHitTest.path(for: connections[0], boxes: boxes))
        let onTheCurve = path.point(at: 0.5)

        #expect(CanvasHitTest.connection(under: onTheCurve, connections: connections, boxes: boxes) == "k1")
        #expect(CanvasHitTest.connection(
            under: CGPoint(x: onTheCurve.x, y: onTheCurve.y + 200),
            connections: connections,
            boxes: boxes
        ) == nil)
    }

    @Test func findsNoLinkWhenAnEndIsMissing() {
        let boxes = CanvasHitTest.boxes(
            for: [component("c1", x: 0, y: 0)],
            selected: [],
            dragTranslation: .zero
        )

        #expect(CanvasHitTest.path(for: link("k1", "c1", "c9"), boxes: boxes) == nil)
        #expect(CanvasHitTest.connection(
            under: CGPoint(x: 100, y: 40),
            connections: [link("k1", "c1", "c9")],
            boxes: boxes
        ) == nil)
    }

    @Test func givesALaterLinkThePointWhenTwoRunTogether() throws {
        let components = [component("c1", x: 0, y: 0), component("c2", x: 500, y: 0)]
        let boxes = CanvasHitTest.boxes(for: components, selected: [], dragTranslation: .zero)
        let connections = [link("k1", "c1", "c2"), link("k2", "c1", "c2")]

        let path = try #require(CanvasHitTest.path(for: connections[0], boxes: boxes))

        #expect(CanvasHitTest.connection(
            under: path.point(at: 0.5),
            connections: connections,
            boxes: boxes
        ) == "k2")
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'CanvasHitTest' in scope`.

- [ ] **Step 3: Write the hit test**

Create `threatmodeller/canvas/CanvasHitTest.swift`:

```swift
import CoreGraphics
import ThreatModelKit

/// What a point on the canvas landed on.
///
/// Nothing here reads a view or a gesture, so every rule the canvas uses to
/// decide what a click hit is tested without a window. Declared `nonisolated`:
/// the app target defaults every type to the main actor, and this one holds no
/// state at all.
nonisolated enum CanvasHitTest {
    /// Where each component sits, with a drag in flight applied to the
    /// selected ones.
    static func boxes(
        for components: [ViewedComponent],
        selected: Set<String>,
        dragTranslation: CGSize
    ) -> [String: ComponentBox] {
        var found: [String: ComponentBox] = [:]
        for component in components {
            let shift = selected.contains(component.id) ? dragTranslation : CGSize.zero
            found[component.id] = ComponentBox(
                x: component.x + shift.width,
                y: component.y + shift.height
            )
        }
        return found
    }

    /// The curve a link draws, or nil when either end is missing.
    static func path(
        for connection: ViewedConnection,
        boxes: [String: ComponentBox]
    ) -> ConnectionPath? {
        guard let source = boxes[connection.sourceComponentId],
              let target = boxes[connection.targetComponentId] else { return nil }
        let anchors = AnchorGeometry.nearestPair(from: source, to: target)
        return ConnectionPath(
            from: AnchorGeometry.point(anchors.source, of: source),
            to: AnchorGeometry.point(anchors.target, of: target)
        )
    }

    /// The link under the point, or nil. A later link wins, so the one drawn
    /// on top is the one the click selects.
    static func connection(
        under modelPoint: CGPoint,
        connections: [ViewedConnection],
        boxes: [String: ComponentBox]
    ) -> String? {
        connections.last {
            path(for: $0, boxes: boxes)?.containsClick(at: modelPoint) == true
        }?.id
    }

    /// The component under the point, or nil. A later component wins.
    static func component(under modelPoint: CGPoint, components: [ViewedComponent]) -> String? {
        components.last { ComponentBox(x: $0.x, y: $0.y).contains(modelPoint) }?.id
    }
}
```

- [ ] **Step 4: Move the pan anchor onto the canvas state**

Add to `threatmodeller/canvas/CanvasState.swift`:

```swift
    /// How much of a Command-drag has already been applied to the pan. A drag
    /// reports the translation from where it started, so the pan applies the
    /// step since the last change rather than the whole translation again.
    var lastPanTranslation: CGSize = .zero
```

- [ ] **Step 5: Write the gestures**

Create `threatmodeller/canvas/CanvasGestures.swift`, moving every gesture and commit method out of `CanvasView` unchanged apart from reading `CanvasHitTest` and `canvas.lastPanTranslation`:

```swift
import SwiftUI
import ThreatModelKit

/// Every gesture the canvas installs, and what each one commits.
///
/// Split out of `CanvasView` so that view holds layout only. This type reads
/// the session and the canvas state and calls use cases through the session.
/// It draws nothing.
@MainActor
struct CanvasGestures {
    let session: ThreatModelSession
    let canvas: CanvasState

    private var boxes: [String: ComponentBox] {
        CanvasHitTest.boxes(
            for: session.canvas.components,
            selected: canvas.selectedComponentIds,
            dragTranslation: canvas.dragTranslation ?? .zero
        )
    }

    // MARK: background

    var backgroundTap: some Gesture {
        SpatialTapGesture(coordinateSpace: .named("canvas")).onEnded { value in
            let point = canvas.transform.modelPoint(value.location)
            if let connectionId = CanvasHitTest.connection(
                under: point,
                connections: session.canvas.connections,
                boxes: boxes
            ) {
                canvas.select(connectionId: connectionId, addingToSelection: false)
            } else {
                canvas.clearSelection()
            }
        }
    }

    var backgroundDrag: some Gesture {
        // Command-drag pans; a plain drag draws the marquee.
        DragGesture(minimumDistance: 2, coordinateSpace: .named("canvas"))
            .modifiers(.command)
            .onChanged { value in
                let step = CGSize(
                    width: value.translation.width - canvas.lastPanTranslation.width,
                    height: value.translation.height - canvas.lastPanTranslation.height
                )
                canvas.lastPanTranslation = value.translation
                canvas.transform = canvas.transform.panned(by: step)
            }
            .onEnded { _ in canvas.lastPanTranslation = .zero }
            .exclusively(before: marqueeDrag)
    }

    private var marqueeDrag: some Gesture {
        DragGesture(minimumDistance: 2, coordinateSpace: .named("canvas"))
            .onChanged { value in
                canvas.marquee = (
                    start: canvas.transform.modelPoint(value.startLocation),
                    end: canvas.transform.modelPoint(value.location)
                )
            }
            .onEnded { _ in
                if let rect = canvas.marqueeRect {
                    canvas.select(componentIds: MarqueeSelection.selected(
                        in: rect,
                        from: session.canvas.components.map {
                            (id: $0.id, box: ComponentBox(x: $0.x, y: $0.y))
                        }
                    ))
                }
                canvas.marquee = nil
            }
    }

    // MARK: nodes

    func selectComponent(_ componentId: String, addingToSelection: Bool) {
        canvas.select(componentId: componentId, addingToSelection: addingToSelection)
    }

    func nodeDragChanged(_ componentId: String, _ translation: CGSize) {
        if canvas.isSelected(componentId: componentId) == false {
            canvas.select(componentId: componentId, addingToSelection: false)
        }
        canvas.dragTranslation = canvas.transform.modelDistance(translation)
    }

    func nodeDragEnded(_ translation: CGSize) {
        let shift = canvas.transform.modelDistance(translation)
        let moves = session.canvas.components
            .filter { canvas.isSelected(componentId: $0.id) }
            .map {
                ComponentMove(
                    componentId: $0.id,
                    x: $0.x + shift.width,
                    y: $0.y + shift.height
                )
            }
        canvas.dragTranslation = nil
        guard moves.isEmpty == false else { return }
        session.move(moves)
    }

    func anchorDragChanged(_ componentId: String, _ location: CGPoint) {
        canvas.connectionDrag = (
            sourceComponentId: componentId,
            currentPoint: canvas.transform.modelPoint(location)
        )
    }

    func anchorDragEnded(_ componentId: String, _ location: CGPoint) {
        canvas.connectionDrag = nil
        let point = canvas.transform.modelPoint(location)
        guard let targetId = CanvasHitTest.component(
            under: point,
            components: session.canvas.components
        ) else { return }
        session.connect(sourceComponentId: componentId, targetComponentId: targetId)
    }

    // MARK: commands

    func deleteSelection() {
        for connectionId in canvas.selectedConnectionIds {
            session.removeConnection(connectionId)
        }
        if canvas.selectedComponentIds.isEmpty == false {
            session.removeComponents(Array(canvas.selectedComponentIds))
        }
        canvas.retainOnly(
            componentIds: Set(session.canvas.components.map(\.id)),
            connectionIds: Set(session.canvas.connections.map(\.id))
        )
    }

    func zoom(by factor: CGFloat, about viewPoint: CGPoint) {
        canvas.transform = canvas.transform.zoomed(by: factor, about: viewPoint)
    }
}
```

- [ ] **Step 6: Leave `CanvasView` holding layout only**

Replace `threatmodeller/canvas/CanvasView.swift`:

```swift
import SwiftUI
import ThreatModelKit

/// The diagram. Painting order per spec section 9: background, then every
/// connection in one `Canvas` pass, then the component views.
///
/// This view holds layout. Gestures live in `CanvasGestures` and hit testing
/// in `CanvasHitTest`.
struct CanvasView: View {
    let session: ThreatModelSession
    let canvas: CanvasState

    private var gestures: CanvasGestures {
        CanvasGestures(session: session, canvas: canvas)
    }

    private var boxes: [String: ComponentBox] {
        CanvasHitTest.boxes(
            for: session.canvas.components,
            selected: canvas.selectedComponentIds,
            dragTranslation: canvas.dragTranslation ?? .zero
        )
    }

    var body: some View {
        // A GeometryReader takes the space the split view offers and never
        // reports its children's size back up. Without it the 20000 point
        // drawing layer sizes the whole window.
        GeometryReader { _ in
            ZStack(alignment: .topLeading) {
                Color(nsColor: .textBackgroundColor)
                    .contentShape(Rectangle())
                    // The identifier sits on the background, not on the whole
                    // canvas: an identifier on a container overwrites the
                    // identifier of every element inside it.
                    .accessibilityIdentifier("canvas")
                    .gesture(gestures.backgroundTap)
                    .gesture(gestures.backgroundDrag)

                content
                    .scaleEffect(canvas.transform.zoom, anchor: .topLeading)
                    .offset(x: canvas.transform.pan.width, y: canvas.transform.pan.height)

                zoomControls
            }
        }
        .coordinateSpace(.named("canvas"))
        .clipped()
        .focusable()
        .focusEffectDisabled()
        .onKeyPress(.escape) {
            canvas.cancel() ? .handled : .ignored
        }
        .onKeyPress(.delete) {
            gestures.deleteSelection()
            return .handled
        }
        .gesture(
            MagnifyGesture()
                .onChanged { value in
                    gestures.zoom(
                        by: 1 + (value.magnification - 1) * 0.3,
                        about: value.startLocation
                    )
                }
        )
        .dropDestination(for: String.self) { technologyIds, location in
            guard let technologyId = technologyIds.first else { return false }
            let point = canvas.transform.modelPoint(location)
            session.add(
                technologyId: technologyId,
                x: point.x - Component.size.width / 2,
                y: point.y - Component.size.height / 2
            )
            return true
        }
    }

    private var content: some View {
        ZStack(alignment: .topLeading) {
            ConnectionsLayer(
                connections: session.canvas.connections,
                boxes: boxes,
                selectedConnectionIds: canvas.selectedConnectionIds,
                preview: previewLine
            )
            .frame(width: 20000, height: 20000)

            ForEach(session.canvas.components, id: \.id) { component in
                let componentBox = boxes[component.id] ?? ComponentBox(x: component.x, y: component.y)
                ComponentNodeView(
                    component: component,
                    isSelected: canvas.isSelected(componentId: component.id),
                    onSelect: { gestures.selectComponent(component.id, addingToSelection: $0) },
                    onDragChanged: { gestures.nodeDragChanged(component.id, $0) },
                    onDragEnded: { gestures.nodeDragEnded($0) },
                    onAnchorDragChanged: { gestures.anchorDragChanged(component.id, $0) },
                    onAnchorDragEnded: { gestures.anchorDragEnded(component.id, $0) }
                )
                .position(x: componentBox.centre.x, y: componentBox.centre.y)
            }

            if let rect = canvas.marqueeRect {
                Rectangle()
                    .fill(Color.accentColor.opacity(0.12))
                    .overlay(Rectangle().strokeBorder(Color.accentColor, lineWidth: 1))
                    .frame(width: rect.width, height: rect.height)
                    .position(x: rect.midX, y: rect.midY)
                    .allowsHitTesting(false)
            }
        }
    }

    private var zoomControls: some View {
        HStack(spacing: 4) {
            Button { gestures.zoom(by: 1 / 1.25, about: CGPoint(x: 400, y: 300)) } label: {
                Image(systemName: "minus.magnifyingglass")
            }
            .accessibilityIdentifier("zoom-out")
            Button { canvas.transform = CanvasTransform() } label: {
                Image(systemName: "1.magnifyingglass")
            }
            .accessibilityIdentifier("zoom-reset")
            Button { gestures.zoom(by: 1.25, about: CGPoint(x: 400, y: 300)) } label: {
                Image(systemName: "plus.magnifyingglass")
            }
            .accessibilityIdentifier("zoom-in")
        }
        .buttonStyle(.bordered)
        .padding(8)
    }

    private var previewLine: (start: CGPoint, end: CGPoint)? {
        guard let drag = canvas.connectionDrag,
              let source = boxes[drag.sourceComponentId] else { return nil }
        return (start: source.centre, end: drag.currentPoint)
    }
}
```

- [ ] **Step 7: Point `ComponentBox` at the core's footprint**

`Component.size` now lives in the core, so the app target stops holding a second copy. In `threatmodeller/canvas/ComponentBox.swift`:

```swift
import CoreGraphics
import ThreatModelKit

/// The rectangle a component occupies, in model coordinates.
///
/// The size comes from the core, because zone containment tests a component's
/// centre and the core has to know the extent that centre comes from.
nonisolated struct ComponentBox: Equatable {
    static let size = CGSize(width: Component.size.width, height: Component.size.height)

    let origin: CGPoint

    init(x: Double, y: Double) {
        origin = CGPoint(x: x, y: y)
    }

    var rect: CGRect { CGRect(origin: origin, size: Self.size) }

    var centre: CGPoint { CGPoint(x: rect.midX, y: rect.midY) }

    func contains(_ modelPoint: CGPoint) -> Bool { rect.contains(modelPoint) }
}
```

- [ ] **Step 8: Run every suite**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'Failing tests|\*\* TEST' -A3 | head -8
```

Expected: PASS, including the user interface journey. `CanvasView.swift` is now under 150 lines.

- [ ] **Step 9: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add threatmodeller threatmodellerTests
git commit -m "refactor: split the canvas into layout, gestures and hit testing

The carry-forward said to split this file before zones land, and zones add a
layer, three gestures and two hit tests. CanvasHitTest is pure, so the rules
that decide what a click landed on now have their own tests. A click on
overlapping links selects the one drawn on top, not the one drawn first.

ComponentBox reads its size from the core, so the footprint is stated once."
```

---

### Task 14: `ZoneBox` and `ZoneHandle`

**Files:**
- Create: `threatmodeller/canvas/ZoneBox.swift`
- Test: `threatmodellerTests/canvas/ZoneBoxTests.swift`

**Interfaces:**
- Consumes: `ZoneContainment.headerHeight`, `Zone.minimumSize`, `ViewedZone`.
- Produces: `ZoneHandle` (8 cases); `ZoneBox(x:y:width:height:)`, `ZoneBox(zone:)`, `.rect`, `.headerRect`, `.contentRect`, `.containsHeader(_:)`, `.handleRect(_:)`, `.handle(at:)`, `.resized(by:from:)`, `ZoneBox.headerHeight`, `.handleSize`, `.minimumSize`.

- [ ] **Step 1: Write the failing test**

Create `threatmodellerTests/canvas/ZoneBoxTests.swift`:

```swift
import CoreGraphics
import Testing
import ThreatModelKit
@testable import threatmodeller

struct ZoneBoxTests {
    private let box = ZoneBox(x: 100, y: 200, width: 600, height: 400)

    @Test func takesItsHeaderBandFromTheCore() {
        // The canvas and the core must agree, or a component would look
        // captured while scoring as though it were outside.
        // Compared as Double on both sides: `#expect` keeps the captured
        // operands' own types, so a CGFloat against a Double reads as unequal
        // even when both print the same number.
        #expect(Double(ZoneBox.headerHeight) == ZoneContainment.headerHeight)
        #expect(Double(ZoneBox.minimumSize.width) == Zone.minimumSize.width)
        #expect(Double(ZoneBox.minimumSize.height) == Zone.minimumSize.height)
    }

    @Test func splitsItselfIntoAHeaderAndAContentArea() {
        #expect(box.headerRect == CGRect(x: 100, y: 200, width: 600, height: ZoneBox.headerHeight))
        #expect(box.contentRect == CGRect(
            x: 100,
            y: 200 + ZoneBox.headerHeight,
            width: 600,
            height: 400 - ZoneBox.headerHeight
        ))
    }

    @Test func neverSplitsPastItsOwnBottom() {
        let squashed = ZoneBox(x: 0, y: 0, width: 600, height: 20)

        #expect(squashed.headerRect.height == 20)
        #expect(squashed.contentRect.height == 0)
    }

    @Test func knowsWhenAPointIsOnItsHeader() {
        #expect(box.containsHeader(CGPoint(x: 300, y: 210)))
        #expect(box.containsHeader(CGPoint(x: 300, y: 300)) == false)
        #expect(box.containsHeader(CGPoint(x: 50, y: 210)) == false)
    }

    @Test func putsAHandleOnEveryCornerAndEveryEdge() {
        #expect(ZoneHandle.allCases.count == 8)

        for handle in ZoneHandle.allCases {
            let rect = box.handleRect(handle)
            #expect(rect.width == ZoneBox.handleSize)
            #expect(rect.height == ZoneBox.handleSize)
            #expect(box.handle(at: CGPoint(x: rect.midX, y: rect.midY)) == handle)
        }
    }

    @Test func findsNoHandleAwayFromTheEdges() {
        #expect(box.handle(at: CGPoint(x: 400, y: 400)) == nil)
    }

    @Test func growsFromTheHandleTheUserDragged() {
        #expect(box.resized(by: CGSize(width: 50, height: 30), from: .bottomRight)
                == CGRect(x: 100, y: 200, width: 650, height: 430))

        #expect(box.resized(by: CGSize(width: -50, height: -30), from: .topLeft)
                == CGRect(x: 50, y: 170, width: 650, height: 430))
    }

    @Test func movesOnlyTheEdgeAnEdgeHandleOwns() {
        #expect(box.resized(by: CGSize(width: 40, height: 999), from: .right)
                == CGRect(x: 100, y: 200, width: 640, height: 400))

        #expect(box.resized(by: CGSize(width: 999, height: 40), from: .bottom)
                == CGRect(x: 100, y: 200, width: 600, height: 440))
    }

    @Test func stopsAtTheMinimumRatherThanTurningInsideOut() {
        let shrunk = box.resized(by: CGSize(width: -5000, height: -5000), from: .bottomRight)

        #expect(shrunk.width == ZoneBox.minimumSize.width)
        #expect(shrunk.height == ZoneBox.minimumSize.height)
        // The dragged corner stops; the opposite corner does not move.
        #expect(shrunk.minX == 100)
        #expect(shrunk.minY == 200)
    }

    @Test func stopsTheDraggedEdgeWhenTheTopLeftShrinksTooFar() {
        let shrunk = box.resized(by: CGSize(width: 5000, height: 5000), from: .topLeft)

        #expect(shrunk.width == ZoneBox.minimumSize.width)
        #expect(shrunk.height == ZoneBox.minimumSize.height)
        // The bottom-right corner is the one that stays put.
        #expect(shrunk.maxX == 700)
        #expect(shrunk.maxY == 600)
    }

    @Test func buildsItselfFromWhatTheCanvasWasGiven() {
        let viewed = ViewedZone(
            id: "z1",
            name: "Payments",
            customName: "Payments",
            networkZoneId: "private",
            networkTypeId: "vpc",
            riskReductionEnabled: true,
            riskReductionPercent: 20,
            x: 10,
            y: 20,
            width: 300,
            height: 200
        )

        #expect(ZoneBox(zone: viewed).rect == CGRect(x: 10, y: 20, width: 300, height: 200))
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'ZoneBox' in scope`.

- [ ] **Step 3: Write the geometry**

Create `threatmodeller/canvas/ZoneBox.swift`:

```swift
import CoreGraphics
import ThreatModelKit

/// The eight grips on a zone's outline.
nonisolated enum ZoneHandle: String, CaseIterable, Equatable {
    case topLeft
    case top
    case topRight
    case right
    case bottomRight
    case bottom
    case bottomLeft
    case left
}

/// A zone's rectangle on the canvas, its header band, and its resize grips.
///
/// The header height and the minimum size come from the core, so what the user
/// sees and what the core scores can never disagree.
nonisolated struct ZoneBox: Equatable {
    static let headerHeight = CGFloat(ZoneContainment.headerHeight)
    static let handleSize: CGFloat = 12
    static let minimumSize = CGSize(
        width: Zone.minimumSize.width,
        height: Zone.minimumSize.height
    )

    let rect: CGRect

    init(x: Double, y: Double, width: Double, height: Double) {
        rect = CGRect(x: x, y: y, width: width, height: height)
    }

    init(zone: ViewedZone) {
        self.init(x: zone.x, y: zone.y, width: zone.width, height: zone.height)
    }

    /// The band holding the zone's name. Dragging it moves the zone.
    var headerRect: CGRect {
        CGRect(
            x: rect.minX,
            y: rect.minY,
            width: rect.width,
            height: min(Self.headerHeight, rect.height)
        )
    }

    /// The area a component's centre must sit in to belong to the zone.
    var contentRect: CGRect {
        let removed = min(Self.headerHeight, rect.height)
        return CGRect(
            x: rect.minX,
            y: rect.minY + removed,
            width: rect.width,
            height: rect.height - removed
        )
    }

    func containsHeader(_ modelPoint: CGPoint) -> Bool { headerRect.contains(modelPoint) }

    func handleRect(_ handle: ZoneHandle) -> CGRect {
        let centre = handlePoint(handle)
        return CGRect(
            x: centre.x - Self.handleSize / 2,
            y: centre.y - Self.handleSize / 2,
            width: Self.handleSize,
            height: Self.handleSize
        )
    }

    func handle(at modelPoint: CGPoint) -> ZoneHandle? {
        ZoneHandle.allCases.first { handleRect($0).contains(modelPoint) }
    }

    /// The rectangle a drag from a grip produces.
    ///
    /// A corner grip moves two edges, an edge grip moves one. The rectangle
    /// never falls below the minimum: the dragged edge stops and the opposite
    /// edge stays put, so the zone cannot turn inside out.
    func resized(by translation: CGSize, from handle: ZoneHandle) -> CGRect {
        var minX = rect.minX
        var minY = rect.minY
        var maxX = rect.maxX
        var maxY = rect.maxY

        switch handle {
        case .topLeft:
            minX += translation.width
            minY += translation.height
        case .top:
            minY += translation.height
        case .topRight:
            maxX += translation.width
            minY += translation.height
        case .right:
            maxX += translation.width
        case .bottomRight:
            maxX += translation.width
            maxY += translation.height
        case .bottom:
            maxY += translation.height
        case .bottomLeft:
            minX += translation.width
            maxY += translation.height
        case .left:
            minX += translation.width
        }

        if maxX - minX < Self.minimumSize.width {
            if handle == .topLeft || handle == .left || handle == .bottomLeft {
                minX = maxX - Self.minimumSize.width
            } else {
                maxX = minX + Self.minimumSize.width
            }
        }
        if maxY - minY < Self.minimumSize.height {
            if handle == .topLeft || handle == .top || handle == .topRight {
                minY = maxY - Self.minimumSize.height
            } else {
                maxY = minY + Self.minimumSize.height
            }
        }

        return CGRect(x: minX, y: minY, width: maxX - minX, height: maxY - minY)
    }

    private func handlePoint(_ handle: ZoneHandle) -> CGPoint {
        switch handle {
        case .topLeft: CGPoint(x: rect.minX, y: rect.minY)
        case .top: CGPoint(x: rect.midX, y: rect.minY)
        case .topRight: CGPoint(x: rect.maxX, y: rect.minY)
        case .right: CGPoint(x: rect.maxX, y: rect.midY)
        case .bottomRight: CGPoint(x: rect.maxX, y: rect.maxY)
        case .bottom: CGPoint(x: rect.midX, y: rect.maxY)
        case .bottomLeft: CGPoint(x: rect.minX, y: rect.maxY)
        case .left: CGPoint(x: rect.minX, y: rect.midY)
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'Failing tests|\*\* TEST' -A3 | head -8
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add threatmodeller/canvas/ZoneBox.swift threatmodellerTests/canvas/ZoneBoxTests.swift
git commit -m "feat: add the zone canvas geometry

The header band and the minimum size come from the core, so what the user
sees and what the core scores cannot disagree. A resize stops at the minimum
rather than turning the zone inside out."
```

---

### Task 15: Zone state and the session's zone methods

**Files:**
- Modify: `threatmodeller/canvas/CanvasState.swift`
- Modify: `threatmodeller/canvas/CanvasHitTest.swift`
- Modify: `threatmodeller/ThreatModelSession.swift`
- Modify: `threatmodellerTests/canvas/CanvasStateTests.swift`
- Modify: `threatmodellerTests/threatmodellerTests.swift`

**Interfaces:**
- Consumes: `ZoneBox`, `ZoneHandle`, and the four zone use cases.
- Produces:
  - `CanvasState.selectedZoneIds`, `.isDrawingZone`, `.zoneDraft`, `.zoneDraftRect`, `.zoneDrag`, `.select(zoneId:)`, `.startDrawingZone()`, `.retainOnly(componentIds:connectionIds:zoneIds:)`
  - `CanvasHitTest.zone(under:zones:)`
  - `ThreatModelSession.addZone(x:y:width:height:) -> String?`, `.resizeZone(_:x:y:width:height:)`, `.setZoneProperties(zoneId:name:networkZoneId:networkTypeId:riskReductionEnabled:riskReductionPercent:)`, `.removeZone(_:)`

- [ ] **Step 1: Write the failing tests**

Add to `threatmodellerTests/canvas/CanvasStateTests.swift`:

```swift
    @Test func selectingAZoneDropsEveryOtherSelection() {
        let canvas = CanvasState()

        canvas.select(componentIds: ["c1", "c2"])
        canvas.select(zoneId: "z1")

        #expect(canvas.selectedZoneIds == ["z1"])
        #expect(canvas.selectedComponentIds.isEmpty)
        #expect(canvas.selectedConnectionIds.isEmpty)
        #expect(canvas.hasSelection)
    }

    @Test func selectingAComponentDropsTheZoneSelection() {
        let canvas = CanvasState()

        canvas.select(zoneId: "z1")
        canvas.select(componentId: "c1", addingToSelection: false)

        #expect(canvas.selectedZoneIds.isEmpty)
    }

    @Test func dropsASelectedZoneTheModelNoLongerHolds() {
        let canvas = CanvasState()

        canvas.select(zoneId: "z1")
        canvas.retainOnly(componentIds: [], connectionIds: [], zoneIds: [])

        #expect(canvas.selectedZoneIds.isEmpty)
    }

    @Test func reportsTheZoneDraftRectangleWhileTheUserDrawsIt() {
        let canvas = CanvasState()

        #expect(canvas.zoneDraftRect == nil)
        canvas.zoneDraft = (start: CGPoint(x: 90, y: 80), end: CGPoint(x: 10, y: 20))
        #expect(canvas.zoneDraftRect == CGRect(x: 10, y: 20, width: 80, height: 60))
    }

    @Test func escapeLeavesTheZoneDrawingModeBeforeItClearsTheSelection() {
        let canvas = CanvasState()

        canvas.select(zoneId: "z1")
        canvas.startDrawingZone()
        #expect(canvas.isDrawingZone)

        #expect(canvas.cancel())
        #expect(canvas.isDrawingZone == false)
        #expect(canvas.zoneDraft == nil)
        #expect(canvas.selectedZoneIds == ["z1"])

        #expect(canvas.cancel())
        #expect(canvas.hasSelection == false)
    }

    @Test func cancelsAConnectionDragBeforeItLeavesTheZoneMode() {
        let canvas = CanvasState()

        canvas.startDrawingZone()
        canvas.connectionDrag = (sourceComponentId: "c1", currentPoint: .zero)

        #expect(canvas.cancel())
        #expect(canvas.connectionDrag == nil)
        #expect(canvas.isDrawingZone)
    }
```

Add to `threatmodellerTests/threatmodellerTests.swift`:

```swift
    @Test func drawsAZoneAndReducesWhatItCaptures() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        let before = try #require(session.threats.first { $0.threatId == "credential-theft" }).riskScore

        let zoneId = session.addZone(x: 0, y: 0, width: 600, height: 500)

        #expect(zoneId != nil)
        #expect(session.canvas.zones.count == 1)
        #expect(session.canvas.components.first?.zoneId == zoneId)
        let after = try #require(session.threats.first { $0.threatId == "credential-theft" }).riskScore
        #expect(after < before)
        #expect(session.errorMessage == nil)
    }

    @Test func refusesAZoneDrawnTooSmall() {
        let session = session()

        #expect(session.addZone(x: 0, y: 0, width: 10, height: 10) == nil)
        #expect(session.canvas.zones.isEmpty)
        #expect(session.errorMessage == "That zone is too small to draw.")
    }

    @Test func movesAZoneToItsNewRectangle() throws {
        let session = session()
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 600, height: 500))

        session.resizeZone(zoneId, x: 40, y: 60, width: 700, height: 550)

        let zone = try #require(session.canvas.zones.first)
        #expect(zone.x == 40)
        #expect(zone.width == 700)
    }

    @Test func setsAZonesPropertiesAndRescores() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 600, height: 500))
        #expect(session.threats.contains { $0.threatId == "lateral-movement" })

        session.setZoneProperties(
            zoneId: zoneId,
            name: "Internet",
            networkZoneId: "public",
            networkTypeId: "generic",
            riskReductionEnabled: true,
            riskReductionPercent: 20
        )

        #expect(session.canvas.zones.first?.name == "Internet")
        #expect(session.canvas.zones.first?.networkZoneId == "public")
        // A public zone raises no zone threats and reduces nothing.
        #expect(session.threats.contains { $0.threatId == "lateral-movement" } == false)
        #expect(try #require(session.threats.first { $0.threatId == "credential-theft" }).riskScore == 4)
    }

    @Test func removesAZoneAndLeavesItsComponents() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 600, height: 500))

        session.removeZone(zoneId)

        #expect(session.canvas.zones.isEmpty)
        #expect(session.canvas.components.count == 1)
        #expect(session.canvas.components.first?.zoneId == nil)
    }
```

The session adds at `internal` sensitivity, rank 2, so `credential-theft` is 4 × 2 = 8 outside a zone and 4 × 2 × 0.8 = 6.4 → 6 inside the default private zone.

- [ ] **Step 2: Run them to verify they fail**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `value of type 'CanvasState' has no member 'selectedZoneIds'`.

- [ ] **Step 3: Add the zone state**

In `threatmodeller/canvas/CanvasState.swift`, add the stored properties beside the others:

```swift
    private(set) var selectedZoneIds: Set<String> = []

    /// True while the next background drag draws a zone rather than a marquee.
    private(set) var isDrawingZone = false

    /// The two corners of the zone being drawn, in model coordinates.
    var zoneDraft: (start: CGPoint, end: CGPoint)?

    /// The zone being moved or resized, the grip the drag started from, and
    /// how far it has moved in model units. A nil handle means the drag started
    /// on the header, which moves the zone rather than resizing it.
    var zoneDrag: (zoneId: String, handle: ZoneHandle?, translation: CGSize)?
```

Add the derived rectangle beside `marqueeRect`:

```swift
    var zoneDraftRect: CGRect? {
        zoneDraft.map { MarqueeSelection.rect(from: $0.start, to: $0.end) }
    }
```

Extend `hasSelection`, add the selector, extend `clearSelection`, `retainOnly` and `cancel`:

```swift
    var hasSelection: Bool {
        selectedComponentIds.isEmpty == false
            || selectedConnectionIds.isEmpty == false
            || selectedZoneIds.isEmpty == false
    }

    func isSelected(zoneId: String) -> Bool { selectedZoneIds.contains(zoneId) }

    /// One zone at a time. The panel edits a single zone, and a zone is a
    /// container rather than a thing to gather into a group.
    func select(zoneId: String) {
        selectedComponentIds = []
        selectedConnectionIds = []
        selectedZoneIds = [zoneId]
    }

    func startDrawingZone() {
        isDrawingZone = true
        zoneDraft = nil
    }

    func stopDrawingZone() {
        isDrawingZone = false
        zoneDraft = nil
    }
```

`select(componentId:addingToSelection:)`, `select(connectionId:addingToSelection:)` and `select(componentIds:)` each gain `selectedZoneIds = []` as their first line, beside the clearing they already do. `clearSelection()` clears all three sets. `retainOnly` gains a third argument:

```swift
    func retainOnly(componentIds: Set<String>, connectionIds: Set<String>, zoneIds: Set<String>) {
        selectedComponentIds.formIntersection(componentIds)
        selectedConnectionIds.formIntersection(connectionIds)
        selectedZoneIds.formIntersection(zoneIds)
    }
```

`cancel()` gains the middle rung:

```swift
    /// Escape: cancel a connection drag when one is in flight, else leave the
    /// zone drawing mode, else clear the selection. Returns true when it
    /// changed something.
    @discardableResult
    func cancel() -> Bool {
        if connectionDrag != nil {
            connectionDrag = nil
            return true
        }
        if isDrawingZone {
            stopDrawingZone()
            return true
        }
        if hasSelection {
            clearSelection()
            return true
        }
        return false
    }
```

- [ ] **Step 4: Add the zone hit test**

Append to `CanvasHitTest`:

```swift
    /// The zone under the point, or nil. A later zone wins, matching
    /// `ZoneContainment` in the core.
    static func zone(under modelPoint: CGPoint, zones: [ViewedZone]) -> String? {
        zones.last { ZoneBox(zone: $0).rect.contains(modelPoint) }?.id
    }
```

- [ ] **Step 5: Add the session's zone methods**

Add to `threatmodeller/ThreatModelSession.swift`:

```swift
    /// Returns the new zone's identifier, or nil when the drag was too small
    /// to make a zone.
    @discardableResult
    func addZone(x: Double, y: Double, width: Double, height: Double) -> String? {
        defer { refresh() }

        switch useCases.addZone().execute(
            AddZoneRequest(x: x, y: y, width: width, height: height)
        ) {
        case .added(let zoneId):
            errorMessage = nil
            return zoneId
        case .tooSmall:
            errorMessage = "That zone is too small to draw."
            return nil
        }
    }

    func resizeZone(_ zoneId: String, x: Double, y: Double, width: Double, height: Double) {
        switch useCases.resizeZone().execute(
            ResizeZoneRequest(zoneId: zoneId, x: x, y: y, width: width, height: height)
        ) {
        case .resized:
            errorMessage = nil
        case .unknownZone:
            errorMessage = "That zone is no longer on the model."
        case .tooSmall:
            errorMessage = "That zone is too small to draw."
        }

        refresh()
    }

    func setZoneProperties(
        zoneId: String,
        name: String?,
        networkZoneId: String,
        networkTypeId: String,
        riskReductionEnabled: Bool,
        riskReductionPercent: Int
    ) {
        switch useCases.setZoneProperties().execute(
            SetZonePropertiesRequest(
                zoneId: zoneId,
                name: name,
                networkZone: networkZoneId,
                networkType: networkTypeId,
                riskReductionEnabled: riskReductionEnabled,
                riskReductionPercent: riskReductionPercent
            )
        ) {
        case .updated:
            errorMessage = nil
        case .unknownZone:
            errorMessage = "That zone is no longer on the model."
        case .unknownNetworkZone:
            errorMessage = "That kind of zone is not recognised."
        case .unknownNetworkType:
            errorMessage = "That network type is not recognised."
        case .reductionOutOfRange:
            errorMessage = "Risk reduction must be between 0 and 100 per cent."
        }

        refresh()
    }

    func removeZone(_ zoneId: String) {
        switch useCases.removeZone().execute(RemoveZoneRequest(zoneId: zoneId)) {
        case .removed:
            errorMessage = nil
        case .unknownZone:
            errorMessage = "That zone is no longer on the model."
        }

        refresh()
    }
```

- [ ] **Step 6: Extend the delete command**

In `CanvasGestures.deleteSelection()`, remove the selected zones too and pass the third set to `retainOnly`:

```swift
    func deleteSelection() {
        for connectionId in canvas.selectedConnectionIds {
            session.removeConnection(connectionId)
        }
        for zoneId in canvas.selectedZoneIds {
            session.removeZone(zoneId)
        }
        if canvas.selectedComponentIds.isEmpty == false {
            session.removeComponents(Array(canvas.selectedComponentIds))
        }
        canvas.retainOnly(
            componentIds: Set(session.canvas.components.map(\.id)),
            connectionIds: Set(session.canvas.connections.map(\.id)),
            zoneIds: Set(session.canvas.zones.map(\.id))
        )
    }
```

- [ ] **Step 7: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'Failing tests|\*\* TEST' -A3 | head -8
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add threatmodeller threatmodellerTests
git commit -m "feat: add zone state and the session's zone methods

Escape now has three rungs: cancel a connection drag, leave the zone drawing
mode, clear the selection. The delete key removes selected zones as well."
```

---

### Task 16: The zone layer

**Files:**
- Create: `threatmodeller/canvas/ZoneView.swift`
- Modify: `threatmodeller/canvas/CanvasView.swift`

**Interfaces:**
- Consumes: `ZoneBox`, `ZoneHandle`, `ViewedZone`.
- Produces: `ZoneView(zone:isSelected:onSelect:onDragChanged:onDragEnded:)`; accessibility identifier `zone-<id>`.

Painting order becomes what spec §9 states in full: zones, then every connection in one `Canvas` pass, then component views. Zones go first, so a zone never covers a node.

- [ ] **Step 1: Write the zone view**

Create `threatmodeller/canvas/ZoneView.swift`:

```swift
import SwiftUI
import ThreatModelKit

/// One zone: its outline, its header, and its resize grips when selected.
///
/// A public zone is drawn with a dashed outline, because it reduces nothing
/// and raises nothing — the difference has to be visible without reading the
/// panel.
struct ZoneView: View {
    let zone: ViewedZone
    /// The size to draw at. While a resize is in flight this is the size the
    /// drag produces, not the size the model holds, so the outline, the header
    /// and the grips all follow the pointer.
    let size: CGSize
    let isSelected: Bool
    let onSelect: () -> Void
    let onDragChanged: (_ handle: ZoneHandle?, _ translation: CGSize) -> Void
    let onDragEnded: (_ handle: ZoneHandle?, _ translation: CGSize) -> Void

    /// The zone drawn at the view's own origin, so a grip's position inside
    /// this view does not depend on where the zone sits on the canvas.
    private var box: ZoneBox {
        ZoneBox(x: 0, y: 0, width: size.width, height: size.height)
    }

    private var isPrivate: Bool { zone.networkZoneId == "private" }

    private var tint: Color { isPrivate ? .green : .orange }

    var body: some View {
        ZStack(alignment: .topLeading) {
            RoundedRectangle(cornerRadius: 12)
                .fill(tint.opacity(0.07))
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .strokeBorder(
                            isSelected ? Color.accentColor : tint.opacity(0.7),
                            style: StrokeStyle(
                                lineWidth: isSelected ? 2.5 : 1.5,
                                dash: isPrivate ? [] : [6, 4]
                            )
                        )
                )

            header
        }
        .frame(width: size.width, height: size.height)
        .overlay(alignment: .topLeading) {
            if isSelected { grips }
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("zone-\(zone.id)")
    }

    private var header: some View {
        HStack(spacing: 8) {
            Text(zone.name)
                .font(.headline)
                .lineLimit(1)
            if isPrivate && zone.riskReductionEnabled {
                Text("−\(zone.riskReductionPercent)%")
                    .font(.caption2)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Capsule().fill(tint.opacity(0.2)))
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12)
        .frame(width: size.width, height: ZoneBox.headerHeight, alignment: .leading)
        .contentShape(Rectangle())
        .onTapGesture { onSelect() }
        .gesture(
            DragGesture(minimumDistance: 3, coordinateSpace: .named("canvas"))
                .onChanged { onDragChanged(nil, $0.translation) }
                .onEnded { onDragEnded(nil, $0.translation) }
        )
    }

    private var grips: some View {
        ForEach(ZoneHandle.allCases, id: \.self) { handle in
            let rect = box.handleRect(handle)
            RoundedRectangle(cornerRadius: 2)
                .fill(Color.accentColor)
                .frame(width: rect.width, height: rect.height)
                .position(x: rect.midX, y: rect.midY)
                .gesture(
                    DragGesture(minimumDistance: 1, coordinateSpace: .named("canvas"))
                        .onChanged { onDragChanged(handle, $0.translation) }
                        .onEnded { onDragEnded(handle, $0.translation) }
                )
        }
    }
}
```

- [ ] **Step 2: Paint the zones first**

In `CanvasView.content`, put the zone layer above the connections layer inside the `ZStack`, so it paints first:

```swift
    private var content: some View {
        ZStack(alignment: .topLeading) {
            ForEach(session.canvas.zones, id: \.id) { zone in
                let rect = CanvasHitTest.rect(for: zone, drag: canvas.zoneDrag)
                ZoneView(
                    zone: zone,
                    size: rect.size,
                    isSelected: canvas.isSelected(zoneId: zone.id),
                    onSelect: { canvas.select(zoneId: zone.id) },
                    onDragChanged: { gestures.zoneDragChanged(zone.id, handle: $0, translation: $1) },
                    onDragEnded: { gestures.zoneDragEnded(zone.id, handle: $0, translation: $1) }
                )
                .position(x: rect.midX, y: rect.midY)
            }

            if let draft = canvas.zoneDraftRect {
                RoundedRectangle(cornerRadius: 12)
                    .fill(Color.green.opacity(0.07))
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .strokeBorder(Color.accentColor, style: StrokeStyle(lineWidth: 2, dash: [6, 4]))
                    )
                    .frame(width: draft.width, height: draft.height)
                    .position(x: draft.midX, y: draft.midY)
                    .allowsHitTesting(false)
            }

            ConnectionsLayer(
                connections: session.canvas.connections,
                boxes: boxes,
                selectedConnectionIds: canvas.selectedConnectionIds,
                preview: previewLine
            )
            .frame(width: 20000, height: 20000)

            // … the component views and the marquee, unchanged …
        }
    }
```

WARNING: `ZoneView` draws at the `size` it is given, never at `zone.width` and `zone.height`. `CanvasHitTest.rect(for:drag:)` supplies that size, so a move or a resize in flight follows the pointer. Reading the stored size instead would leave the outline frozen until the drag ended.

- [ ] **Step 3: Build and look at it**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' build 2>&1 | grep -E 'error:|BUILD' | head -5
```

Expected: BUILD SUCCEEDED. Nothing draws a zone yet, because nothing calls `AddZone` from the canvas until Task 17.

- [ ] **Step 4: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add threatmodeller
git commit -m "feat: draw zones under everything else

Zones paint first, so a zone never covers a node. A public zone is drawn with
a dashed outline, because it reduces nothing and raises nothing and the
difference has to be visible without reading the panel."
```

---

### Task 17: Drawing, moving and resizing a zone

**Files:**
- Modify: `threatmodeller/canvas/CanvasHitTest.swift`
- Modify: `threatmodeller/canvas/CanvasGestures.swift`
- Modify: `threatmodeller/canvas/CanvasView.swift`
- Modify: `threatmodellerTests/canvas/CanvasHitTestTests.swift`

**Interfaces:**
- Consumes: `ZoneBox.resized(by:from:)`, `ThreatModelSession.addZone`, `.resizeZone`.
- Produces: `CanvasHitTest.rect(for:drag:)`; `CanvasGestures.zoneDragChanged(_:handle:translation:)`, `.zoneDragEnded(_:handle:translation:)`; a "Draw zone" toggle in the canvas toolbar.

- [ ] **Step 1: Write the failing test**

Add to `threatmodellerTests/canvas/CanvasHitTestTests.swift`:

```swift
    private func viewedZone(_ id: String, x: Double = 0, y: Double = 0) -> ViewedZone {
        ViewedZone(
            id: id,
            name: "Private Zone",
            customName: nil,
            networkZoneId: "private",
            networkTypeId: "generic",
            riskReductionEnabled: true,
            riskReductionPercent: 20,
            x: x,
            y: y,
            width: 600,
            height: 400
        )
    }

    @Test func drawsAZoneAtItsOwnRectangleWhenNothingIsDragging() {
        #expect(CanvasHitTest.rect(for: viewedZone("z1", x: 10, y: 20), drag: nil)
                == CGRect(x: 10, y: 20, width: 600, height: 400))
    }

    @Test func movesTheZoneBeingDraggedByItsHeader() {
        let rect = CanvasHitTest.rect(
            for: viewedZone("z1", x: 10, y: 20),
            drag: (zoneId: "z1", handle: nil, translation: CGSize(width: 30, height: -5))
        )

        #expect(rect == CGRect(x: 40, y: 15, width: 600, height: 400))
    }

    @Test func resizesTheZoneBeingDraggedByAGrip() {
        let rect = CanvasHitTest.rect(
            for: viewedZone("z1"),
            drag: (zoneId: "z1", handle: .bottomRight, translation: CGSize(width: 50, height: 40))
        )

        #expect(rect == CGRect(x: 0, y: 0, width: 650, height: 440))
    }

    @Test func leavesEveryOtherZoneWhereItIs() {
        let rect = CanvasHitTest.rect(
            for: viewedZone("z2", x: 900),
            drag: (zoneId: "z1", handle: nil, translation: CGSize(width: 30, height: 30))
        )

        #expect(rect == CGRect(x: 900, y: 0, width: 600, height: 400))
    }

    @Test func findsTheZoneUnderAPoint() {
        let zones = [viewedZone("z1"), viewedZone("z2", x: 100, y: 100)]

        #expect(CanvasHitTest.zone(under: CGPoint(x: 50, y: 50), zones: zones) == "z1")
        // A later zone wins where two overlap, matching the core's rule.
        #expect(CanvasHitTest.zone(under: CGPoint(x: 200, y: 200), zones: zones) == "z2")
        #expect(CanvasHitTest.zone(under: CGPoint(x: 5000, y: 5000), zones: zones) == nil)
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `type 'CanvasHitTest' has no member 'rect'`.

- [ ] **Step 3: Add the drawn rectangle**

Append to `CanvasHitTest`:

```swift
    /// Where a zone is drawn, with a move or resize in flight applied.
    static func rect(
        for zone: ViewedZone,
        drag: (zoneId: String, handle: ZoneHandle?, translation: CGSize)?
    ) -> CGRect {
        let box = ZoneBox(zone: zone)
        guard let drag, drag.zoneId == zone.id else { return box.rect }
        guard let handle = drag.handle else {
            return box.rect.offsetBy(dx: drag.translation.width, dy: drag.translation.height)
        }
        return box.resized(by: drag.translation, from: handle)
    }
```

- [ ] **Step 4: Add the zone gestures**

Add to `CanvasGestures`:

```swift
    // MARK: zones

    func zoneDragChanged(_ zoneId: String, handle: ZoneHandle?, translation: CGSize) {
        canvas.select(zoneId: zoneId)
        canvas.zoneDrag = (
            zoneId: zoneId,
            handle: handle,
            translation: canvas.transform.modelDistance(translation)
        )
    }

    func zoneDragEnded(_ zoneId: String, handle: ZoneHandle?, translation: CGSize) {
        defer { canvas.zoneDrag = nil }

        guard let zone = session.canvas.zones.first(where: { $0.id == zoneId }) else { return }
        let rect = CanvasHitTest.rect(
            for: zone,
            drag: (
                zoneId: zoneId,
                handle: handle,
                translation: canvas.transform.modelDistance(translation)
            )
        )
        session.resizeZone(
            zoneId,
            x: rect.minX,
            y: rect.minY,
            width: rect.width,
            height: rect.height
        )
    }
```

Change `marqueeDrag` so it draws a zone while the mode is on:

```swift
    private var marqueeDrag: some Gesture {
        DragGesture(minimumDistance: 2, coordinateSpace: .named("canvas"))
            .onChanged { value in
                let corners = (
                    start: canvas.transform.modelPoint(value.startLocation),
                    end: canvas.transform.modelPoint(value.location)
                )
                if canvas.isDrawingZone {
                    canvas.zoneDraft = corners
                } else {
                    canvas.marquee = corners
                }
            }
            .onEnded { _ in
                if canvas.isDrawingZone {
                    commitDraftZone()
                } else {
                    commitMarquee()
                }
            }
    }

    private func commitDraftZone() {
        defer { canvas.stopDrawingZone() }
        guard let rect = canvas.zoneDraftRect else { return }
        if let zoneId = session.addZone(
            x: rect.minX,
            y: rect.minY,
            width: rect.width,
            height: rect.height
        ) {
            canvas.select(zoneId: zoneId)
        }
    }

    private func commitMarquee() {
        if let rect = canvas.marqueeRect {
            canvas.select(componentIds: MarqueeSelection.selected(
                in: rect,
                from: session.canvas.components.map {
                    (id: $0.id, box: ComponentBox(x: $0.x, y: $0.y))
                }
            ))
        }
        canvas.marquee = nil
    }
```

Change `backgroundTap` so a click selects a zone when it hits no link:

```swift
    var backgroundTap: some Gesture {
        SpatialTapGesture(coordinateSpace: .named("canvas")).onEnded { value in
            let point = canvas.transform.modelPoint(value.location)
            if let connectionId = CanvasHitTest.connection(
                under: point,
                connections: session.canvas.connections,
                boxes: boxes
            ) {
                canvas.select(connectionId: connectionId, addingToSelection: false)
            } else if let zoneId = CanvasHitTest.zone(under: point, zones: session.canvas.zones) {
                canvas.select(zoneId: zoneId)
            } else {
                canvas.clearSelection()
            }
        }
    }
```

- [ ] **Step 5: Add the "Draw zone" toggle**

In `CanvasView.zoomControls`, put the toggle first and rename the group:

```swift
    private var canvasToolbar: some View {
        HStack(spacing: 8) {
            Button {
                canvas.isDrawingZone ? canvas.stopDrawingZone() : canvas.startDrawingZone()
            } label: {
                Label("Draw zone", systemImage: "rectangle.dashed")
            }
            .buttonStyle(.bordered)
            .tint(canvas.isDrawingZone ? .accentColor : nil)
            .accessibilityIdentifier("draw-zone")

            Divider().frame(height: 16)

            Button { gestures.zoom(by: 1 / 1.25, about: CGPoint(x: 400, y: 300)) } label: {
                Image(systemName: "minus.magnifyingglass")
            }
            .accessibilityIdentifier("zoom-out")
            Button { canvas.transform = CanvasTransform() } label: {
                Image(systemName: "1.magnifyingglass")
            }
            .accessibilityIdentifier("zoom-reset")
            Button { gestures.zoom(by: 1.25, about: CGPoint(x: 400, y: 300)) } label: {
                Image(systemName: "plus.magnifyingglass")
            }
            .accessibilityIdentifier("zoom-in")
        }
        .buttonStyle(.bordered)
        .padding(8)
    }
```

Rename the use in `body` from `zoomControls` to `canvasToolbar`, and show the crosshair while the mode is on:

```swift
        .pointerStyle(canvas.isDrawingZone ? .crosshair : nil)
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
git commit -m "feat: draw, move and resize a zone on the canvas

A toolbar toggle puts the canvas in zone mode and the next background drag
draws the zone. Dragging the header moves it, dragging a grip resizes it, and
both commit on release. A click on empty canvas that hits no link selects the
zone under it."
```

---

### Task 18: The zone panel and the node's zone badge

**Files:**
- Create: `threatmodeller/canvas/ZonePanel.swift`
- Modify: `threatmodeller/ContentView.swift`
- Modify: `threatmodeller/canvas/ComponentNodeView.swift`
- Modify: `threatmodeller/canvas/CanvasView.swift`

**Interfaces:**
- Consumes: `ThreatModelSession.setZoneProperties`, `ViewedZone`, `ViewedComponent.zoneId`.
- Produces: `ZonePanel(session:zone:)`; accessibility identifiers `zone-name`, `zone-kind`, `zone-network-type`, `zone-reduction-enabled`, `zone-reduction-percent`.

- [ ] **Step 1: Write the panel**

Create `threatmodeller/canvas/ZonePanel.swift`:

```swift
import SwiftUI
import ThreatModelKit

/// The bar under the canvas, shown while exactly one zone is selected.
///
/// Every control writes through `SetZoneProperties` and the threat list
/// rescores, so the user sees the effect of a reduction as they change it.
struct ZonePanel: View {
    let session: ThreatModelSession
    let zone: ViewedZone

    private static let kinds = [("private", "Private"), ("public", "Public")]
    private static let networkTypes = [
        ("generic", "Generic Network"),
        ("vpc", "VPC"),
        ("subnet", "Subnet"),
        ("on-premises", "On-Premises"),
        ("dmz", "DMZ"),
        ("management", "Management Network"),
        ("data", "Data Network")
    ]

    var body: some View {
        HStack(alignment: .center, spacing: 16) {
            TextField("Name", text: name)
                .textFieldStyle(.roundedBorder)
                .frame(width: 180)
                .accessibilityIdentifier("zone-name")

            Picker("Kind", selection: kind) {
                ForEach(Self.kinds, id: \.0) { Text($0.1).tag($0.0) }
            }
            .pickerStyle(.segmented)
            .frame(width: 160)
            .accessibilityIdentifier("zone-kind")

            Picker("Network", selection: networkType) {
                ForEach(Self.networkTypes, id: \.0) { Text($0.1).tag($0.0) }
            }
            .frame(width: 200)
            .accessibilityIdentifier("zone-network-type")

            Toggle("Reduce risk", isOn: reductionEnabled)
                .toggleStyle(.switch)
                .accessibilityIdentifier("zone-reduction-enabled")

            if zone.riskReductionEnabled && zone.networkZoneId == "private" {
                HStack(spacing: 6) {
                    Slider(value: reductionPercent, in: 0...100, step: 5)
                        .frame(width: 140)
                        .accessibilityIdentifier("zone-reduction-percent")
                    Text("\(zone.riskReductionPercent)%")
                        .monospacedDigit()
                        .frame(width: 42, alignment: .trailing)
                }
            }

            Spacer(minLength: 0)

            Button(role: .destructive) {
                session.removeZone(zone.id)
            } label: {
                Label("Remove zone", systemImage: "trash")
            }
            .accessibilityIdentifier("zone-remove")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.bar)
    }

    // MARK: writing through

    private func write(
        name newName: String? = nil,
        kind newKind: String? = nil,
        networkType newNetworkType: String? = nil,
        enabled newEnabled: Bool? = nil,
        percent newPercent: Int? = nil
    ) {
        session.setZoneProperties(
            zoneId: zone.id,
            name: newName ?? zone.customName,
            networkZoneId: newKind ?? zone.networkZoneId,
            networkTypeId: newNetworkType ?? zone.networkTypeId,
            riskReductionEnabled: newEnabled ?? zone.riskReductionEnabled,
            riskReductionPercent: newPercent ?? zone.riskReductionPercent
        )
    }

    private var name: Binding<String> {
        Binding(get: { zone.customName ?? "" }, set: { write(name: $0) })
    }

    private var kind: Binding<String> {
        Binding(get: { zone.networkZoneId }, set: { write(kind: $0) })
    }

    private var networkType: Binding<String> {
        Binding(get: { zone.networkTypeId }, set: { write(networkType: $0) })
    }

    private var reductionEnabled: Binding<Bool> {
        Binding(get: { zone.riskReductionEnabled }, set: { write(enabled: $0) })
    }

    private var reductionPercent: Binding<Double> {
        Binding(
            get: { Double(zone.riskReductionPercent) },
            set: { write(percent: Int($0.rounded())) }
        )
    }
}
```

- [ ] **Step 2: Put the panel under the canvas**

In `CanvasView.body`, attach it to the `GeometryReader`'s result so it pushes the canvas up rather than covering it:

```swift
        .safeAreaInset(edge: .bottom) {
            if let zone = selectedZone {
                ZonePanel(session: session, zone: zone)
            }
        }
```

and add:

```swift
    /// The panel edits one zone at a time, so it appears only when exactly one
    /// is selected.
    private var selectedZone: ViewedZone? {
        guard canvas.selectedZoneIds.count == 1,
              let zoneId = canvas.selectedZoneIds.first else { return nil }
        return session.canvas.zones.first { $0.id == zoneId }
    }
```

- [ ] **Step 3: Show a component's zone on its node**

In `ComponentNodeView`, add the badge to the second row of the label, after the sensitivity capsule:

```swift
                    if let zoneName {
                        Text(zoneName)
                            .font(.caption2)
                            .lineLimit(1)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(Capsule().fill(Color.green.opacity(0.18)))
                    }
```

and the input that feeds it:

```swift
    /// The display name of the zone holding this component, or nil. The rule
    /// is the component's centre inside the zone below its header, which is
    /// invisible without this badge.
    let zoneName: String?
```

`CanvasView` passes it:

```swift
                    zoneName: session.canvas.zones.first { $0.id == component.zoneId }?.name,
```

- [ ] **Step 4: Cover the panel's writing with a test**

Add to `threatmodellerTests/threatmodellerTests.swift`:

```swift
    @Test func showsTheZoneBadgeNameForACapturedComponent() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 600, height: 500))
        session.setZoneProperties(
            zoneId: zoneId,
            name: "Payments",
            networkZoneId: "private",
            networkTypeId: "vpc",
            riskReductionEnabled: true,
            riskReductionPercent: 20
        )

        let captured = try #require(session.canvas.components.first)
        #expect(captured.zoneId == zoneId)
        #expect(session.canvas.zones.first?.name == "Payments")
    }

    @Test func reportsAReductionOutsideTheRange() throws {
        let session = session()
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 600, height: 500))

        session.setZoneProperties(
            zoneId: zoneId,
            name: nil,
            networkZoneId: "private",
            networkTypeId: "generic",
            riskReductionEnabled: true,
            riskReductionPercent: 200
        )

        #expect(session.errorMessage == "Risk reduction must be between 0 and 100 per cent.")
        #expect(session.canvas.zones.first?.riskReductionPercent == 20)
    }
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'Failing tests|\*\* TEST' -A3 | head -8
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add threatmodeller threatmodellerTests
git commit -m "feat: add the zone panel and the node's zone badge

The panel is a bar under the canvas, so it pushes the canvas up rather than
covering it, and every control writes through SetZoneProperties. A node shows
the zone holding it, because the containment rule is otherwise invisible."
```

---

### Task 19: The user interface journey

**Files:**
- Modify: `threatmodellerUITests/threatmodellerUITests.swift`

**Interfaces:**
- Consumes: the identifiers `category-aws-compute`, `technology-aws-ec2`, `node-aws-ec2`, `draw-zone`, `canvas`.
- Produces: nothing.

WARNING: an identifier on a SwiftUI container overwrites the identifier of every element inside it, and a view built from several texts reports each text separately. Query by identifier across every element kind: `app.descendants(matching: .any)["…"]`.

- [ ] **Step 1: Extend the journey**

Add to `threatmodellerUITests/threatmodellerUITests.swift`, after the existing threat assertions in the journey test:

```swift
        // Draw a zone around the node, and read the threat the zone raises.
        mark("turning on the zone drawing mode")
        let drawZone = app.descendants(matching: .any)["draw-zone"].firstMatch
        XCTAssertTrue(
            drawZone.waitForExistence(timeout: 5),
            "The 'Draw zone' control never appeared in the canvas toolbar."
        )
        drawZone.click()

        mark("dragging a zone across the canvas")
        let canvas = app.descendants(matching: .any)["canvas"].firstMatch
        XCTAssertTrue(canvas.exists, "The canvas background was not found.")
        canvas.coordinate(withNormalizedOffset: CGVector(dx: 0.05, dy: 0.05))
            .press(
                forDuration: 0.2,
                thenDragTo: canvas.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.85))
            )

        // The zone captures the node, so the zone's own threats appear.
        XCTAssertTrue(
            app.staticTexts["Lateral Movement"].firstMatch.waitForExistence(timeout: 10),
            "Drawing a zone did not raise the zone's own threats."
        )
        mark("zone threats shown")
```

WARNING: the vendored catalogue is what the app runs on, not the fixture, so the threat name here is the real one. `lateral-movement` is in the vendored data with the name "Lateral Movement".

- [ ] **Step 2: Run the user interface suite**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller \
    -destination 'platform=macOS' -only-testing:threatmodellerUITests test 2>&1 | grep -E 'error:|Failing tests|\*\* TEST' -A3 | head -12
```

Expected: PASS.

WARNING: if the drag does not draw a zone, dump the tree with `print(app.debugDescription)` at that point and read which element the coordinates landed on, rather than guessing at the offsets. Remove the dump before committing.

- [ ] **Step 3: Run every suite**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && time swift test 2>&1 | tail -5
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'Failing tests|\*\* TEST' -A3 | head -8
```

Expected: PASS, package suite under 30 seconds.

- [ ] **Step 4: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add threatmodellerUITests
git commit -m "test: walk the journey as far as a drawn zone

The journey now turns on the zone drawing mode, drags a zone across the
canvas, and reads the threat the zone raises."
```

---

## Milestone complete

Check every line before you call the milestone done:

- [ ] `swift test` from `ThreatModelKit/` is green and runs in under 30 seconds.
- [ ] `xcodebuild ... test` is green, including the user interface suite.
- [ ] `CanvasView.swift` holds layout only; gestures are in `CanvasGestures.swift` and hit testing in `CanvasHitTest.swift`.
- [ ] Zone membership is stored nowhere. `grep -rn 'zoneId' ThreatModelKit/Sources/ThreatModelKit/modelling/domain/` finds nothing.
- [ ] The header height and the component footprint are each stated once, in the core.
- [ ] The catalogue tag is still `v1.0.1`.
- [ ] Drawing a zone around a component lowers that component's scores.
- [ ] A public zone lowers nothing and raises nothing.
- [ ] A private zone raises its own threats once, scored against internal data and reduced by its own percentage.
- [ ] A link is lowered only when both ends are inside private zones, and takes the lower of the two reductions.
- [ ] Moving the component out, moving the zone away, and removing the zone each restore the original scores.
- [ ] Dragging a zone's header moves it; dragging a grip resizes it; neither can shrink it below the minimum.
- [ ] Escape leaves the zone drawing mode before it clears the selection.
- [ ] The delete key removes a selected zone and leaves its components.
- [ ] A node shows the name of the zone holding it.

Then write `docs/superpowers/specs/MILESTONE-4-CARRY-FORWARD.md` recording what Milestone 3 deliberately deferred, and start the Milestone 4 plan.

Still deferred, with the trigger unchanged:

- `ThreatModelGateway` has no atomic append. Every caller is synchronous and main-actor isolated.
- Three catalogue faults tied to a tag bump: the dangling threat id dropped by `compactMap`, the trap on a duplicate technology id, and the fake disagreeing with the real gateway on a duplicate id.
- `IdentityGenerator` and `ThreatModelGateway` still have no shared contract.
- `ThreatModelSession` still fixes `sensitivity: "internal"`.
- `ContentView` shows `String(describing: error)` when the catalogue fails to load.
- The palette has no keyboard path; pan needs the Command key; zoom needs a pinch or a button.
- The canvas draws in a fixed 20000 point square.
- The anchor pair and the path sampling are recomputed on every draw and are unmeasured.
- No user interface test covers node drag, marquee, connection drawing, delete, or zone resize.
