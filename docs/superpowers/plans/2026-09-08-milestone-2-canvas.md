# Milestone 2: Canvas — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The user drags technologies onto a diagram canvas, moves them, connects them, selects them with clicks and a marquee, deletes them, and sees the connection threats each link raises with correct risk scores and a TLS-mitigated flag.

**Architecture:** The core gains one read use case (`ViewThreatModel`) and four write use cases (`ConnectComponents`, `MoveComponents`, `RemoveComponents`, `RemoveConnection`). `AssessThreatModel` learns connection threats and reports the source of every threat through an enum. The app target gains five plain geometry structs with no SwiftUI import, one `CanvasState` observable holding only transient interaction state, and the canvas views. `ThreatModelSession` keeps its Milestone 1 job: call use cases, publish responses.

**Tech Stack:** Swift 6.3 (Swift 6 language mode in the package **and now the app target**), Swift Package Manager, Swift Testing, SwiftUI, macOS 26.

**Spec:** `docs/superpowers/specs/2026-09-07-native-macos-threat-modeller-design.md`

**Carry-forward:** `docs/superpowers/specs/MILESTONE-2-CARRY-FORWARD.md`

**Read Task 13 before starting Task 3.** Task 13 is the acceptance test — the outer loop. Swift cannot compile a test that names types which do not yet exist, so it is written after the types, but Tasks 3–12 exist to make it pass. Read it first so you know what you are building towards.

## Global Constraints

- Minimum deployment target: macOS 26. The package declares `platforms: [.macOS(.v26)]`.
- Package manifest uses `// swift-tools-version: 6.2`, which selects Swift 6 language mode.
- From Task 1 the app target also builds in Swift 6 language mode: `SWIFT_VERSION = 6.0` in all six build configurations.
- `ThreatModelKit` (the core target) must not `import SwiftUI`, `import AppKit`, `import CoreGraphics`, or read from disk. It may `import Foundation` for value types only.
- Domain objects never cross a use case boundary. Every `Request` and `Response` type contains only `String`, `Int`, `Double`, `Bool`, arrays, enums of those, and other Response structs.
- Use cases take collaborators in `init` and the request in `execute`. One use case per file. Protocol named `<Name>UseCase`, concrete type named `<Name>`.
- Gateways accept and return Domain objects. The only non-Domain values crossing a gateway boundary are identifiers used to locate data.
- Catalogue pinned at `jib1337/threat-model-library` tag **v1.0.1**. Do not raise the tag in this milestone.
- Severity ranks come from the order of `taxonomy.json` `severities`: low=1, medium=2, high=3, critical=4.
- Data sensitivity ranks are application-owned: public=1, internal=2, confidential=3, restricted=4.
- Risk score = severity rank × sensitivity rank. Risk level: `>= 12` critical, `>= 8` high, `>= 4` medium, otherwise low.
- A connection's sensitivity is the higher of its two endpoints' sensitivities.
- The TLS-mitigated flag is for display. It never changes a risk score.
- Zone multipliers are 1.0 throughout this milestone. Zones arrive in Milestone 3.
- Bundle identifier stays `uk.craigbass.threatmodeller`.
- Commit after every task. Never commit a red suite.

## Out of scope for this milestone

Zones, pathway mitigations, severity overrides, implemented controls, undo/redo, documents, copy/paste/duplicate, custom technologies, external actors, exports, samples, threat cards grouped by source, connection labels, the component property panel, `RenameComponent`, `SetComponentSensitivity` and `DisableComponentThreats`. Do not add gateway methods or Response fields for them.

`ThreatModelGateway` still has no atomic append. Carry-forward item 5 stays deferred: every caller in this milestone is synchronous and runs on the main actor, so the recorded trigger has not fired. Add the atomic append operation before any caller becomes asynchronous, or in Milestone 6 when documents open concurrently, whichever is first.

Carry-forward items 6, 7 and 8 are tied to a catalogue tag bump. The tag stays `v1.0.1`, so they are not in this milestone.

## File Structure

**Created:**

| Path | Responsibility |
|---|---|
| `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift` | The use case set a delivery mechanism may call |
| `.../ThreatModelKit/modelling/domain/ModellingIdentifiers.swift` | `ComponentId`, `ConnectionId` |
| `.../ThreatModelKit/modelling/domain/Connection.swift` | `Connection` |
| `.../ThreatModelKit/modelling/usecase/ViewThreatModel.swift` | `ViewThreatModel`, `ViewedComponent`, `ViewedConnection` |
| `.../ThreatModelKit/modelling/usecase/ConnectComponents.swift` | `ConnectComponents` and its Request/Response |
| `.../ThreatModelKit/modelling/usecase/MoveComponents.swift` | `MoveComponents`, `ComponentMove` |
| `.../ThreatModelKit/modelling/usecase/RemoveComponents.swift` | `RemoveComponents` and its Request/Response |
| `.../ThreatModelKit/modelling/usecase/RemoveConnection.swift` | `RemoveConnection` and its Request/Response |
| `.../ThreatModelKit/assessment/domain/SensitivityLadder.swift` | Higher of two sensitivities |
| `.../ThreatModelKit/assessment/domain/ConnectionEncryption.swift` | Which connection threats TLS mitigates |
| `ThreatModelKit/Tests/UnitTests/ConnectionTests.swift` | Modelling domain values |
| `ThreatModelKit/Tests/UnitTests/ViewThreatModelTests.swift` | The read use case |
| `ThreatModelKit/Tests/UnitTests/ConnectComponentsTests.swift` | Connection rules |
| `ThreatModelKit/Tests/UnitTests/MoveComponentsTests.swift` | Move rules |
| `ThreatModelKit/Tests/UnitTests/RemoveComponentsTests.swift` | Removal and its cascade |
| `ThreatModelKit/Tests/UnitTests/RemoveConnectionTests.swift` | Connection removal |
| `ThreatModelKit/Tests/UnitTests/SensitivityLadderTests.swift` | Sensitivity ladder |
| `ThreatModelKit/Tests/UnitTests/ConnectionEncryptionTests.swift` | TLS flag |
| `ThreatModelKit/Tests/AcceptanceTests/ConnectingComponentsTests.swift` | The milestone's outer loop |
| `threatmodeller/canvas/CanvasTransform.swift` | Model and view coordinates, zoom clamping |
| `threatmodeller/canvas/ComponentBox.swift` | The rectangle a component occupies |
| `threatmodeller/canvas/AnchorGeometry.swift` | `ConnectionAnchor`, anchor points, nearest pair |
| `threatmodeller/canvas/ConnectionPath.swift` | Bezier, arrowhead, click hit test |
| `threatmodeller/canvas/MarqueeSelection.swift` | Marquee rectangle and intersection |
| `threatmodeller/canvas/CanvasState.swift` | Pan, zoom, selection, drags in flight |
| `threatmodeller/canvas/CanvasView.swift` | The canvas and its gestures |
| `threatmodeller/canvas/ComponentNodeView.swift` | One component and its anchor handles |
| `threatmodeller/canvas/ConnectionsLayer.swift` | Every connection drawn in one `Canvas` pass |
| `threatmodellerTests/canvas/CanvasTransformTests.swift` | Geometry |
| `threatmodellerTests/canvas/ComponentBoxTests.swift` | Geometry |
| `threatmodellerTests/canvas/AnchorGeometryTests.swift` | Geometry |
| `threatmodellerTests/canvas/ConnectionPathTests.swift` | Geometry |
| `threatmodellerTests/canvas/MarqueeSelectionTests.swift` | Geometry |
| `threatmodellerTests/canvas/CanvasStateTests.swift` | Selection and cancel rules |

**Modified:**

- `threatmodeller.xcodeproj/project.pbxproj` — Swift 6 language mode; link `TestSupport` into `threatmodellerTests`
- `ThreatModelKit/Package.swift` — publish `TestSupport` as a product
- `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Component.swift` — `ComponentId` moves out
- `.../modelling/domain/ThreatModel.swift` — gains `connections` and `component(_:)`
- `.../catalogue/gateway/TechnologyCatalogue.swift` — gains `connectionThreats()`
- `.../assessment/usecase/AssessThreatModel.swift` — source enum, connection threats, TLS flag, deduplication
- `ThreatModelKit/Sources/CatalogueGateways/BundledTechnologyCatalogue.swift` — `connectionThreats()`
- `ThreatModelKit/Sources/TestSupport/InMemoryTechnologyCatalogue.swift` — `connectionThreats()`
- `ThreatModelKit/Sources/TestSupport/CatalogueFixture.swift` — two connection threats
- `ThreatModelKit/Sources/TestSupport/TechnologyCatalogueContract.swift` — connection threat clauses
- `ThreatModelKit/Sources/TestSupport/TestDependencies.swift` — conforms to `UseCaseFactory`, vends the new use cases
- `ThreatModelKit/Tests/UnitTests/AssessThreatModelTests.swift` — source enum, connection cases
- `ThreatModelKit/Tests/AcceptanceTests/BuildingAThreatModelTests.swift` — source enum
- `ThreatModelKit/Tests/GatewayIntegrationTests/BundledTechnologyCatalogueTests.swift` — connection threat ids
- `threatmodeller/Dependencies.swift` — the local protocol goes; vends the new use cases
- `threatmodeller/ThreatModelSession.swift` — `@MainActor`, publishes the canvas, one method per new use case
- `threatmodeller/ContentView.swift` — three columns, the canvas, the source enum
- `threatmodellerTests/threatmodellerTests.swift` — runs on `TestDependencies`
- `threatmodellerUITests/threatmodellerUITests.swift` — template leftovers deleted, journey extended to the canvas

**Deleted:**

- `threatmodellerUITests/threatmodellerUITestsLaunchTests.swift` — template leftover

---

### Task 1: Swift 6 language mode for the app target

Closes carry-forward item 1. The package already builds in Swift 6 language mode; the app target does not, so the delivery mechanism gets no data-race checking. Do this before writing any new app code, so every later task is checked.

**Files:**
- Modify: `threatmodeller.xcodeproj/project.pbxproj` (six `SWIFT_VERSION` lines)
- Modify: `threatmodeller/ThreatModelSession.swift`

**Interfaces:**
- Consumes: nothing.
- Produces: an app target that compiles under Swift 6 language mode; `ThreatModelSession` is `@MainActor`.

- [ ] **Step 1: Record the starting state**

```bash
cd /Users/craigjbass/Projects/threat-modeller
grep -c 'SWIFT_VERSION = 5.0;' threatmodeller.xcodeproj/project.pbxproj
```

Expected: `6`

- [ ] **Step 2: Switch every configuration to Swift 6**

```bash
cd /Users/craigjbass/Projects/threat-modeller
sed -i '' 's/SWIFT_VERSION = 5\.0;/SWIFT_VERSION = 6.0;/g' threatmodeller.xcodeproj/project.pbxproj
grep -c 'SWIFT_VERSION = 6.0;' threatmodeller.xcodeproj/project.pbxproj
```

Expected: `6`

- [ ] **Step 3: Build and read the errors**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' build 2>&1 | grep -E 'error:|warning: .*concurrency' | head -20
```

Expected: errors about `ThreatModelSession` being used from the main actor while not itself isolated. The `App` and `View` types are already `@MainActor` because SwiftUI declares them so.

- [ ] **Step 4: Isolate the session to the main actor**

Every caller of `ThreatModelSession` is a SwiftUI view, and SwiftUI views are main-actor isolated. Marking the class matches where it already runs.

Replace the declaration in `threatmodeller/ThreatModelSession.swift`:

```swift
import Observation
import ThreatModelKit

/// Translates user intent into use case calls and publishes the responses.
/// Holds no business rules and names no gateway.
///
/// Main-actor isolated: every caller is a SwiftUI view, and the use cases it
/// calls are synchronous. `ThreatModelGateway` has no atomic append, so a
/// second concurrent caller would lose a change; the isolation keeps that
/// impossible while the port stays as it is.
@MainActor
@Observable
final class ThreatModelSession {
```

Leave the rest of the file as it is.

- [ ] **Step 5: Build again**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' build 2>&1 | grep -E 'error:' | head -20
```

Expected: no output. If an error remains, read it and isolate the named type to the main actor as well. Do not silence an error with `@unchecked Sendable` or `nonisolated(unsafe)`.

- [ ] **Step 6: Run every suite**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -5
cd /Users/craigjbass/Projects/threat-modeller && xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | tail -5
```

Expected: both green. The app unit tests still read the vendored catalogue at this point; Task 2 changes that.

- [ ] **Step 7: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add threatmodeller.xcodeproj/project.pbxproj threatmodeller/ThreatModelSession.swift
git commit -m "build: build the app target in Swift 6 language mode

The package ran Swift 6 language mode while the app target ran Swift 5, so
the delivery mechanism got no data-race checking. ThreatModelSession becomes
main-actor isolated, which is where every SwiftUI caller already runs."
```

---

### Task 2: `UseCaseFactory` moves into the core

Closes carry-forward items 2 and 3. Today `UseCaseFactory` lives in the app target, so `TestDependencies` cannot conform to it and two composition roots vend the same use cases with nothing keeping them in step. Milestone 2 adds five use cases, so fix this first.

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`
- Modify: `ThreatModelKit/Package.swift`
- Modify: `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`
- Modify: `threatmodeller/Dependencies.swift`
- Modify: `threatmodeller.xcodeproj/project.pbxproj`
- Modify: `threatmodellerTests/threatmodellerTests.swift`

**Interfaces:**
- Consumes: `ListTechnologiesUseCase`, `AddComponentUseCase`, `AssessThreatModelUseCase` from Milestone 1.
- Produces: `public protocol UseCaseFactory` in `ThreatModelKit`; `TestDependencies: UseCaseFactory`; `Dependencies: UseCaseFactory`; a `TestSupport` package product linkable from the Xcode test target.

- [ ] **Step 1: Write the failing test**

Replace the whole of `threatmodellerTests/threatmodellerTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The session is the delivery mechanism's translator. These tests run it on
/// the fake catalogue, not the vendored one: a catalogue update must never
/// break a delivery-mechanism test.
@MainActor
struct ThreatModelSessionTests {
    private func session() -> ThreatModelSession {
        ThreatModelSession(useCases: TestDependencies())
    }

    @Test func loadsThePaletteOnLaunch() {
        let session = session()

        #expect(session.palette.map(\.id) == ["aws", "gcp"])
        #expect(session.threats.isEmpty)
    }

    @Test func raisesScoredThreatsWhenATechnologyIsAdded() {
        let session = session()

        session.add(technologyId: "aws-ec2")

        #expect(session.threats.map(\.threatId) == [
            "credential-theft",
            "misconfiguration",
            "dos-attack"
        ])
        #expect(session.threats.first?.riskScore == 8)
        #expect(session.threats.first?.riskLevel == "high")
        #expect(session.errorMessage == nil)
    }

    @Test func reportsATechnologyThatIsNotInTheCatalogue() {
        let session = session()

        session.add(technologyId: "aws-imaginary")

        #expect(session.threats.isEmpty)
        #expect(session.errorMessage == "That technology is not in the catalogue.")
    }
}
```

The session adds at sensitivity `internal`, rank 2. `credential-theft` is critical, rank 4, so 4 × 2 = 8, which is `high`.

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'error:' | head -5
```

Expected: FAIL with `no such module 'TestSupport'`.

- [ ] **Step 3: Publish `TestSupport` as a package product**

In `ThreatModelKit/Package.swift`, replace the `products:` array:

```swift
    products: [
        .library(name: "ThreatModelKit", targets: ["ThreatModelKit", "CatalogueGateways"]),
        // Published so the Xcode app test target can build the same fakes and
        // the same composition root the package's own tests use.
        .library(name: "TestSupport", targets: ["TestSupport"])
    ],
```

- [ ] **Step 4: Write the protocol into the core**

Create `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`:

```swift
/// The set of use cases a delivery mechanism may call.
///
/// Two composition roots conform: `Dependencies` in the application, wired to
/// real gateways, and `TestDependencies` in `TestSupport`, wired to fakes.
/// The protocol keeps the two in step. A use case added here does not compile
/// until both roots vend it.
public protocol UseCaseFactory {
    func listTechnologies() -> ListTechnologiesUseCase
    func viewThreatModel() -> ViewThreatModelUseCase
    func addComponent() -> AddComponentUseCase
    func moveComponents() -> MoveComponentsUseCase
    func removeComponents() -> RemoveComponentsUseCase
    func connectComponents() -> ConnectComponentsUseCase
    func removeConnection() -> RemoveConnectionUseCase
    func assessThreatModel() -> AssessThreatModelUseCase
}
```

WARNING: this file names five use cases that Tasks 4–8 create. It will not compile yet. Write only the three that exist now, and add one line per use case as each task lands:

```swift
public protocol UseCaseFactory {
    func listTechnologies() -> ListTechnologiesUseCase
    func addComponent() -> AddComponentUseCase
    func assessThreatModel() -> AssessThreatModelUseCase
}
```

Each of Tasks 4–8 adds its own line, its own `Dependencies` method and its own `TestDependencies` method.

- [ ] **Step 5: Conform `TestDependencies`**

In `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`, change the declaration line only:

```swift
public final class TestDependencies: UseCaseFactory {
```

- [ ] **Step 6: Conform `Dependencies` and delete the local protocol**

Replace the top of `threatmodeller/Dependencies.swift`, removing the local `protocol UseCaseFactory` block entirely:

```swift
import CatalogueGateways
import ThreatModelKit

/// The composition root. One graph per open model; from Milestone 6 that means
/// one per document window. `UseCaseFactory` lives in the core so this root and
/// `TestDependencies` cannot drift apart.
final class Dependencies: UseCaseFactory {
```

Leave the body as it is.

- [ ] **Step 7: Link `TestSupport` into the app test target**

This edits `project.pbxproj`, which is `objectVersion = 77`. Run this script exactly; it matches the identifiers Milestone 1 wrote.

```bash
cd /Users/craigjbass/Projects/threat-modeller
python3 - threatmodeller.xcodeproj/project.pbxproj <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()

BUILDFILE = "A0000000000000000000006"
PRODUCT   = "A0000000000000000000007"

assert BUILDFILE not in s, "TestSupport is already linked"

s = s.replace(
    "\t\tA0000000000000000000004 /* ThreatModelKit in Frameworks */ = {isa = PBXBuildFile; productRef = A0000000000000000000005 /* ThreatModelKit */; };",
    "\t\tA0000000000000000000004 /* ThreatModelKit in Frameworks */ = {isa = PBXBuildFile; productRef = A0000000000000000000005 /* ThreatModelKit */; };\n"
    "\t\t%s /* TestSupport in Frameworks */ = {isa = PBXBuildFile; productRef = %s /* TestSupport */; };" % (BUILDFILE, PRODUCT),
    1)

s = s.replace(
    "\t\t\t\tA0000000000000000000004 /* ThreatModelKit in Frameworks */,",
    "\t\t\t\tA0000000000000000000004 /* ThreatModelKit in Frameworks */,\n"
    "\t\t\t\t%s /* TestSupport in Frameworks */," % BUILDFILE,
    1)

s = s.replace(
    "\t\t\t\tA0000000000000000000005 /* ThreatModelKit */,",
    "\t\t\t\tA0000000000000000000005 /* ThreatModelKit */,\n"
    "\t\t\t\t%s /* TestSupport */," % PRODUCT,
    1)

s = s.replace(
    "\t\tA0000000000000000000005 /* ThreatModelKit */ = {\n\t\t\tisa = XCSwiftPackageProductDependency;\n\t\t\tproductName = ThreatModelKit;\n\t\t};",
    "\t\tA0000000000000000000005 /* ThreatModelKit */ = {\n\t\t\tisa = XCSwiftPackageProductDependency;\n\t\t\tproductName = ThreatModelKit;\n\t\t};\n"
    "\t\t%s /* TestSupport */ = {\n\t\t\tisa = XCSwiftPackageProductDependency;\n\t\t\tproductName = TestSupport;\n\t\t};" % PRODUCT,
    1)

for token in (BUILDFILE, PRODUCT):
    assert s.count(token) >= 2, "edit did not apply for " + token

open(p, "w").write(s)
print("linked TestSupport into threatmodellerTests")
PY
```

- [ ] **Step 8: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
cd /Users/craigjbass/Projects/threat-modeller && xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | tail -5
```

Expected: PASS. The app unit tests no longer read the vendored catalogue, so the pinned catalogue numbers are gone.

- [ ] **Step 9: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit/Package.swift \
        ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift \
        ThreatModelKit/Sources/TestSupport/TestDependencies.swift \
        threatmodeller/Dependencies.swift \
        threatmodeller.xcodeproj/project.pbxproj \
        threatmodellerTests/threatmodellerTests.swift
git commit -m "refactor: move UseCaseFactory into the core

TestDependencies could not conform to a protocol that lived in the app
target, so two composition roots vended the same use cases with nothing
keeping them in step. The protocol moves to ThreatModelKit and both roots
conform. The app unit tests now build TestDependencies, so a catalogue
update no longer breaks them."
```

---

### Task 3: Modelling identifiers, `Connection`, and the aggregate

Splits `ComponentId` out of `Component.swift` before `ConnectionId` arrives, which closes a carry-forward item, and gives the aggregate its connections.

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/ModellingIdentifiers.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Connection.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Component.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/ThreatModel.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ConnectionTests.swift`

**Interfaces:**
- Consumes: `TechnologyId`, `Point`, `DataSensitivity` from Milestone 1.
- Produces: `ComponentId`, `ConnectionId`, `Connection(id:source:target:)`, `Connection.touches(_:) -> Bool`, `ThreatModel(name:components:connections:)`, `ThreatModel.component(_: ComponentId) -> Component?`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/ConnectionTests.swift`:

```swift
import Testing
import ThreatModelKit

struct ConnectionTests {
    private let a = ComponentId("a")
    private let b = ComponentId("b")
    private let c = ComponentId("c")

    private func component(_ id: ComponentId) -> Component {
        Component(
            id: id,
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData
        )
    }

    @Test func touchesBothOfItsEnds() {
        let connection = Connection(id: ConnectionId("k1"), source: a, target: b)

        #expect(connection.touches(a))
        #expect(connection.touches(b))
        #expect(connection.touches(c) == false)
    }

    @Test func aReversedPairIsADifferentConnection() {
        let forward = Connection(id: ConnectionId("k1"), source: a, target: b)
        let backward = Connection(id: ConnectionId("k1"), source: b, target: a)

        #expect(forward != backward)
    }

    @Test func anEmptyModelCarriesNoConnections() {
        #expect(ThreatModel().connections.isEmpty)
    }

    @Test func findsAComponentById() {
        let model = ThreatModel(components: [component(a)])

        #expect(model.component(a)?.id == a)
        #expect(model.component(b) == nil)
    }

    @Test func holdsTheConnectionsItWasBuiltWith() {
        let model = ThreatModel(
            components: [component(a), component(b)],
            connections: [Connection(id: ConnectionId("k1"), source: a, target: b)]
        )

        #expect(model.connections.map(\.id.value) == ["k1"])
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter ConnectionTests 2>&1 | grep -E 'error:' | head -5
```

Expected: FAIL with `cannot find 'Connection' in scope`.

- [ ] **Step 3: Create the modelling identifiers file**

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/ModellingIdentifiers.swift`:

```swift
public struct ComponentId: Hashable, Sendable, CustomStringConvertible {
    public let value: String
    public init(_ value: String) { self.value = value }
    public var description: String { value }
}

public struct ConnectionId: Hashable, Sendable, CustomStringConvertible {
    public let value: String
    public init(_ value: String) { self.value = value }
    public var description: String { value }
}
```

- [ ] **Step 4: Remove `ComponentId` from `Component.swift`**

Delete the `ComponentId` declaration at the top of `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Component.swift`, so the file starts at `public struct Component: Equatable, Sendable {`. Change nothing else in the file.

- [ ] **Step 5: Create `Connection`**

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/Connection.swift`:

```swift
/// A directed link from one component to another.
///
/// The canvas draws an arrowhead at `target`. A component never links to
/// itself, and one source and target pair carries at most one connection.
/// A link in the opposite direction is a separate connection.
/// `ConnectComponents` enforces all three rules.
public struct Connection: Equatable, Sendable {
    public let id: ConnectionId
    public let source: ComponentId
    public let target: ComponentId

    public init(id: ConnectionId, source: ComponentId, target: ComponentId) {
        self.id = id
        self.source = source
        self.target = target
    }

    /// True when the component is either end of this connection.
    /// `RemoveComponents` uses it to cascade, `AssessThreatModel` to find the
    /// endpoints of a link.
    public func touches(_ componentId: ComponentId) -> Bool {
        source == componentId || target == componentId
    }
}
```

- [ ] **Step 6: Give the aggregate its connections**

Replace the whole of `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/ThreatModel.swift`:

```swift
/// The aggregate a threat model is assessed from. Zones, overrides and
/// implemented controls join it in later milestones.
public struct ThreatModel: Equatable, Sendable {
    public var name: String
    public var components: [Component]
    public var connections: [Connection]

    public init(
        name: String = "Untitled",
        components: [Component] = [],
        connections: [Connection] = []
    ) {
        self.name = name
        self.components = components
        self.connections = connections
    }

    /// The component with that identifier, or nil. Every write use case checks
    /// a component exists before it changes anything.
    public func component(_ id: ComponentId) -> Component? {
        components.first { $0.id == id }
    }
}
```

- [ ] **Step 7: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit/Sources/ThreatModelKit/modelling/domain ThreatModelKit/Tests/UnitTests/ConnectionTests.swift
git commit -m "feat: add Connection to the modelling domain

ComponentId moves out of Component.swift and joins ConnectionId in
Identifiers.swift, matching how the catalogue ids are held. The aggregate
gains its connections and a lookup by component id."
```

---

### Task 4: `ViewThreatModel`

Spec §9 says the session publishes a canvas snapshot, and spec §3.4 forbids the delivery mechanism from naming a gateway. This read use case supplies the snapshot.

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/ViewThreatModel.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`
- Modify: `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`
- Modify: `threatmodeller/Dependencies.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ViewThreatModelTests.swift`

**Interfaces:**
- Consumes: `ThreatModelGateway`, `TechnologyCatalogue`, `Connection`, `ThreatModel.component(_:)`.
- Produces: `ViewThreatModelUseCase`, `ViewThreatModelRequest()`, `ViewThreatModelResponse(name:components:connections:)`, `ViewedComponent(id:technologyId:name:providerId:categoryId:x:y:sensitivityId:threatsDisabled:isUnknownTechnology:)`, `ViewedConnection(id:sourceComponentId:targetComponentId:)`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/ViewThreatModelTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct ViewThreatModelTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func view(_ model: ThreatModel) -> ViewThreatModelResponse {
        ViewThreatModel(models: InMemoryThreatModelGateway(model), catalogue: catalogue)
            .execute(ViewThreatModelRequest())
    }

    private func component(
        _ id: String,
        technologyId: String = "aws-ec2",
        x: Double = 0,
        y: Double = 0,
        customName: String? = nil,
        threatsDisabled: Bool = false
    ) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId(technologyId),
            position: Point(x: x, y: y),
            sensitivity: .confidential,
            customName: customName,
            threatsDisabled: threatsDisabled
        )
    }

    @Test func showsAnEmptyModel() {
        let response = view(ThreatModel())

        #expect(response.name == "Untitled")
        #expect(response.components.isEmpty)
        #expect(response.connections.isEmpty)
    }

    @Test func describesAComponentForDrawing() throws {
        let response = view(ThreatModel(components: [component("c1", x: 120, y: 40)]))

        let drawn = try #require(response.components.first)
        #expect(drawn.id == "c1")
        #expect(drawn.technologyId == "aws-ec2")
        #expect(drawn.name == "EC2")
        #expect(drawn.providerId == "aws")
        #expect(drawn.categoryId == "compute")
        #expect(drawn.x == 120)
        #expect(drawn.y == 40)
        #expect(drawn.sensitivityId == "confidential")
        #expect(drawn.threatsDisabled == false)
        #expect(drawn.isUnknownTechnology == false)
    }

    @Test func prefersTheUsersOwnNameForAComponent() throws {
        let response = view(ThreatModel(components: [component("c1", customName: "Web tier")]))

        #expect(try #require(response.components.first).name == "Web tier")
    }

    @Test func stillDrawsAComponentWhoseTechnologyLeftTheCatalogue() throws {
        let response = view(ThreatModel(components: [component("c1", technologyId: "aws-retired")]))

        let drawn = try #require(response.components.first)
        #expect(drawn.name == "aws-retired")
        #expect(drawn.providerId == "")
        #expect(drawn.categoryId == "")
        #expect(drawn.isUnknownTechnology)
    }

    @Test func listsConnectionsInModelOrder() {
        let response = view(
            ThreatModel(
                components: [component("c1"), component("c2"), component("c3")],
                connections: [
                    Connection(id: ConnectionId("k2"), source: ComponentId("c2"), target: ComponentId("c3")),
                    Connection(id: ConnectionId("k1"), source: ComponentId("c1"), target: ComponentId("c2"))
                ]
            )
        )

        #expect(response.connections.map(\.id) == ["k2", "k1"])
        #expect(response.connections.first?.sourceComponentId == "c2")
        #expect(response.connections.first?.targetComponentId == "c3")
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter ViewThreatModelTests 2>&1 | grep -E 'error:' | head -5
```

Expected: FAIL with `cannot find 'ViewThreatModel' in scope`.

- [ ] **Step 3: Write the use case**

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/ViewThreatModel.swift`:

```swift
public protocol ViewThreatModelUseCase {
    func execute(_ request: ViewThreatModelRequest) -> ViewThreatModelResponse
}

public struct ViewThreatModelRequest: Equatable, Sendable {
    public init() {}
}

public struct ViewedComponent: Equatable, Sendable {
    public let id: String
    public let technologyId: String
    /// The user's own name when they set one, else the technology's name, else
    /// the technology id when the catalogue no longer holds that technology.
    public let name: String
    /// Empty when the catalogue no longer holds the technology.
    public let providerId: String
    /// Empty when the catalogue no longer holds the technology.
    public let categoryId: String
    public let x: Double
    public let y: Double
    public let sensitivityId: String
    public let threatsDisabled: Bool
    /// True when the catalogue has no entry for `technologyId`. A model saved
    /// against an older catalogue can carry one. The canvas still draws it.
    public let isUnknownTechnology: Bool

    public init(
        id: String,
        technologyId: String,
        name: String,
        providerId: String,
        categoryId: String,
        x: Double,
        y: Double,
        sensitivityId: String,
        threatsDisabled: Bool,
        isUnknownTechnology: Bool
    ) {
        self.id = id
        self.technologyId = technologyId
        self.name = name
        self.providerId = providerId
        self.categoryId = categoryId
        self.x = x
        self.y = y
        self.sensitivityId = sensitivityId
        self.threatsDisabled = threatsDisabled
        self.isUnknownTechnology = isUnknownTechnology
    }
}

public struct ViewedConnection: Equatable, Sendable {
    public let id: String
    public let sourceComponentId: String
    public let targetComponentId: String

    public init(id: String, sourceComponentId: String, targetComponentId: String) {
        self.id = id
        self.sourceComponentId = sourceComponentId
        self.targetComponentId = targetComponentId
    }
}

public struct ViewThreatModelResponse: Equatable, Sendable {
    public let name: String
    public let components: [ViewedComponent]
    public let connections: [ViewedConnection]

    public init(name: String, components: [ViewedComponent], connections: [ViewedConnection]) {
        self.name = name
        self.components = components
        self.connections = connections
    }
}

/// Everything the canvas draws, as plain values. The canvas never reads a
/// gateway, so this use case supplies the drawing.
public struct ViewThreatModel: ViewThreatModelUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

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
                    isUnknownTechnology: technology == nil
                )
            },
            connections: model.connections.map {
                ViewedConnection(
                    id: $0.id.value,
                    sourceComponentId: $0.source.value,
                    targetComponentId: $0.target.value
                )
            }
        )
    }
}
```

- [ ] **Step 4: Vend it from both composition roots**

Add one line to the protocol in `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`, after `listTechnologies()`:

```swift
    func viewThreatModel() -> ViewThreatModelUseCase
```

Add to `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`:

```swift
    public func viewThreatModel() -> ViewThreatModelUseCase {
        ViewThreatModel(models: models, catalogue: catalogue)
    }
```

Add to `threatmodeller/Dependencies.swift`:

```swift
    func viewThreatModel() -> ViewThreatModelUseCase {
        ViewThreatModel(models: models, catalogue: catalogue)
    }
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
cd /Users/craigjbass/Projects/threat-modeller && xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' build 2>&1 | grep -E 'error:' | head -5
```

Expected: PASS, and no build errors.

- [ ] **Step 6: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit/Sources/ThreatModelKit ThreatModelKit/Sources/TestSupport/TestDependencies.swift \
        threatmodeller/Dependencies.swift ThreatModelKit/Tests/UnitTests/ViewThreatModelTests.swift
git commit -m "feat: add ViewThreatModel

The canvas needs the components and connections to draw, and may not read a
gateway. This read use case returns them as plain values, including a
fallback for a technology that has left the catalogue."
```

---

### Task 5: `ConnectComponents`

Enforces the connection rules recorded in spec §5.3.

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/ConnectComponents.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`
- Modify: `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`
- Modify: `threatmodeller/Dependencies.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ConnectComponentsTests.swift`

**Interfaces:**
- Consumes: `ThreatModelGateway`, `IdentityGenerator`, `Connection`, `ThreatModel.component(_:)`.
- Produces: `ConnectComponentsUseCase`, `ConnectComponentsRequest(sourceComponentId:targetComponentId:)`, `ConnectComponentsResponse` with cases `.connected(connectionId:)`, `.unknownComponent(componentId:)`, `.selfConnection`, `.duplicateConnection(connectionId:)`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/ConnectComponentsTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct ConnectComponentsTests {
    private let models = InMemoryThreatModelGateway(
        ThreatModel(components: [
            ConnectComponentsTests.component("c1"),
            ConnectComponentsTests.component("c2"),
            ConnectComponentsTests.component("c3")
        ])
    )
    private let ids = SequentialIdentityGenerator()

    private static func component(_ id: String) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData
        )
    }

    private func connect(_ source: String, _ target: String) -> ConnectComponentsResponse {
        ConnectComponents(models: models, ids: ids)
            .execute(ConnectComponentsRequest(sourceComponentId: source, targetComponentId: target))
    }

    private func view() -> ViewThreatModelResponse {
        ViewThreatModel(models: models, catalogue: CatalogueFixture.catalogue())
            .execute(ViewThreatModelRequest())
    }

    @Test func linksTwoComponents() {
        #expect(connect("c1", "c2") == .connected(connectionId: "id-1"))

        let connections = view().connections
        #expect(connections.map(\.id) == ["id-1"])
        #expect(connections.first?.sourceComponentId == "c1")
        #expect(connections.first?.targetComponentId == "c2")
    }

    @Test func refusesAComponentLinkedToItself() {
        #expect(connect("c1", "c1") == .selfConnection)
        #expect(view().connections.isEmpty)
    }

    @Test func refusesASecondLinkBetweenTheSamePairInTheSameDirection() {
        _ = connect("c1", "c2")

        #expect(connect("c1", "c2") == .duplicateConnection(connectionId: "id-1"))
        #expect(view().connections.count == 1)
    }

    @Test func allowsALinkBackTheOtherWay() {
        _ = connect("c1", "c2")

        #expect(connect("c2", "c1") == .connected(connectionId: "id-2"))
        #expect(view().connections.count == 2)
    }

    @Test func refusesASourceTheModelDoesNotHold() {
        #expect(connect("c9", "c2") == .unknownComponent(componentId: "c9"))
        #expect(view().connections.isEmpty)
    }

    @Test func refusesATargetTheModelDoesNotHold() {
        #expect(connect("c1", "c9") == .unknownComponent(componentId: "c9"))
        #expect(view().connections.isEmpty)
    }

    @Test func spendsNoIdentifierOnALinkItRefuses() {
        _ = connect("c1", "c1")
        _ = connect("c9", "c2")

        #expect(connect("c1", "c2") == .connected(connectionId: "id-1"))
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter ConnectComponentsTests 2>&1 | grep -E 'error:' | head -5
```

Expected: FAIL with `cannot find 'ConnectComponents' in scope`.

- [ ] **Step 3: Write the use case**

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/ConnectComponents.swift`:

```swift
public protocol ConnectComponentsUseCase {
    func execute(_ request: ConnectComponentsRequest) -> ConnectComponentsResponse
}

public struct ConnectComponentsRequest: Equatable, Sendable {
    public let sourceComponentId: String
    public let targetComponentId: String

    public init(sourceComponentId: String, targetComponentId: String) {
        self.sourceComponentId = sourceComponentId
        self.targetComponentId = targetComponentId
    }
}

public enum ConnectComponentsResponse: Equatable, Sendable {
    case connected(connectionId: String)
    case unknownComponent(componentId: String)
    case selfConnection
    /// The pair is already linked in this direction. Carries the identifier of
    /// the link that already exists, so the canvas can select it.
    case duplicateConnection(connectionId: String)
}

/// Links one component to another.
///
/// Both components must exist, a component may not link to itself, and one
/// source and target pair carries at most one link. A link back the other way
/// is a separate link and is allowed. The use case takes no identifier from
/// the generator until every rule passes.
public struct ConnectComponents: ConnectComponentsUseCase {
    private let models: ThreatModelGateway
    private let ids: IdentityGenerator

    public init(models: ThreatModelGateway, ids: IdentityGenerator) {
        self.models = models
        self.ids = ids
    }

    public func execute(_ request: ConnectComponentsRequest) -> ConnectComponentsResponse {
        let source = ComponentId(request.sourceComponentId)
        let target = ComponentId(request.targetComponentId)

        var model = models.current()

        guard model.component(source) != nil else {
            return .unknownComponent(componentId: source.value)
        }
        guard model.component(target) != nil else {
            return .unknownComponent(componentId: target.value)
        }
        guard source != target else {
            return .selfConnection
        }
        if let existing = model.connections.first(where: { $0.source == source && $0.target == target }) {
            return .duplicateConnection(connectionId: existing.id.value)
        }

        let connection = Connection(id: ConnectionId(ids.next()), source: source, target: target)
        model.connections.append(connection)
        models.save(model)

        return .connected(connectionId: connection.id.value)
    }
}
```

The existence checks run before the self-link check, so linking an unknown identifier to itself reports `.unknownComponent`.

- [ ] **Step 4: Vend it from both composition roots**

Add to `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`:

```swift
    func connectComponents() -> ConnectComponentsUseCase
```

Add to `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`:

```swift
    public func connectComponents() -> ConnectComponentsUseCase {
        ConnectComponents(models: models, ids: ids)
    }
```

Add to `threatmodeller/Dependencies.swift`:

```swift
    func connectComponents() -> ConnectComponentsUseCase {
        ConnectComponents(models: models, ids: ids)
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
git add ThreatModelKit/Sources threatmodeller/Dependencies.swift ThreatModelKit/Tests/UnitTests/ConnectComponentsTests.swift
git commit -m "feat: add ConnectComponents

A link is directed, a component may not link to itself, and a pair carries
at most one link in one direction. A link back the other way is separate."
```

---

### Task 6: `MoveComponents`

A completed drag moves the whole selection. Positions are absolute, so calling the use case twice with the same request gives the same model.

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/MoveComponents.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`
- Modify: `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`
- Modify: `threatmodeller/Dependencies.swift`
- Test: `ThreatModelKit/Tests/UnitTests/MoveComponentsTests.swift`

**Interfaces:**
- Consumes: `ThreatModelGateway`, `Point`, `ThreatModel.component(_:)`.
- Produces: `MoveComponentsUseCase`, `ComponentMove(componentId:x:y:)`, `MoveComponentsRequest(moves:)`, `MoveComponentsResponse` with cases `.moved(count:)` and `.unknownComponent(componentId:)`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/MoveComponentsTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct MoveComponentsTests {
    private let models = InMemoryThreatModelGateway(
        ThreatModel(components: [
            MoveComponentsTests.component("c1"),
            MoveComponentsTests.component("c2")
        ])
    )

    private static func component(_ id: String) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData
        )
    }

    private func move(_ moves: [ComponentMove]) -> MoveComponentsResponse {
        MoveComponents(models: models).execute(MoveComponentsRequest(moves: moves))
    }

    private func positions() -> [String: Point] {
        var found: [String: Point] = [:]
        for component in models.current().components {
            found[component.id.value] = component.position
        }
        return found
    }

    @Test func movesOneComponent() {
        #expect(move([ComponentMove(componentId: "c1", x: 120, y: 40)]) == .moved(count: 1))

        #expect(positions()["c1"] == Point(x: 120, y: 40))
        #expect(positions()["c2"] == Point(x: 0, y: 0))
    }

    @Test func movesEveryComponentInTheRequest() {
        let response = move([
            ComponentMove(componentId: "c1", x: 10, y: 20),
            ComponentMove(componentId: "c2", x: 30, y: 40)
        ])

        #expect(response == .moved(count: 2))
        #expect(positions()["c1"] == Point(x: 10, y: 20))
        #expect(positions()["c2"] == Point(x: 30, y: 40))
    }

    @Test func movesNothingWhenOneComponentIsUnknown() {
        let response = move([
            ComponentMove(componentId: "c1", x: 10, y: 20),
            ComponentMove(componentId: "c9", x: 30, y: 40)
        ])

        #expect(response == .unknownComponent(componentId: "c9"))
        #expect(positions()["c1"] == Point(x: 0, y: 0))
    }

    @Test func acceptsAnEmptyRequest() {
        #expect(move([]) == .moved(count: 0))
    }

    @Test func takesTheLastPositionWhenAComponentIsNamedTwice() {
        let response = move([
            ComponentMove(componentId: "c1", x: 10, y: 20),
            ComponentMove(componentId: "c1", x: 30, y: 40)
        ])

        #expect(response == .moved(count: 1))
        #expect(positions()["c1"] == Point(x: 30, y: 40))
    }

    @Test func givesTheSameResultWhenCalledTwice() {
        let request = [ComponentMove(componentId: "c1", x: 55, y: 65)]

        _ = move(request)
        _ = move(request)

        #expect(positions()["c1"] == Point(x: 55, y: 65))
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter MoveComponentsTests 2>&1 | grep -E 'error:' | head -5
```

Expected: FAIL with `cannot find 'MoveComponents' in scope`.

- [ ] **Step 3: Write the use case**

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/MoveComponents.swift`:

```swift
public protocol MoveComponentsUseCase {
    func execute(_ request: MoveComponentsRequest) -> MoveComponentsResponse
}

/// One component's new position, in model coordinates.
public struct ComponentMove: Equatable, Sendable {
    public let componentId: String
    public let x: Double
    public let y: Double

    public init(componentId: String, x: Double, y: Double) {
        self.componentId = componentId
        self.x = x
        self.y = y
    }
}

public struct MoveComponentsRequest: Equatable, Sendable {
    public let moves: [ComponentMove]

    public init(moves: [ComponentMove]) {
        self.moves = moves
    }
}

public enum MoveComponentsResponse: Equatable, Sendable {
    /// The number of distinct components that moved.
    case moved(count: Int)
    case unknownComponent(componentId: String)
}

/// Puts components at new positions.
///
/// Positions are absolute, not offsets, so the same request applied twice
/// leaves the same model. The move is all or nothing: one unknown component
/// leaves every position as it was. Naming a component twice in one request
/// takes the last position given for it.
public struct MoveComponents: MoveComponentsUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: MoveComponentsRequest) -> MoveComponentsResponse {
        var model = models.current()
        var positions: [ComponentId: Point] = [:]

        for move in request.moves {
            let id = ComponentId(move.componentId)
            guard model.component(id) != nil else {
                return .unknownComponent(componentId: move.componentId)
            }
            positions[id] = Point(x: move.x, y: move.y)
        }

        guard positions.isEmpty == false else { return .moved(count: 0) }

        for index in model.components.indices {
            if let position = positions[model.components[index].id] {
                model.components[index].position = position
            }
        }
        models.save(model)

        return .moved(count: positions.count)
    }
}
```

- [ ] **Step 4: Vend it from both composition roots**

Add to `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`:

```swift
    func moveComponents() -> MoveComponentsUseCase
```

Add to `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`:

```swift
    public func moveComponents() -> MoveComponentsUseCase {
        MoveComponents(models: models)
    }
```

Add to `threatmodeller/Dependencies.swift`:

```swift
    func moveComponents() -> MoveComponentsUseCase {
        MoveComponents(models: models)
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
git add ThreatModelKit/Sources threatmodeller/Dependencies.swift ThreatModelKit/Tests/UnitTests/MoveComponentsTests.swift
git commit -m "feat: add MoveComponents

A completed drag moves the whole selection. Positions are absolute, so a
repeated request leaves the same model, and one unknown component leaves
every position unchanged."
```

---

### Task 7: `RemoveConnection`

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/RemoveConnection.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`
- Modify: `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`
- Modify: `threatmodeller/Dependencies.swift`
- Test: `ThreatModelKit/Tests/UnitTests/RemoveConnectionTests.swift`

**Interfaces:**
- Consumes: `ThreatModelGateway`, `Connection`.
- Produces: `RemoveConnectionUseCase`, `RemoveConnectionRequest(connectionId:)`, `RemoveConnectionResponse` with cases `.removed` and `.unknownConnection`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/RemoveConnectionTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct RemoveConnectionTests {
    private let models = InMemoryThreatModelGateway(
        ThreatModel(
            components: [
                RemoveConnectionTests.component("c1"),
                RemoveConnectionTests.component("c2")
            ],
            connections: [
                Connection(id: ConnectionId("k1"), source: ComponentId("c1"), target: ComponentId("c2")),
                Connection(id: ConnectionId("k2"), source: ComponentId("c2"), target: ComponentId("c1"))
            ]
        )
    )

    private static func component(_ id: String) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData
        )
    }

    private func remove(_ id: String) -> RemoveConnectionResponse {
        RemoveConnection(models: models).execute(RemoveConnectionRequest(connectionId: id))
    }

    @Test func removesTheNamedConnectionAndLeavesTheOther() {
        #expect(remove("k1") == .removed)

        #expect(models.current().connections.map(\.id.value) == ["k2"])
        #expect(models.current().components.count == 2)
    }

    @Test func refusesAConnectionTheModelDoesNotHold() {
        #expect(remove("k9") == .unknownConnection)
        #expect(models.current().connections.count == 2)
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter RemoveConnectionTests 2>&1 | grep -E 'error:' | head -5
```

Expected: FAIL with `cannot find 'RemoveConnection' in scope`.

- [ ] **Step 3: Write the use case**

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/RemoveConnection.swift`:

```swift
public protocol RemoveConnectionUseCase {
    func execute(_ request: RemoveConnectionRequest) -> RemoveConnectionResponse
}

public struct RemoveConnectionRequest: Equatable, Sendable {
    public let connectionId: String

    public init(connectionId: String) {
        self.connectionId = connectionId
    }
}

public enum RemoveConnectionResponse: Equatable, Sendable {
    case removed
    case unknownConnection
}

/// Removes one link. The components at each end stay on the model.
public struct RemoveConnection: RemoveConnectionUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RemoveConnectionRequest) -> RemoveConnectionResponse {
        let id = ConnectionId(request.connectionId)

        var model = models.current()
        guard model.connections.contains(where: { $0.id == id }) else {
            return .unknownConnection
        }

        model.connections.removeAll { $0.id == id }
        models.save(model)

        return .removed
    }
}
```

- [ ] **Step 4: Vend it from both composition roots**

Add to `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`:

```swift
    func removeConnection() -> RemoveConnectionUseCase
```

Add to `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`:

```swift
    public func removeConnection() -> RemoveConnectionUseCase {
        RemoveConnection(models: models)
    }
```

Add to `threatmodeller/Dependencies.swift`:

```swift
    func removeConnection() -> RemoveConnectionUseCase {
        RemoveConnection(models: models)
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
git add ThreatModelKit/Sources threatmodeller/Dependencies.swift ThreatModelKit/Tests/UnitTests/RemoveConnectionTests.swift
git commit -m "feat: add RemoveConnection"
```

---

### Task 8: `RemoveComponents` and its cascade

Spec §5.3: removing a component also removes every connection that touches it. The response reports the removed connections so the canvas can drop them from the selection.

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/RemoveComponents.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`
- Modify: `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`
- Modify: `threatmodeller/Dependencies.swift`
- Test: `ThreatModelKit/Tests/UnitTests/RemoveComponentsTests.swift`

**Interfaces:**
- Consumes: `ThreatModelGateway`, `Connection.touches(_:)`, `ThreatModel.component(_:)`.
- Produces: `RemoveComponentsUseCase`, `RemoveComponentsRequest(componentIds:)`, `RemoveComponentsResponse` with cases `.removed(componentIds:connectionIds:)` and `.unknownComponent(componentId:)`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/RemoveComponentsTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct RemoveComponentsTests {
    private let models = InMemoryThreatModelGateway(
        ThreatModel(
            components: [
                RemoveComponentsTests.component("c1"),
                RemoveComponentsTests.component("c2"),
                RemoveComponentsTests.component("c3")
            ],
            connections: [
                Connection(id: ConnectionId("k1"), source: ComponentId("c1"), target: ComponentId("c2")),
                Connection(id: ConnectionId("k2"), source: ComponentId("c2"), target: ComponentId("c3")),
                Connection(id: ConnectionId("k3"), source: ComponentId("c3"), target: ComponentId("c1"))
            ]
        )
    )

    private static func component(_ id: String) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData
        )
    }

    private func remove(_ ids: [String]) -> RemoveComponentsResponse {
        RemoveComponents(models: models).execute(RemoveComponentsRequest(componentIds: ids))
    }

    @Test func removesTheComponentAndEveryConnectionThatTouchesIt() {
        let response = remove(["c1"])

        #expect(response == .removed(componentIds: ["c1"], connectionIds: ["k1", "k3"]))
        #expect(models.current().components.map(\.id.value) == ["c2", "c3"])
        #expect(models.current().connections.map(\.id.value) == ["k2"])
    }

    @Test func removesSeveralComponentsAtOnce() {
        let response = remove(["c3", "c1"])

        #expect(response == .removed(componentIds: ["c1", "c3"], connectionIds: ["k1", "k2", "k3"]))
        #expect(models.current().components.map(\.id.value) == ["c2"])
        #expect(models.current().connections.isEmpty)
    }

    @Test func reportsEachRemovalInModelOrderNotRequestOrder() {
        let response = remove(["c2", "c1"])

        #expect(response == .removed(componentIds: ["c1", "c2"], connectionIds: ["k1", "k2", "k3"]))
    }

    @Test func removesNothingWhenOneComponentIsUnknown() {
        let response = remove(["c1", "c9"])

        #expect(response == .unknownComponent(componentId: "c9"))
        #expect(models.current().components.count == 3)
        #expect(models.current().connections.count == 3)
    }

    @Test func acceptsAnEmptyRequest() {
        #expect(remove([]) == .removed(componentIds: [], connectionIds: []))
        #expect(models.current().components.count == 3)
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter RemoveComponentsTests 2>&1 | grep -E 'error:' | head -5
```

Expected: FAIL with `cannot find 'RemoveComponents' in scope`.

- [ ] **Step 3: Write the use case**

Create `ThreatModelKit/Sources/ThreatModelKit/modelling/usecase/RemoveComponents.swift`:

```swift
public protocol RemoveComponentsUseCase {
    func execute(_ request: RemoveComponentsRequest) -> RemoveComponentsResponse
}

public struct RemoveComponentsRequest: Equatable, Sendable {
    public let componentIds: [String]

    public init(componentIds: [String]) {
        self.componentIds = componentIds
    }
}

public enum RemoveComponentsResponse: Equatable, Sendable {
    /// What left the model, both listed in model order, not request order.
    /// `connectionIds` holds the links removed because a component they touch
    /// was removed.
    case removed(componentIds: [String], connectionIds: [String])
    case unknownComponent(componentId: String)
}

/// Removes components and every link that touches one of them.
///
/// The removal is all or nothing: one unknown component leaves the model as it
/// was. The response lists what left so the canvas can drop those rows from
/// its selection.
public struct RemoveComponents: RemoveComponentsUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RemoveComponentsRequest) -> RemoveComponentsResponse {
        var model = models.current()
        var doomed: Set<ComponentId> = []

        for raw in request.componentIds {
            let id = ComponentId(raw)
            guard model.component(id) != nil else {
                return .unknownComponent(componentId: raw)
            }
            doomed.insert(id)
        }

        guard doomed.isEmpty == false else {
            return .removed(componentIds: [], connectionIds: [])
        }

        let removedComponents = model.components
            .filter { doomed.contains($0.id) }
            .map(\.id.value)
        let removedConnections = model.connections
            .filter { connection in doomed.contains(where: connection.touches) }
            .map(\.id.value)

        model.components.removeAll { doomed.contains($0.id) }
        model.connections.removeAll { connection in doomed.contains(where: connection.touches) }
        models.save(model)

        return .removed(componentIds: removedComponents, connectionIds: removedConnections)
    }
}
```

- [ ] **Step 4: Vend it from both composition roots**

Add to `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`:

```swift
    func removeComponents() -> RemoveComponentsUseCase
```

Add to `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`:

```swift
    public func removeComponents() -> RemoveComponentsUseCase {
        RemoveComponents(models: models)
    }
```

Add to `threatmodeller/Dependencies.swift`:

```swift
    func removeComponents() -> RemoveComponentsUseCase {
        RemoveComponents(models: models)
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
git add ThreatModelKit/Sources threatmodeller/Dependencies.swift ThreatModelKit/Tests/UnitTests/RemoveComponentsTests.swift
git commit -m "feat: add RemoveComponents with its connection cascade

Removing a component removes every link that touches it. The response lists
both, so the canvas can drop the removed rows from its selection."
```

---

### Task 9: `connectionThreats()` on the catalogue port

Extends the port, the fake, the shared contract and the real gateway together, so both implementations prove the same behaviour.

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/catalogue/gateway/TechnologyCatalogue.swift`
- Modify: `ThreatModelKit/Sources/TestSupport/InMemoryTechnologyCatalogue.swift`
- Modify: `ThreatModelKit/Sources/TestSupport/CatalogueFixture.swift`
- Modify: `ThreatModelKit/Sources/TestSupport/TechnologyCatalogueContract.swift`
- Modify: `ThreatModelKit/Sources/CatalogueGateways/BundledTechnologyCatalogue.swift`
- Modify: `ThreatModelKit/Tests/GatewayIntegrationTests/BundledTechnologyCatalogueTests.swift`

**Interfaces:**
- Consumes: `Threat.isConnectionThreat`.
- Produces: `TechnologyCatalogue.connectionThreats() -> [Threat]`; `CatalogueFixture.connectionThreats()` returning `connection-mitm` (medium, one control) and `connection-dos` (low, one control).

- [ ] **Step 1: Write the failing test**

Add these clauses to the end of `verifyTechnologyCatalogueContract` in `ThreatModelKit/Sources/TestSupport/TechnologyCatalogueContract.swift`, inside the function body:

```swift
    let connectionThreats = subject.connectionThreats()
    #expect(connectionThreats.isEmpty == false)
    // A key path here makes the `rethrows` on `allSatisfy` unresolvable inside
    // the `#expect` macro expansion, so the closure form is required.
    #expect(connectionThreats.allSatisfy { $0.isConnectionThreat })
    #expect(Set(connectionThreats.map(\.id)).count == connectionThreats.count)
    for threat in connectionThreats {
        #expect(taxonomy.severity(id: threat.severity.id) == threat.severity)
        #expect(threat.controls.isEmpty == false)
    }

    // A connection threat belongs to the link, never to a technology. No
    // technology may declare one as its own threat, or the same threat would
    // be raised twice from two different sources.
    let connectionThreatIds = Set(connectionThreats.map(\.id))
    for technology in subject.all() {
        #expect(Set(technology.threatIds).isDisjoint(with: connectionThreatIds))
    }
```

Add to `ThreatModelKit/Tests/GatewayIntegrationTests/BundledTechnologyCatalogueTests.swift`:

```swift
    @Test func listsTheConnectionThreatsTheVendoredDataFlags() throws {
        let catalogue = try BundledTechnologyCatalogue()

        #expect(catalogue.connectionThreats().map(\.id.value) == [
            "connection-mitm",
            "connection-data-exposure",
            "connection-replay",
            "connection-injection",
            "connection-dos"
        ])
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter TechnologyCatalogueContractTests 2>&1 | grep -E 'error:' | head -5
```

Expected: FAIL with `value of type 'any TechnologyCatalogue' has no member 'connectionThreats'`.

- [ ] **Step 3: Add the method to the port**

In `ThreatModelKit/Sources/ThreatModelKit/catalogue/gateway/TechnologyCatalogue.swift`, add after `threatsFor(technologyId:)` and update the doc comment:

```swift
/// Reads the technology and threat catalogue.
///
/// Later milestones extend this port with `zoneThreats()` and
/// `pathwayMitigations()`. Do not add them before the milestone that needs them.
public protocol TechnologyCatalogue {
    func all() -> [Technology]
    func findById(_ id: TechnologyId) -> Technology?
    /// The technology's threats, in the order the technology declares them.
    /// Empty for an unknown technology.
    func threatsFor(technologyId: TechnologyId) -> [Threat]
    /// Every threat the catalogue flags as belonging to a link between two
    /// components, in catalogue order. These threats belong to no technology.
    func connectionThreats() -> [Threat]
    func taxonomy() -> Taxonomy
    func providers() -> [Provider]
}
```

- [ ] **Step 4: Implement it on the fake**

Replace the whole of `ThreatModelKit/Sources/TestSupport/InMemoryTechnologyCatalogue.swift`:

```swift
import ThreatModelKit

/// A working catalogue backed by arrays. Honours the same contract as the real one.
public final class InMemoryTechnologyCatalogue: TechnologyCatalogue {
    private let technologies: [Technology]
    /// Kept in the order given, so `connectionThreats()` answers in catalogue
    /// order the way the real gateway does.
    private let orderedThreats: [Threat]
    private let threats: [ThreatId: Threat]
    private let taxonomyValue: Taxonomy
    private let providersValue: [Provider]

    public init(
        technologies: [Technology],
        threats: [Threat],
        taxonomy: Taxonomy,
        providers: [Provider]
    ) {
        self.technologies = technologies
        self.orderedThreats = threats
        self.threats = Dictionary(uniqueKeysWithValues: threats.map { ($0.id, $0) })
        self.taxonomyValue = taxonomy
        self.providersValue = providers
    }

    public func all() -> [Technology] { technologies }

    public func findById(_ id: TechnologyId) -> Technology? {
        technologies.first { $0.id == id }
    }

    public func threatsFor(technologyId: TechnologyId) -> [Threat] {
        guard let technology = findById(technologyId) else { return [] }
        return technology.threatIds.compactMap { threats[$0] }
    }

    public func connectionThreats() -> [Threat] {
        orderedThreats.filter(\.isConnectionThreat)
    }

    public func taxonomy() -> Taxonomy { taxonomyValue }

    public func providers() -> [Provider] { providersValue }
}
```

- [ ] **Step 5: Give the fixture its connection threats**

Add to `ThreatModelKit/Sources/TestSupport/CatalogueFixture.swift`, after `ec2Threats()`:

```swift
    /// Two connection threats shaped like the vendored ones. `connection-mitm`
    /// is one of the two threats TLS mitigates; `connection-dos` is not, so a
    /// test can tell the flag apart from the score.
    public static func connectionThreats() -> [Threat] {
        [
            Threat(
                id: ThreatId("connection-mitm"),
                name: "Man-in-the-Middle Attack",
                description: "Attacker intercepts traffic between two components",
                severity: medium,
                stride: [StrideId("tampering"), StrideId("information-disclosure")],
                mitreTechniques: [
                    MitreTechnique(id: "T1557", name: "Adversary-in-the-Middle", tactic: "Collection")
                ],
                controls: [Control(id: "ctrl-conn-1", description: "Enforce TLS on every hop")],
                isConnectionThreat: true
            ),
            Threat(
                id: ThreatId("connection-dos"),
                name: "Connection Flooding",
                description: "Attacker exhausts the link between two components",
                severity: low,
                stride: [StrideId("denial-of-service")],
                controls: [Control(id: "ctrl-conn-2", description: "Apply connection rate limits")],
                isConnectionThreat: true
            )
        ]
    }
```

Change the `catalogue()` factory in the same file so the connection threats reach the fake:

```swift
    public static func catalogue() -> InMemoryTechnologyCatalogue {
        InMemoryTechnologyCatalogue(
            technologies: [ec2(), rds(), bigQuery()],
            threats: ec2Threats() + connectionThreats(),
            taxonomy: taxonomy(),
            providers: providers()
        )
    }
```

No fixture technology declares a connection threat in its `threatIds`, so `threatsFor(technologyId:)` is unchanged.

- [ ] **Step 6: Implement it on the real gateway**

In `ThreatModelKit/Sources/CatalogueGateways/BundledTechnologyCatalogue.swift`, add a stored property beside `threatsById`:

```swift
    private let connectionThreatsValue: [Threat]
```

Inside `init`, change the threat decoding loop so it collects the flagged threats in file order. Replace the loop and the line after it:

```swift
        var threats: [ThreatId: Threat] = [:]
        var connectionThreatList: [Threat] = []
        for entry in threatsJSON.threats {
            guard let severity = taxonomyValue.severity(id: entry.severity) else {
                throw CatalogueLoadError.unknownSeverity(threatId: entry.id, severity: entry.severity)
            }
            let threat = Threat(
                id: ThreatId(entry.id),
                name: entry.name,
                description: entry.description,
                severity: severity,
                stride: entry.stride.map(StrideId.init),
                mitreTechniques: entry.mitreTechniques.map {
                    MitreTechnique(id: $0.id, name: $0.name, tactic: $0.tactic)
                },
                controls: entry.controls.map {
                    Control(id: $0.id, description: $0.description)
                },
                isConnectionThreat: entry.isConnectionThreat ?? false,
                isZoneThreat: entry.isZoneThreat ?? false,
                isPathwayThreat: entry.isPathwayThreat ?? false,
                zoneContext: entry.zoneContext
            )
            threats[threat.id] = threat
            if threat.isConnectionThreat {
                connectionThreatList.append(threat)
            }
        }
        threatsById = threats
        connectionThreatsValue = connectionThreatList
```

Add the method beside `threatsFor(technologyId:)`:

```swift
    public func connectionThreats() -> [Threat] { connectionThreatsValue }
```

- [ ] **Step 7: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

Expected: PASS. Both the fake and the bundled gateway honour the extended contract.

- [ ] **Step 8: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit/Sources ThreatModelKit/Tests
git commit -m "feat: read connection threats from the catalogue

The port, the fake, the shared contract and the bundled gateway gain
connectionThreats() together. The contract also proves no technology claims
a connection threat as its own, which would raise it from two sources."
```

---

### Task 10: `SensitivityLadder` and `ConnectionEncryption`

Two assessment domain objects. Spec §5.2 lists `SensitivityLadder`; spec §5.3 states the connection encryption rule.

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/SensitivityLadder.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ConnectionEncryption.swift`
- Test: `ThreatModelKit/Tests/UnitTests/SensitivityLadderTests.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ConnectionEncryptionTests.swift`

**Interfaces:**
- Consumes: `DataSensitivity`, `Threat`, `Technology`, `ThreatId`.
- Produces: `SensitivityLadder.higher(_:_:) -> DataSensitivity`; `ConnectionEncryption.mitigatedThreatIds: Set<ThreatId>`; `ConnectionEncryption.isTlsMitigated(threat:source:target:) -> Bool`.

- [ ] **Step 1: Write the failing tests**

Create `ThreatModelKit/Tests/UnitTests/SensitivityLadderTests.swift`:

```swift
import Testing
import ThreatModelKit

struct SensitivityLadderTests {
    @Test func picksTheHigherOfTwoSensitivities() {
        #expect(SensitivityLadder.higher(.publicData, .restricted) == .restricted)
        #expect(SensitivityLadder.higher(.restricted, .publicData) == .restricted)
        #expect(SensitivityLadder.higher(.internalData, .confidential) == .confidential)
    }

    @Test func returnsTheSameValueWhenBothMatch() {
        #expect(SensitivityLadder.higher(.confidential, .confidential) == .confidential)
    }

    @Test func rankOrderDecidesNotDeclarationOrder() {
        for first in DataSensitivity.allCases {
            for second in DataSensitivity.allCases {
                let picked = SensitivityLadder.higher(first, second)
                #expect(picked.rank == max(first.rank, second.rank))
            }
        }
    }
}
```

Create `ThreatModelKit/Tests/UnitTests/ConnectionEncryptionTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct ConnectionEncryptionTests {
    private let plain = CatalogueFixture.ec2()            // enforcesEncryption == false
    private let encrypting = CatalogueFixture.rds()       // enforcesEncryption == true

    private func threat(_ id: String) -> Threat {
        Threat(
            id: ThreatId(id),
            name: id,
            description: "",
            severity: CatalogueFixture.medium,
            isConnectionThreat: true
        )
    }

    @Test func namesTheTwoThreatsTlsMitigates() {
        #expect(ConnectionEncryption.mitigatedThreatIds == [
            ThreatId("connection-mitm"),
            ThreatId("connection-data-exposure")
        ])
    }

    @Test func flagsAMitigableThreatWhenTheSourceEnforcesEncryption() {
        #expect(ConnectionEncryption.isTlsMitigated(
            threat: threat("connection-mitm"), source: encrypting, target: plain))
    }

    @Test func flagsAMitigableThreatWhenTheTargetEnforcesEncryption() {
        #expect(ConnectionEncryption.isTlsMitigated(
            threat: threat("connection-data-exposure"), source: plain, target: encrypting))
    }

    @Test func leavesAMitigableThreatUnflaggedWhenNeitherEndEnforcesEncryption() {
        #expect(ConnectionEncryption.isTlsMitigated(
            threat: threat("connection-mitm"), source: plain, target: plain) == false)
    }

    @Test func neverFlagsAThreatOutsideTheTwo() {
        #expect(ConnectionEncryption.isTlsMitigated(
            threat: threat("connection-dos"), source: encrypting, target: encrypting) == false)
    }

    @Test func treatsAnUnknownTechnologyAsNotEnforcingEncryption() {
        #expect(ConnectionEncryption.isTlsMitigated(
            threat: threat("connection-mitm"), source: nil, target: nil) == false)
        #expect(ConnectionEncryption.isTlsMitigated(
            threat: threat("connection-mitm"), source: nil, target: encrypting))
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter SensitivityLadderTests 2>&1 | grep -E 'error:' | head -5
```

Expected: FAIL with `cannot find 'SensitivityLadder' in scope`.

- [ ] **Step 3: Write `SensitivityLadder`**

Create `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/SensitivityLadder.swift`:

```swift
/// Picks the sensitivity a threat is scored against when more than one
/// component supplies data.
///
/// Spec section 5.3: a connection's sensitivity is the higher of its two
/// endpoints' sensitivities. Milestone 5 adds the downstream rule for pathway
/// threats; do not add it before then.
public enum SensitivityLadder {
    public static func higher(_ first: DataSensitivity, _ second: DataSensitivity) -> DataSensitivity {
        first.rank >= second.rank ? first : second
    }
}
```

- [ ] **Step 4: Write `ConnectionEncryption`**

Create `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ConnectionEncryption.swift`:

```swift
/// Which connection threats a TLS-enforcing endpoint mitigates.
///
/// WARNING: the flag is for display only. It never changes a risk score.
/// Spec section 5.3 states that rule; the original application behaves the
/// same way, and the ported tests hold it.
public enum ConnectionEncryption {
    /// Only these two threats carry the flag. Every other connection threat is
    /// unaffected by transport encryption.
    public static let mitigatedThreatIds: Set<ThreatId> = [
        ThreatId("connection-mitm"),
        ThreatId("connection-data-exposure")
    ]

    /// True when the threat is one of the two, and either endpoint technology
    /// enforces encryption. A technology the catalogue no longer holds counts
    /// as not enforcing it.
    public static func isTlsMitigated(
        threat: Threat,
        source: Technology?,
        target: Technology?
    ) -> Bool {
        guard mitigatedThreatIds.contains(threat.id) else { return false }
        return source?.enforcesEncryption == true || target?.enforcesEncryption == true
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
git add ThreatModelKit/Sources/ThreatModelKit/assessment/domain ThreatModelKit/Tests/UnitTests
git commit -m "feat: add SensitivityLadder and ConnectionEncryption

Two assessment rules the connection threats need: a link is scored against
the higher of its endpoints' sensitivities, and two named threats carry a
TLS-mitigated display flag that never changes the score."
```

---

### Task 11: `AssessedThreatSource`

A refactor with no behaviour change. `AssessedThreat` carries three flat fields that only describe a component; a connection threat has no component source. Replacing them with an enum gives every call site exhaustive handling, and Milestone 3 adds a `.zone` case to the same enum.

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/AssessThreatModel.swift`
- Modify: `ThreatModelKit/Tests/UnitTests/AssessThreatModelTests.swift`
- Modify: `ThreatModelKit/Tests/AcceptanceTests/BuildingAThreatModelTests.swift`
- Modify: `threatmodeller/ContentView.swift`

**Interfaces:**
- Consumes: nothing new.
- Produces: `AssessedThreatSource` with cases `.component(id:name:providerId:)` and `.connection(id:sourceName:targetName:)`, plus `displayName: String` and `id: String`. `AssessedThreat.source: AssessedThreatSource` replaces `sourceComponentId`, `sourceName` and `sourceProviderId`.

- [ ] **Step 1: Write the failing tests**

In `ThreatModelKit/Tests/UnitTests/AssessThreatModelTests.swift`, replace `ordersByScoreThenThreatIdThenComponentId` and `namesTheSourceAfterTheTechnologyUnlessRenamed` with:

```swift
    @Test func ordersByScoreThenThreatIdThenSource() {
        let response = assess(
            ThreatModel(components: [ec2(id: "c2"), ec2(id: "c1", sensitivity: .publicData)])
        )
        let ordering = response.threats.map { "\($0.riskScore):\($0.threatId):\($0.source.id)" }
        #expect(ordering == [
            "12:credential-theft:component:c2",
            "6:misconfiguration:component:c2",
            "4:credential-theft:component:c1",
            "3:dos-attack:component:c2",
            "2:misconfiguration:component:c1",
            "1:dos-attack:component:c1"
        ])
    }

    @Test func namesTheSourceAfterTheTechnologyUnlessRenamed() throws {
        let plain = assess(ThreatModel(components: [ec2()]))
        #expect(try #require(plain.threats.first).source
                == .component(id: "c1", name: "EC2", providerId: "aws"))
        #expect(try #require(plain.threats.first).source.displayName == "EC2")

        let renamed = assess(ThreatModel(components: [ec2(customName: "Bastion host")]))
        #expect(try #require(renamed.threats.first).source.displayName == "Bastion host")
    }
```

In `ThreatModelKit/Tests/AcceptanceTests/BuildingAThreatModelTests.swift`, replace line 43:

```swift
        #expect(assessment.threats.allSatisfy { $0.source.displayName == "EC2" })
```

and replace line 83:

```swift
        #expect(assessment.threats.contains { $0.source.id == "component:\(componentId)" })
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter AssessThreatModelTests 2>&1 | grep -E 'error:' | head -5
```

Expected: FAIL with `value of type 'AssessedThreat' has no member 'source'`.

- [ ] **Step 3: Add the source enum and change `AssessedThreat`**

In `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/AssessThreatModel.swift`, add the enum above `AssessedThreat`:

```swift
/// What raised a threat.
///
/// Milestone 3 adds a `zone` case. Every call site handles the cases
/// exhaustively, so a new case is a compile error rather than a silent gap.
public enum AssessedThreatSource: Hashable, Sendable {
    case component(id: String, name: String, providerId: String)
    case connection(id: String, sourceName: String, targetName: String)

    /// The label the user reads on the threat row.
    public var displayName: String {
        switch self {
        case .component(_, let name, _):
            name
        case .connection(_, let sourceName, let targetName):
            "\(sourceName) → \(targetName)"
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
        }
    }
}
```

Replace the three flat fields in `AssessedThreat` with one, keeping the field order:

```swift
public struct AssessedThreat: Hashable, Sendable {
    public let threatId: String
    public let name: String
    public let description: String
    public let severityId: String
    public let severityLabel: String
    public let stride: [String]
    public let mitreTechniques: [AssessedMitreTechnique]
    public let controls: [AssessedControl]
    public let source: AssessedThreatSource
    public let sensitivityId: String
    public let riskScore: Int
    public let riskLevel: String
    public let context: String?

    public init(
        threatId: String,
        name: String,
        description: String,
        severityId: String,
        severityLabel: String,
        stride: [String],
        mitreTechniques: [AssessedMitreTechnique],
        controls: [AssessedControl],
        source: AssessedThreatSource,
        sensitivityId: String,
        riskScore: Int,
        riskLevel: String,
        context: String?
    ) {
        self.threatId = threatId
        self.name = name
        self.description = description
        self.severityId = severityId
        self.severityLabel = severityLabel
        self.stride = stride
        self.mitreTechniques = mitreTechniques
        self.controls = controls
        self.source = source
        self.sensitivityId = sensitivityId
        self.riskScore = riskScore
        self.riskLevel = riskLevel
        self.context = context
    }
}
```

In `execute`, replace the three arguments:

```swift
                        source: .component(
                            id: component.id.value,
                            name: component.customName ?? technology.name,
                            providerId: technology.provider.value
                        ),
```

Replace the tail of `ordering`:

```swift
        return a.source.id < b.source.id
```

- [ ] **Step 4: Update the threat list view**

In `threatmodeller/ContentView.swift`, replace the `rowIdentity` extension:

```swift
private extension AssessedThreat {
    /// Row key for the threat list. `AssessedThreat` carries no identity field
    /// of its own, so two equal threats would collide as one row. The pair of
    /// `threatId` and the source's id identifies a row.
    var rowIdentity: String { "\(threatId)#\(source.id)" }
}
```

and replace the source line inside the list row:

```swift
                        Text(threat.source.displayName)
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | tail -5
```

Expected: PASS. No score, order or control changed.

- [ ] **Step 6: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit threatmodeller/ContentView.swift
git commit -m "refactor: report what raised a threat as an enum

Three flat fields described a component only, and a connection threat has no
component source. AssessedThreatSource gives each kind its own case and every
call site exhaustive handling. Milestone 3 adds the zone case. No behaviour
changed."
```

---

### Task 12: Connection threats, the TLS flag, and deduplication

The assessment half of the milestone. Also closes carry-forward item 4.

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/AssessThreatModel.swift`
- Modify: `ThreatModelKit/Tests/UnitTests/AssessThreatModelTests.swift`

**Interfaces:**
- Consumes: `TechnologyCatalogue.connectionThreats()`, `SensitivityLadder.higher(_:_:)`, `ConnectionEncryption.isTlsMitigated(threat:source:target:)`, `ThreatModel.component(_:)`, `AssessedThreatSource`.
- Produces: `AssessedThreat.isTlsMitigated: Bool` as the last initialiser argument.

- [ ] **Step 1: Write the failing tests**

Add to `ThreatModelKit/Tests/UnitTests/AssessThreatModelTests.swift`, inside the struct. The helpers `assess` and `ec2` already exist; add two more helpers first:

```swift
    private func rds(
        id: String = "c2",
        sensitivity: DataSensitivity = .confidential,
        threatsDisabled: Bool = false
    ) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-rds"),
            position: Point(x: 0, y: 0),
            sensitivity: sensitivity,
            threatsDisabled: threatsDisabled
        )
    }

    private func link(_ id: String, _ source: String, _ target: String) -> Connection {
        Connection(id: ConnectionId(id), source: ComponentId(source), target: ComponentId(target))
    }
```

Then the cases:

```swift
    @Test func raisesEveryConnectionThreatOnALink() {
        let response = assess(
            ThreatModel(
                components: [ec2(id: "c1", sensitivity: .internalData), rds(sensitivity: .internalData)],
                connections: [link("k1", "c1", "c2")]
            )
        )

        let onTheLink = response.threats.filter {
            if case .connection = $0.source { return true } else { return false }
        }
        #expect(onTheLink.map(\.threatId) == ["connection-mitm", "connection-dos"])
        #expect(onTheLink.allSatisfy { $0.source.id == "connection:k1" })
        #expect(onTheLink.first?.source.displayName == "EC2 → RDS")
    }

    @Test func scoresALinkAgainstTheHigherOfItsTwoEndSensitivities() throws {
        let response = assess(
            ThreatModel(
                components: [ec2(id: "c1", sensitivity: .publicData), rds(sensitivity: .restricted)],
                connections: [link("k1", "c1", "c2")]
            )
        )

        let mitm = try #require(response.threats.first { $0.threatId == "connection-mitm" })
        #expect(mitm.sensitivityId == "restricted")
        #expect(mitm.riskScore == 8)
        #expect(mitm.riskLevel == "high")
    }

    @Test func alwaysUsesTheThreatsOwnControlsOnALink() throws {
        let response = assess(
            ThreatModel(
                components: [ec2(id: "c1"), rds()],
                connections: [link("k1", "c1", "c2")]
            )
        )

        let mitm = try #require(response.threats.first { $0.threatId == "connection-mitm" })
        #expect(mitm.controls.map(\.description) == ["Enforce TLS on every hop"])
        #expect(mitm.controls.contains(where: \.isTechnologySpecific) == false)
        #expect(mitm.context == nil)
    }

    @Test func flagsTlsMitigationWithoutChangingTheScore() throws {
        // RDS enforces encryption in the fixture; EC2 does not.
        let response = assess(
            ThreatModel(
                components: [ec2(id: "c1", sensitivity: .internalData), rds(sensitivity: .internalData)],
                connections: [link("k1", "c1", "c2")]
            )
        )

        let mitm = try #require(response.threats.first { $0.threatId == "connection-mitm" })
        let flood = try #require(response.threats.first { $0.threatId == "connection-dos" })

        #expect(mitm.isTlsMitigated)
        #expect(mitm.riskScore == 4)
        #expect(flood.isTlsMitigated == false)
        #expect(flood.riskScore == 2)
    }

    @Test func neverFlagsTlsMitigationOnAComponentThreat() {
        let response = assess(ThreatModel(components: [ec2()]))
        #expect(response.threats.allSatisfy { $0.isTlsMitigated == false })
    }

    @Test func raisesNothingOnALinkTouchingAComponentWithThreatsDisabled() {
        let response = assess(
            ThreatModel(
                components: [ec2(id: "c1"), rds(threatsDisabled: true)],
                connections: [link("k1", "c1", "c2")]
            )
        )

        #expect(response.threats.allSatisfy {
            if case .connection = $0.source { return false } else { return true }
        })
    }

    @Test func raisesNothingOnALinkWhoseEndIsNotOnTheModel() {
        let response = assess(
            ThreatModel(components: [ec2(id: "c1")], connections: [link("k1", "c1", "c9")])
        )

        #expect(response.threats.allSatisfy {
            if case .connection = $0.source { return false } else { return true }
        })
    }

    @Test func stillRaisesLinkThreatsWhenAnEndsTechnologyLeftTheCatalogue() throws {
        let orphan = Component(
            id: ComponentId("c2"),
            technologyId: TechnologyId("aws-nope"),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData
        )
        let response = assess(
            ThreatModel(
                components: [ec2(id: "c1", sensitivity: .internalData), orphan],
                connections: [link("k1", "c1", "c2")]
            )
        )

        let mitm = try #require(response.threats.first { $0.threatId == "connection-mitm" })
        #expect(mitm.source.displayName == "EC2 → aws-nope")
        #expect(mitm.isTlsMitigated == false)
    }

    @Test func raisesLinkThreatsOncePerLink() {
        let response = assess(
            ThreatModel(
                components: [ec2(id: "c1"), rds(), ec2(id: "c3")],
                connections: [link("k1", "c1", "c2"), link("k2", "c1", "c3")]
            )
        )

        let mitm = response.threats.filter { $0.threatId == "connection-mitm" }
        #expect(mitm.map(\.source.id).sorted() == ["connection:k1", "connection:k2"])
    }

    @Test func raisesADuplicateThreatAndSourcePairOnlyOnce() {
        // A technology that declares the same threat twice must not produce two
        // rows. Spec section 5.3. No vendored technology does this today.
        let doubled = Technology(
            id: TechnologyId("aws-doubled"),
            name: "Doubled",
            provider: ProviderId("aws"),
            category: CategoryId("compute"),
            description: "Declares one threat twice",
            threatIds: [ThreatId("misconfiguration"), ThreatId("misconfiguration")]
        )
        let catalogue = InMemoryTechnologyCatalogue(
            technologies: [doubled],
            threats: CatalogueFixture.ec2Threats() + CatalogueFixture.connectionThreats(),
            taxonomy: CatalogueFixture.taxonomy(),
            providers: CatalogueFixture.providers()
        )
        let model = ThreatModel(components: [
            Component(
                id: ComponentId("c1"),
                technologyId: TechnologyId("aws-doubled"),
                position: Point(x: 0, y: 0),
                sensitivity: .internalData
            )
        ])

        let response = AssessThreatModel(models: InMemoryThreatModelGateway(model), catalogue: catalogue)
            .execute(AssessThreatModelRequest())

        #expect(response.threats.map(\.threatId) == ["misconfiguration"])
    }
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter AssessThreatModelTests 2>&1 | grep -E 'error:' | head -5
```

Expected: FAIL with `value of type 'AssessedThreat' has no member 'isTlsMitigated'`.

- [ ] **Step 3: Add the flag to `AssessedThreat`**

In `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/AssessThreatModel.swift`, add the stored property after `context`, add the initialiser parameter in the same position, and assign it:

```swift
    public let context: String?
    /// True when the threat is one TLS mitigates and an endpoint technology
    /// enforces encryption. Display only. It never changes `riskScore`.
    public let isTlsMitigated: Bool
```

```swift
        context: String?,
        isTlsMitigated: Bool
```

```swift
        self.context = context
        self.isTlsMitigated = isTlsMitigated
```

- [ ] **Step 4: Rewrite the use case body**

Replace the whole `public struct AssessThreatModel: AssessThreatModelUseCase { ... }` block at the bottom of the same file:

```swift
/// Resolves every threat the model raises, and scores each one.
///
/// Component threats come from the component's technology. Connection threats
/// come from the catalogue and belong to the link, not to either end. Zone
/// threats and the zone multiplier arrive in Milestone 3; every score here is
/// the base score.
public struct AssessThreatModel: AssessThreatModelUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: AssessThreatModelRequest) -> AssessThreatModelResponse {
        let model = models.current()
        var assessed: [AssessedThreat] = []
        /// Spec section 5.3: a duplicate threat and source pair is raised once.
        var raised: Set<String> = []

        func raise(_ threat: AssessedThreat) {
            let pair = "\(threat.threatId)@\(threat.source.id)"
            guard raised.contains(pair) == false else { return }
            raised.insert(pair)
            assessed.append(threat)
        }

        for component in model.components {
            guard component.threatsDisabled == false else { continue }
            guard let technology = catalogue.findById(component.technologyId) else { continue }

            for threat in catalogue.threatsFor(technologyId: component.technologyId) {
                let score = RiskScore(severity: threat.severity, sensitivity: component.sensitivity)
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
                        controls: Self.controls(for: threat, on: technology),
                        source: .component(
                            id: component.id.value,
                            name: component.customName ?? technology.name,
                            providerId: technology.provider.value
                        ),
                        sensitivityId: component.sensitivity.rawValue,
                        riskScore: score.value,
                        riskLevel: score.level.rawValue,
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

            for threat in catalogue.connectionThreats() {
                let score = RiskScore(severity: threat.severity, sensitivity: sensitivity)
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
                        // Spec section 5.3: a link always uses the threat's own
                        // controls, never a technology's mitigations.
                        controls: threat.controls.map {
                            AssessedControl(description: $0.description, isTechnologySpecific: false)
                        },
                        source: .connection(
                            id: connection.id.value,
                            sourceName: Self.name(of: source, as: sourceTechnology),
                            targetName: Self.name(of: target, as: targetTechnology)
                        ),
                        sensitivityId: sensitivity.rawValue,
                        riskScore: score.value,
                        riskLevel: score.level.rawValue,
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

        return AssessThreatModelResponse(threats: assessed.sorted(by: Self.ordering))
    }

    /// A link still raises its threats when an end's technology has left the
    /// catalogue: the threats belong to the link, and the sensitivity is stored
    /// on the component. The technology id stands in for the missing name.
    private static func name(of component: Component, as technology: Technology?) -> String {
        component.customName ?? technology?.name ?? component.technologyId.value
    }

    private static func controls(for threat: Threat, on technology: Technology) -> [AssessedControl] {
        if let specific = technology.threatMitigations[threat.id], specific.isEmpty == false {
            return specific.map { AssessedControl(description: $0, isTechnologySpecific: true) }
        }
        return threat.controls.map {
            AssessedControl(description: $0.description, isTechnologySpecific: false)
        }
    }

    private static func ordering(_ a: AssessedThreat, _ b: AssessedThreat) -> Bool {
        if a.riskScore != b.riskScore { return a.riskScore > b.riskScore }
        if a.threatId != b.threatId { return a.threatId < b.threatId }
        return a.source.id < b.source.id
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
git commit -m "feat: raise connection threats with a TLS-mitigated flag

A link raises every connection threat in the catalogue, scored against the
higher of its two ends' sensitivities, using the threat's own controls. The
TLS flag is display only. A duplicate threat and source pair is raised once."
```

---

### Task 13: The acceptance test

The milestone's outer loop. It speaks to the use case boundary only: never a Domain object, never a gateway.

**Files:**
- Create: `ThreatModelKit/Tests/AcceptanceTests/ConnectingComponentsTests.swift`

**Interfaces:**
- Consumes: `TestDependencies` and every use case it vends.
- Produces: nothing. It is the milestone's definition of done.

Fixture facts this test relies on: EC2 is `aws`/`compute` and does not enforce encryption; RDS is `aws`/`database`, declares only `misconfiguration`, and enforces encryption. Connection threats are `connection-mitm` (medium, rank 2) and `connection-dos` (low, rank 1). `SequentialIdentityGenerator` issues `id-1`, `id-2`, `id-3` in call order.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/AcceptanceTests/ConnectingComponentsTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

/// Given two technologies on my threat model
/// When I connect one to the other
/// Then the link raises its own threats, scored for the more sensitive end
struct ConnectingComponentsTests {
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

    private func assess() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    private func linkThreats() -> [AssessedThreat] {
        assess().filter {
            if case .connection = $0.source { return true } else { return false }
        }
    }

    @Test func raisesTheLinksThreatsWhenTwoComponentsAreConnected() throws {
        let web = add("aws-ec2", x: 0, y: 0, sensitivity: "confidential")
        let database = add("aws-rds", x: 300, y: 0, sensitivity: "restricted")

        #expect(app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: web, targetComponentId: database)
        ) == .connected(connectionId: "id-3"))

        let onTheLink = linkThreats()
        #expect(onTheLink.map(\.threatId) == ["connection-mitm", "connection-dos"])
        #expect(onTheLink.allSatisfy { $0.source.displayName == "EC2 → RDS" })

        // The link is scored against restricted, the higher of the two ends.
        let mitm = try #require(onTheLink.first { $0.threatId == "connection-mitm" })
        #expect(mitm.sensitivityId == "restricted")
        #expect(mitm.riskScore == 8)
        #expect(mitm.riskLevel == "high")
        #expect(mitm.controls.map(\.description) == ["Enforce TLS on every hop"])

        // RDS enforces encryption, so the man-in-the-middle threat is flagged.
        // The flag does not change either score.
        let flood = try #require(onTheLink.first { $0.threatId == "connection-dos" })
        #expect(mitm.isTlsMitigated)
        #expect(flood.isTlsMitigated == false)
        #expect(flood.riskScore == 4)
    }

    @Test func showsTheCanvasAsTheModelIsBuilt() throws {
        let web = add("aws-ec2", x: 40, y: 80, sensitivity: "confidential")
        let database = add("aws-rds", x: 300, y: 80, sensitivity: "restricted")
        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: web, targetComponentId: database)
        )

        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())

        #expect(canvas.components.map(\.name) == ["EC2", "RDS"])
        #expect(canvas.components.first?.x == 40)
        #expect(canvas.components.first?.y == 80)
        #expect(canvas.connections.map(\.sourceComponentId) == [web])
        #expect(canvas.connections.map(\.targetComponentId) == [database])
    }

    @Test func movesAComponentWithoutChangingItsThreats() throws {
        let web = add("aws-ec2", x: 0, y: 0, sensitivity: "confidential")
        let before = assess().map(\.threatId)

        #expect(app.moveComponents().execute(
            MoveComponentsRequest(moves: [ComponentMove(componentId: web, x: 250, y: 130)])
        ) == .moved(count: 1))

        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(canvas.components.first?.x == 250)
        #expect(canvas.components.first?.y == 130)
        #expect(assess().map(\.threatId) == before)
    }

    @Test func refusesASecondLinkBetweenTheSamePair() throws {
        let web = add("aws-ec2", x: 0, y: 0, sensitivity: "internal")
        let database = add("aws-rds", x: 300, y: 0, sensitivity: "internal")
        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: web, targetComponentId: database)
        )

        #expect(app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: web, targetComponentId: database)
        ) == .duplicateConnection(connectionId: "id-3"))

        #expect(app.viewThreatModel().execute(ViewThreatModelRequest()).connections.count == 1)
    }

    @Test func removingAComponentTakesItsLinkAndTheLinksThreatsWithIt() throws {
        let web = add("aws-ec2", x: 0, y: 0, sensitivity: "internal")
        let database = add("aws-rds", x: 300, y: 0, sensitivity: "internal")
        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: web, targetComponentId: database)
        )
        #expect(linkThreats().isEmpty == false)

        #expect(app.removeComponents().execute(
            RemoveComponentsRequest(componentIds: [web])
        ) == .removed(componentIds: [web], connectionIds: ["id-3"]))

        #expect(linkThreats().isEmpty)
        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(canvas.components.map(\.name) == ["RDS"])
        #expect(canvas.connections.isEmpty)
    }

    @Test func removingOnlyTheLinkLeavesBothComponents() throws {
        let web = add("aws-ec2", x: 0, y: 0, sensitivity: "internal")
        let database = add("aws-rds", x: 300, y: 0, sensitivity: "internal")
        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: web, targetComponentId: database)
        )

        #expect(app.removeConnection().execute(
            RemoveConnectionRequest(connectionId: "id-3")
        ) == .removed)

        #expect(linkThreats().isEmpty)
        #expect(app.viewThreatModel().execute(ViewThreatModelRequest()).components.count == 2)
    }
}
```

- [ ] **Step 2: Run it to verify it passes**

Tasks 3–12 exist to make this test pass, so it should be green the first time.

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter ConnectingComponentsTests 2>&1 | tail -5
```

Expected: PASS. If a case fails, the fault is in Tasks 3–12, not in this test. Read the failure and fix the use case.

- [ ] **Step 3: Run the whole package suite and time it**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && time swift test 2>&1 | tail -5
```

Expected: PASS, under 30 seconds. Spec §10 sets that target.

- [ ] **Step 4: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit/Tests/AcceptanceTests/ConnectingComponentsTests.swift
git commit -m "test: accept the milestone 2 core at the use case boundary

Connecting two components raises the link's threats scored against the more
sensitive end, moving a component changes no threat, a repeated link is
refused, and removing a component takes its link and the link's threats."
```

---

### Task 14: Canvas geometry

Five plain structs in the app target. They import `CoreGraphics` and `Foundation`, never `SwiftUI`, so every one is testable without a view. Spec §9 requires canvas geometry to live outside a `View` body.

WARNING: the app target sets `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`, so every type declared there is main-actor isolated unless it says otherwise. Declare all five types, and `ConnectionAnchor`, `nonisolated`. Without it the test suites fail to compile with "main actor-isolated default value in a nonisolated context".

**Files:**
- Create: `threatmodeller/canvas/CanvasTransform.swift`
- Create: `threatmodeller/canvas/ComponentBox.swift`
- Create: `threatmodeller/canvas/AnchorGeometry.swift`
- Create: `threatmodeller/canvas/ConnectionPath.swift`
- Create: `threatmodeller/canvas/MarqueeSelection.swift`
- Test: `threatmodellerTests/canvas/CanvasTransformTests.swift`
- Test: `threatmodellerTests/canvas/ComponentBoxTests.swift`
- Test: `threatmodellerTests/canvas/AnchorGeometryTests.swift`
- Test: `threatmodellerTests/canvas/ConnectionPathTests.swift`
- Test: `threatmodellerTests/canvas/MarqueeSelectionTests.swift`

`threatmodeller` and `threatmodellerTests` are `PBXFileSystemSynchronizedRootGroup`s, so a new subdirectory needs no `project.pbxproj` edit.

**Interfaces:**
- Consumes: nothing from the core.
- Produces:
  - `CanvasTransform(pan:zoom:)`, `.viewPoint(_:)`, `.modelPoint(_:)`, `.modelDistance(_:)`, `.panned(by:)`, `.zoomed(by:about:)`, `CanvasTransform.clamp(_:)`, `.minimumZoom`, `.maximumZoom`
  - `ComponentBox(x:y:)`, `.rect`, `.centre`, `.contains(_:)`, `ComponentBox.size`
  - `ConnectionAnchor` (`.top`, `.right`, `.bottom`, `.left`), `AnchorGeometry.point(_:of:)`, `AnchorGeometry.nearestPair(from:to:)`
  - `ConnectionPath(from:to:)`, `.point(at:)`, `.distance(to:)`, `.containsClick(at:)`, `.arrowhead(length:width:)`, `ConnectionPath.hitTolerance`
  - `MarqueeSelection.rect(from:to:)`, `MarqueeSelection.selected(in:from:)`

- [ ] **Step 1: Write the failing tests**

Create `threatmodellerTests/canvas/CanvasTransformTests.swift`:

```swift
import CoreGraphics
import Testing
@testable import threatmodeller

struct CanvasTransformTests {
    @Test func mapsAModelPointToTheView() {
        let transform = CanvasTransform(pan: CGSize(width: 30, height: 10), zoom: 2)

        #expect(transform.viewPoint(CGPoint(x: 100, y: 50)) == CGPoint(x: 230, y: 110))
    }

    @Test func mapsAViewPointBackToTheModel() {
        let transform = CanvasTransform(pan: CGSize(width: 30, height: 10), zoom: 2)

        #expect(transform.modelPoint(CGPoint(x: 230, y: 110)) == CGPoint(x: 100, y: 50))
    }

    @Test func roundTripsEveryPoint() {
        let transform = CanvasTransform(pan: CGSize(width: -17, height: 42), zoom: 0.75)
        let start = CGPoint(x: 12.5, y: -8)

        let round = transform.modelPoint(transform.viewPoint(start))
        #expect(abs(round.x - start.x) < 0.0001)
        #expect(abs(round.y - start.y) < 0.0001)
    }

    @Test func dividesADragTranslationByTheZoom() {
        let transform = CanvasTransform(zoom: 2)

        #expect(transform.modelDistance(CGSize(width: 40, height: 20)) == CGSize(width: 20, height: 10))
    }

    @Test func clampsTheZoomToItsRange() {
        #expect(CanvasTransform(zoom: 0.01).zoom == CanvasTransform.minimumZoom)
        #expect(CanvasTransform(zoom: 99).zoom == CanvasTransform.maximumZoom)
        #expect(CanvasTransform(zoom: 1.5).zoom == 1.5)
    }

    @Test func keepsTheModelPointUnderTheCursorWhileZooming() {
        let transform = CanvasTransform(pan: CGSize(width: 12, height: 8), zoom: 1)
        let cursor = CGPoint(x: 200, y: 140)
        let before = transform.modelPoint(cursor)

        let zoomed = transform.zoomed(by: 2, about: cursor)
        let after = zoomed.modelPoint(cursor)

        #expect(zoomed.zoom == 2)
        #expect(abs(after.x - before.x) < 0.0001)
        #expect(abs(after.y - before.y) < 0.0001)
    }

    @Test func doesNotMoveThePointWhenTheZoomIsAlreadyClamped() {
        let transform = CanvasTransform(zoom: CanvasTransform.maximumZoom)
        let cursor = CGPoint(x: 100, y: 100)

        let zoomed = transform.zoomed(by: 4, about: cursor)

        #expect(zoomed.zoom == CanvasTransform.maximumZoom)
        #expect(zoomed.modelPoint(cursor) == transform.modelPoint(cursor))
    }

    @Test func addsUpSuccessivePans() {
        let transform = CanvasTransform(pan: CGSize(width: 10, height: 10), zoom: 1)
            .panned(by: CGSize(width: 5, height: -3))

        #expect(transform.pan == CGSize(width: 15, height: 7))
        #expect(transform.zoom == 1)
    }
}
```

Create `threatmodellerTests/canvas/ComponentBoxTests.swift`:

```swift
import CoreGraphics
import Testing
@testable import threatmodeller

struct ComponentBoxTests {
    @Test func placesItsRectangleAtTheComponentPosition() {
        let box = ComponentBox(x: 100, y: 50)

        #expect(box.rect.origin == CGPoint(x: 100, y: 50))
        #expect(box.rect.size == ComponentBox.size)
    }

    @Test func findsItsOwnCentre() {
        let box = ComponentBox(x: 0, y: 0)

        #expect(box.centre == CGPoint(x: ComponentBox.size.width / 2, y: ComponentBox.size.height / 2))
    }

    @Test func containsAPointInsideIt() {
        let box = ComponentBox(x: 10, y: 10)

        #expect(box.contains(CGPoint(x: 20, y: 20)))
        #expect(box.contains(CGPoint(x: 9, y: 20)) == false)
        #expect(box.contains(CGPoint(x: 20, y: 10 + ComponentBox.size.height + 1)) == false)
    }
}
```

Create `threatmodellerTests/canvas/AnchorGeometryTests.swift`:

```swift
import CoreGraphics
import Testing
@testable import threatmodeller

struct AnchorGeometryTests {
    private let box = ComponentBox(x: 0, y: 0)

    @Test func placesTheFourAnchorsOnTheEdges() {
        let width = ComponentBox.size.width
        let height = ComponentBox.size.height

        #expect(AnchorGeometry.point(.top, of: box) == CGPoint(x: width / 2, y: 0))
        #expect(AnchorGeometry.point(.right, of: box) == CGPoint(x: width, y: height / 2))
        #expect(AnchorGeometry.point(.bottom, of: box) == CGPoint(x: width / 2, y: height))
        #expect(AnchorGeometry.point(.left, of: box) == CGPoint(x: 0, y: height / 2))
    }

    @Test func leavesFromTheRightAndArrivesOnTheLeftForABoxToTheRight() {
        let pair = AnchorGeometry.nearestPair(from: box, to: ComponentBox(x: 400, y: 0))

        #expect(pair.source == .right)
        #expect(pair.target == .left)
    }

    @Test func leavesFromTheLeftAndArrivesOnTheRightForABoxToTheLeft() {
        let pair = AnchorGeometry.nearestPair(from: box, to: ComponentBox(x: -400, y: 0))

        #expect(pair.source == .left)
        #expect(pair.target == .right)
    }

    @Test func leavesFromTheBottomAndArrivesOnTheTopForABoxBelow() {
        let pair = AnchorGeometry.nearestPair(from: box, to: ComponentBox(x: 0, y: 400))

        #expect(pair.source == .bottom)
        #expect(pair.target == .top)
    }

    @Test func picksTheSamePairEveryTimeForTheSameLayout() {
        let first = AnchorGeometry.nearestPair(from: box, to: ComponentBox(x: 300, y: 300))
        let second = AnchorGeometry.nearestPair(from: box, to: ComponentBox(x: 300, y: 300))

        #expect(first == second)
    }
}
```

Create `threatmodellerTests/canvas/ConnectionPathTests.swift`:

```swift
import CoreGraphics
import Testing
@testable import threatmodeller

struct ConnectionPathTests {
    private let straight = ConnectionPath(from: CGPoint(x: 0, y: 0), to: CGPoint(x: 200, y: 0))

    @Test func startsAtItsStartAndEndsAtItsEnd() {
        #expect(straight.point(at: 0) == CGPoint(x: 0, y: 0))
        #expect(straight.point(at: 1) == CGPoint(x: 200, y: 0))
    }

    @Test func selectsAClickOnTheLine() {
        #expect(straight.containsClick(at: CGPoint(x: 100, y: 0)))
        #expect(straight.containsClick(at: CGPoint(x: 100, y: ConnectionPath.hitTolerance - 1)))
    }

    @Test func ignoresAClickBeyondTheTolerance() {
        #expect(straight.containsClick(at: CGPoint(x: 100, y: ConnectionPath.hitTolerance + 20)) == false)
        #expect(straight.containsClick(at: CGPoint(x: 600, y: 0)) == false)
    }

    @Test func bulgesHorizontallyBetweenTwoOffsetPoints() {
        let curved = ConnectionPath(from: CGPoint(x: 0, y: 0), to: CGPoint(x: 200, y: 200))

        // The straight line between the two ends has x equal to y at every
        // point. The curve leaves the source horizontally, so a quarter of the
        // way along it has run ahead in x.
        let quarter = curved.point(at: 0.25)
        #expect(quarter.x > quarter.y)
        #expect(curved.containsClick(at: quarter))
        #expect(curved.containsClick(at: CGPoint(x: 0, y: 200)) == false)
    }

    @Test func pointsTheArrowheadAlongTheFinalDirection() {
        let head = straight.arrowhead(length: 10, width: 8)

        #expect(head.count == 3)
        #expect(head[0] == CGPoint(x: 200, y: 0))
        // The two base points sit 10 behind the tip and 4 either side of it.
        #expect(abs(head[1].x - 190) < 0.001)
        #expect(abs(head[2].x - 190) < 0.001)
        #expect(abs(abs(head[1].y - head[2].y) - 8) < 0.001)
    }
}
```

Create `threatmodellerTests/canvas/MarqueeSelectionTests.swift`:

```swift
import CoreGraphics
import Testing
@testable import threatmodeller

struct MarqueeSelectionTests {
    private let boxes: [(id: String, box: ComponentBox)] = [
        (id: "c1", box: ComponentBox(x: 0, y: 0)),
        (id: "c2", box: ComponentBox(x: 400, y: 0)),
        (id: "c3", box: ComponentBox(x: 0, y: 400))
    ]

    @Test func buildsARectangleFromAnyDragDirection() {
        let downRight = MarqueeSelection.rect(from: CGPoint(x: 10, y: 20), to: CGPoint(x: 110, y: 220))
        let upLeft = MarqueeSelection.rect(from: CGPoint(x: 110, y: 220), to: CGPoint(x: 10, y: 20))

        #expect(downRight == CGRect(x: 10, y: 20, width: 100, height: 200))
        #expect(downRight == upLeft)
    }

    @Test func selectsEveryBoxTheRectangleTouches() {
        let rect = CGRect(x: -10, y: -10, width: 500, height: 100)

        #expect(MarqueeSelection.selected(in: rect, from: boxes) == ["c1", "c2"])
    }

    @Test func selectsABoxTheRectangleOnlyClips() {
        let rect = CGRect(x: -50, y: -50, width: 51, height: 51)

        #expect(MarqueeSelection.selected(in: rect, from: boxes) == ["c1"])
    }

    @Test func selectsNothingWhenTheRectangleMissesEverything() {
        let rect = CGRect(x: 1000, y: 1000, width: 50, height: 50)

        #expect(MarqueeSelection.selected(in: rect, from: boxes).isEmpty)
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'error:' | head -5
```

Expected: FAIL with `cannot find 'CanvasTransform' in scope`.

- [ ] **Step 3: Write `CanvasTransform`**

Create `threatmodeller/canvas/CanvasTransform.swift`:

```swift
import CoreGraphics

/// Converts between model coordinates and canvas view coordinates.
///
/// The canvas draws its content with
/// `.scaleEffect(zoom, anchor: .topLeading).offset(pan)`, so a model point
/// lands at `modelPoint * zoom + pan`.
struct CanvasTransform: Equatable {
    static let minimumZoom: CGFloat = 0.25
    static let maximumZoom: CGFloat = 4.0

    let pan: CGSize
    let zoom: CGFloat

    init(pan: CGSize = .zero, zoom: CGFloat = 1) {
        self.pan = pan
        self.zoom = Self.clamp(zoom)
    }

    static func clamp(_ zoom: CGFloat) -> CGFloat {
        min(max(zoom, minimumZoom), maximumZoom)
    }

    func viewPoint(_ modelPoint: CGPoint) -> CGPoint {
        CGPoint(x: modelPoint.x * zoom + pan.width, y: modelPoint.y * zoom + pan.height)
    }

    func modelPoint(_ viewPoint: CGPoint) -> CGPoint {
        CGPoint(x: (viewPoint.x - pan.width) / zoom, y: (viewPoint.y - pan.height) / zoom)
    }

    /// The model distance a view distance covers. A drag translation arrives in
    /// view points and has to become a move in model units.
    func modelDistance(_ viewDistance: CGSize) -> CGSize {
        CGSize(width: viewDistance.width / zoom, height: viewDistance.height / zoom)
    }

    func panned(by translation: CGSize) -> CanvasTransform {
        CanvasTransform(
            pan: CGSize(width: pan.width + translation.width, height: pan.height + translation.height),
            zoom: zoom
        )
    }

    /// Zooms about a fixed view point, so the model point under the pointer
    /// stays under the pointer. When the new zoom clamps, the pan changes to
    /// match the clamped zoom, which leaves the point where it was.
    func zoomed(by factor: CGFloat, about viewPoint: CGPoint) -> CanvasTransform {
        let anchor = modelPoint(viewPoint)
        let newZoom = Self.clamp(zoom * factor)
        return CanvasTransform(
            pan: CGSize(
                width: viewPoint.x - anchor.x * newZoom,
                height: viewPoint.y - anchor.y * newZoom
            ),
            zoom: newZoom
        )
    }
}
```

- [ ] **Step 4: Write `ComponentBox`**

Create `threatmodeller/canvas/ComponentBox.swift`:

```swift
import CoreGraphics

/// The rectangle a component occupies, in model coordinates.
///
/// Every component draws at one fixed size, so the rectangle follows from the
/// component's position. The position is the rectangle's top-left corner,
/// which is what `AddComponent` and `MoveComponents` store.
struct ComponentBox: Equatable {
    static let size = CGSize(width: 160, height: 72)

    let origin: CGPoint

    init(x: Double, y: Double) {
        origin = CGPoint(x: x, y: y)
    }

    var rect: CGRect { CGRect(origin: origin, size: Self.size) }

    var centre: CGPoint { CGPoint(x: rect.midX, y: rect.midY) }

    func contains(_ modelPoint: CGPoint) -> Bool { rect.contains(modelPoint) }
}
```

- [ ] **Step 5: Write `AnchorGeometry`**

Create `threatmodeller/canvas/AnchorGeometry.swift`:

```swift
import CoreGraphics
import Foundation

/// Where a connection meets a component.
enum ConnectionAnchor: String, CaseIterable, Equatable {
    case top
    case right
    case bottom
    case left
}

/// The anchor points of a component box, and the pair a link between two
/// boxes uses.
enum AnchorGeometry {
    static func point(_ anchor: ConnectionAnchor, of box: ComponentBox) -> CGPoint {
        let rect = box.rect
        switch anchor {
        case .top: return CGPoint(x: rect.midX, y: rect.minY)
        case .right: return CGPoint(x: rect.maxX, y: rect.midY)
        case .bottom: return CGPoint(x: rect.midX, y: rect.maxY)
        case .left: return CGPoint(x: rect.minX, y: rect.midY)
        }
    }

    /// The anchor pair with the shortest straight line between the two boxes.
    /// A tie keeps the pair found first in `ConnectionAnchor.allCases` order,
    /// so the same layout always draws the same link.
    static func nearestPair(
        from source: ComponentBox,
        to target: ComponentBox
    ) -> (source: ConnectionAnchor, target: ConnectionAnchor) {
        var best = (source: ConnectionAnchor.top, target: ConnectionAnchor.top)
        var shortest = CGFloat.infinity

        for sourceAnchor in ConnectionAnchor.allCases {
            let start = point(sourceAnchor, of: source)
            for targetAnchor in ConnectionAnchor.allCases {
                let end = point(targetAnchor, of: target)
                let distance = hypot(end.x - start.x, end.y - start.y)
                if distance < shortest {
                    shortest = distance
                    best = (sourceAnchor, targetAnchor)
                }
            }
        }

        return best
    }
}
```

- [ ] **Step 6: Write `ConnectionPath`**

Create `threatmodeller/canvas/ConnectionPath.swift`:

```swift
import CoreGraphics
import Foundation

/// The curve a link draws, and the hit test for clicking it.
struct ConnectionPath: Equatable {
    /// How far a click may sit from the curve and still select the link, in
    /// model units.
    static let hitTolerance: CGFloat = 8

    let start: CGPoint
    let end: CGPoint
    let control1: CGPoint
    let control2: CGPoint

    init(from start: CGPoint, to end: CGPoint) {
        self.start = start
        self.end = end
        // The horizontal pull grows with the gap, with a floor so a short link
        // still curves and a ceiling so a long one does not loop back.
        let pull = max(30, min(abs(end.x - start.x) * 0.5, 150))
        control1 = CGPoint(x: start.x + pull, y: start.y)
        control2 = CGPoint(x: end.x - pull, y: end.y)
    }

    /// The point at `t`, where 0 is the start and 1 is the end.
    func point(at t: CGFloat) -> CGPoint {
        let u = 1 - t
        return CGPoint(
            x: u * u * u * start.x + 3 * u * u * t * control1.x
                + 3 * u * t * t * control2.x + t * t * t * end.x,
            y: u * u * u * start.y + 3 * u * u * t * control1.y
                + 3 * u * t * t * control2.y + t * t * t * end.y
        )
    }

    /// The shortest distance from the point to the curve, sampled at 40 steps.
    /// Sampling is enough here: the gap between two samples is far smaller than
    /// `hitTolerance` for any link the canvas draws.
    func distance(to modelPoint: CGPoint) -> CGFloat {
        (0...40).reduce(CGFloat.infinity) { shortest, step in
            let sample = point(at: CGFloat(step) / 40)
            return min(shortest, hypot(sample.x - modelPoint.x, sample.y - modelPoint.y))
        }
    }

    func containsClick(at modelPoint: CGPoint) -> Bool {
        distance(to: modelPoint) <= Self.hitTolerance
    }

    /// The three points of the arrowhead at `end`, pointing along the curve's
    /// final direction. The first point is the tip.
    func arrowhead(length: CGFloat = 10, width: CGFloat = 8) -> [CGPoint] {
        let approach = point(at: 0.98)
        let angle = atan2(end.y - approach.y, end.x - approach.x)
        let baseX = end.x - length * cos(angle)
        let baseY = end.y - length * sin(angle)

        return [
            end,
            CGPoint(x: baseX - width / 2 * sin(angle), y: baseY + width / 2 * cos(angle)),
            CGPoint(x: baseX + width / 2 * sin(angle), y: baseY - width / 2 * cos(angle))
        ]
    }
}
```

- [ ] **Step 7: Write `MarqueeSelection`**

Create `threatmodeller/canvas/MarqueeSelection.swift`:

```swift
import CoreGraphics

/// Which components a marquee rectangle selects.
enum MarqueeSelection {
    /// A rectangle from the drag's two corners, whichever way the drag went.
    static func rect(from start: CGPoint, to end: CGPoint) -> CGRect {
        CGRect(
            x: min(start.x, end.x),
            y: min(start.y, end.y),
            width: abs(end.x - start.x),
            height: abs(end.y - start.y)
        )
    }

    /// The identifiers of every box the rectangle touches, in the order given.
    /// A box counts when the rectangle overlaps it at all, which is what a user
    /// expects from a lasso.
    static func selected(in rect: CGRect, from boxes: [(id: String, box: ComponentBox)]) -> [String] {
        boxes.filter { rect.intersects($0.box.rect) }.map(\.id)
    }
}
```

- [ ] **Step 8: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | tail -5
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add threatmodeller/canvas threatmodellerTests/canvas
git commit -m "feat: add the canvas geometry structs

Coordinates, component rectangles, connection anchors, the bezier and its
click hit test, and marquee intersection. None imports SwiftUI, so all five
are tested without a view."
```

---

### Task 15: `CanvasState` and the session's canvas methods

`CanvasState` holds the transient interaction state spec §3.6 assigns to the delivery mechanism. `ThreatModelSession` keeps its own job: call use cases, publish responses.

**Files:**
- Create: `threatmodeller/canvas/CanvasState.swift`
- Modify: `threatmodeller/ThreatModelSession.swift`
- Test: `threatmodellerTests/canvas/CanvasStateTests.swift`
- Test: `threatmodellerTests/threatmodellerTests.swift`

**Interfaces:**
- Consumes: `CanvasTransform`, `MarqueeSelection`, and the use cases from Tasks 4–8.
- Produces:
  - `CanvasState.transform`, `.selectedComponentIds`, `.selectedConnectionIds`, `.dragTranslation`, `.marquee`, `.connectionDrag`, `.marqueeRect`, `.hasSelection`, `.isSelected(componentId:)`, `.isSelected(connectionId:)`, `.clearSelection()`, `.select(componentId:addingToSelection:)`, `.select(connectionId:addingToSelection:)`, `.select(componentIds:)`, `.retainOnly(componentIds:connectionIds:)`, `.cancel()`
  - `ThreatModelSession.canvas: ViewThreatModelResponse`, `.add(technologyId:x:y:)`, `.move(_:)`, `.connect(sourceComponentId:targetComponentId:)`, `.removeComponents(_:)`, `.removeConnection(_:)`

- [ ] **Step 1: Write the failing tests**

Create `threatmodellerTests/canvas/CanvasStateTests.swift`:

```swift
import CoreGraphics
import Testing
@testable import threatmodeller

@MainActor
struct CanvasStateTests {
    @Test func startsWithNothingSelected() {
        let canvas = CanvasState()

        #expect(canvas.hasSelection == false)
        #expect(canvas.selectedComponentIds.isEmpty)
        #expect(canvas.selectedConnectionIds.isEmpty)
    }

    @Test func aPlainClickSelectsOnlyThatComponent() {
        let canvas = CanvasState()

        canvas.select(componentId: "c1", addingToSelection: false)
        canvas.select(componentId: "c2", addingToSelection: false)

        #expect(canvas.selectedComponentIds == ["c2"])
    }

    @Test func aShiftClickAddsAComponentToTheSelection() {
        let canvas = CanvasState()

        canvas.select(componentId: "c1", addingToSelection: false)
        canvas.select(componentId: "c2", addingToSelection: true)

        #expect(canvas.selectedComponentIds == ["c1", "c2"])
    }

    @Test func aShiftClickOnASelectedComponentRemovesIt() {
        let canvas = CanvasState()

        canvas.select(componentId: "c1", addingToSelection: false)
        canvas.select(componentId: "c2", addingToSelection: true)
        canvas.select(componentId: "c1", addingToSelection: true)

        #expect(canvas.selectedComponentIds == ["c2"])
    }

    @Test func selectingAConnectionDropsTheComponentSelection() {
        let canvas = CanvasState()

        canvas.select(componentId: "c1", addingToSelection: false)
        canvas.select(connectionId: "k1", addingToSelection: false)

        #expect(canvas.selectedComponentIds.isEmpty)
        #expect(canvas.selectedConnectionIds == ["k1"])
        #expect(canvas.isSelected(connectionId: "k1"))
    }

    @Test func aMarqueeReplacesTheWholeSelection() {
        let canvas = CanvasState()

        canvas.select(connectionId: "k1", addingToSelection: false)
        canvas.select(componentIds: ["c1", "c2"])

        #expect(canvas.selectedComponentIds == ["c1", "c2"])
        #expect(canvas.selectedConnectionIds.isEmpty)
    }

    @Test func reportsTheMarqueeRectangleWhileADragIsInFlight() {
        let canvas = CanvasState()

        #expect(canvas.marqueeRect == nil)
        canvas.marquee = (start: CGPoint(x: 40, y: 60), end: CGPoint(x: 10, y: 20))
        #expect(canvas.marqueeRect == CGRect(x: 10, y: 20, width: 30, height: 40))
    }

    @Test func dropsSelectedRowsTheModelNoLongerHolds() {
        let canvas = CanvasState()

        canvas.select(componentIds: ["c1", "c2"])
        canvas.retainOnly(componentIds: ["c2"], connectionIds: [])

        #expect(canvas.selectedComponentIds == ["c2"])
    }

    @Test func escapeCancelsAConnectionDragBeforeItClearsTheSelection() {
        let canvas = CanvasState()

        canvas.select(componentId: "c1", addingToSelection: false)
        canvas.connectionDrag = (sourceComponentId: "c1", currentPoint: CGPoint(x: 5, y: 5))

        #expect(canvas.cancel())
        #expect(canvas.connectionDrag == nil)
        #expect(canvas.selectedComponentIds == ["c1"])

        #expect(canvas.cancel())
        #expect(canvas.hasSelection == false)

        #expect(canvas.cancel() == false)
    }
}
```

Add to `threatmodellerTests/threatmodellerTests.swift`, inside `ThreatModelSessionTests`:

```swift
    @Test func showsTheComponentItAdded() throws {
        let session = session()

        session.add(technologyId: "aws-ec2", x: 120, y: 60)

        let drawn = try #require(session.canvas.components.first)
        #expect(drawn.name == "EC2")
        #expect(drawn.x == 120)
        #expect(drawn.y == 60)
    }

    @Test func showsAndScoresALinkBetweenTwoComponents() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 300, y: 0)
        let ids = session.canvas.components.map(\.id)

        session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])

        #expect(session.canvas.connections.count == 1)
        #expect(session.threats.contains { $0.threatId == "connection-mitm" })
        #expect(session.errorMessage == nil)
    }

    @Test func saysNothingWhenTheUserRepeatsALink() {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 300, y: 0)
        let ids = session.canvas.components.map(\.id)
        session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])

        session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])

        #expect(session.canvas.connections.count == 1)
        #expect(session.errorMessage == nil)
    }

    @Test func movesAComponentToItsNewPosition() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        let id = try #require(session.canvas.components.first).id

        session.move([ComponentMove(componentId: id, x: 90, y: 45)])

        #expect(session.canvas.components.first?.x == 90)
        #expect(session.canvas.components.first?.y == 45)
    }

    @Test func removingAComponentTakesItsLinkWithIt() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 300, y: 0)
        let ids = session.canvas.components.map(\.id)
        session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])

        let removed = session.removeComponents([ids[0]])

        #expect(removed.connectionIds.count == 1)
        #expect(session.canvas.components.map(\.name) == ["RDS"])
        #expect(session.canvas.connections.isEmpty)
        #expect(session.threats.contains { $0.threatId == "connection-mitm" } == false)
    }
```

The existing `add(technologyId:)` calls in that file become `add(technologyId:x:y:)`. Update the three Milestone 1 tests to pass `x: 0, y: 0`.

- [ ] **Step 2: Run them to verify they fail**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'error:' | head -5
```

Expected: FAIL with `cannot find 'CanvasState' in scope`.

- [ ] **Step 3: Write `CanvasState`**

Create `threatmodeller/canvas/CanvasState.swift`:

```swift
import CoreGraphics
import Observation

/// Everything the canvas needs that is not part of the threat model.
///
/// Spec section 3.6 keeps pan, zoom, selection, a drag in flight, the marquee
/// and the connection preview in the delivery mechanism. This object calls no
/// use case and holds no business rule, so a drag changing 60 times a second
/// never touches the object the threat list observes.
@MainActor
@Observable
final class CanvasState {
    var transform = CanvasTransform()

    private(set) var selectedComponentIds: Set<String> = []
    private(set) var selectedConnectionIds: Set<String> = []

    /// How far the selection has moved while a node drag is in flight, in
    /// model units. Nil when no drag is in flight.
    var dragTranslation: CGSize?

    /// The marquee's two corners in model coordinates while a marquee drag is
    /// in flight.
    var marquee: (start: CGPoint, end: CGPoint)?

    /// The component a connection drag started from, and where the pointer is
    /// now, in model coordinates.
    var connectionDrag: (sourceComponentId: String, currentPoint: CGPoint)?

    var marqueeRect: CGRect? {
        marquee.map { MarqueeSelection.rect(from: $0.start, to: $0.end) }
    }

    var hasSelection: Bool {
        selectedComponentIds.isEmpty == false || selectedConnectionIds.isEmpty == false
    }

    func isSelected(componentId: String) -> Bool { selectedComponentIds.contains(componentId) }

    func isSelected(connectionId: String) -> Bool { selectedConnectionIds.contains(connectionId) }

    func clearSelection() {
        selectedComponentIds = []
        selectedConnectionIds = []
    }

    /// A plain click selects only that component. A shift-click adds it, or
    /// removes it when it is already selected.
    func select(componentId: String, addingToSelection: Bool) {
        selectedConnectionIds = []
        guard addingToSelection else {
            selectedComponentIds = [componentId]
            return
        }
        if selectedComponentIds.contains(componentId) {
            selectedComponentIds.remove(componentId)
        } else {
            selectedComponentIds.insert(componentId)
        }
    }

    func select(connectionId: String, addingToSelection: Bool) {
        selectedComponentIds = []
        guard addingToSelection else {
            selectedConnectionIds = [connectionId]
            return
        }
        if selectedConnectionIds.contains(connectionId) {
            selectedConnectionIds.remove(connectionId)
        } else {
            selectedConnectionIds.insert(connectionId)
        }
    }

    /// The result of a marquee drag. It replaces the whole selection.
    func select(componentIds: [String]) {
        selectedComponentIds = Set(componentIds)
        selectedConnectionIds = []
    }

    /// Drops selected rows the model no longer holds. Call after any removal.
    func retainOnly(componentIds: Set<String>, connectionIds: Set<String>) {
        selectedComponentIds.formIntersection(componentIds)
        selectedConnectionIds.formIntersection(connectionIds)
    }

    /// Escape: cancel a connection drag when one is in flight, else clear the
    /// selection. Returns true when it changed something.
    @discardableResult
    func cancel() -> Bool {
        if connectionDrag != nil {
            connectionDrag = nil
            return true
        }
        if hasSelection {
            clearSelection()
            return true
        }
        return false
    }
}
```

- [ ] **Step 4: Give the session its canvas methods**

Replace the whole of `threatmodeller/ThreatModelSession.swift`:

```swift
import Observation
import ThreatModelKit

/// Translates user intent into use case calls and publishes the responses.
/// Holds no business rules and names no gateway.
///
/// Main-actor isolated: every caller is a SwiftUI view, and the use cases it
/// calls are synchronous. `ThreatModelGateway` has no atomic append, so a
/// second concurrent caller would lose a change; the isolation keeps that
/// impossible while the port stays as it is.
@MainActor
@Observable
final class ThreatModelSession {
    private let useCases: UseCaseFactory

    private(set) var palette: [ListedProvider] = []
    /// What the canvas draws. Spec section 9 calls this the canvas snapshot.
    private(set) var canvas = ViewThreatModelResponse(name: "Untitled", components: [], connections: [])
    private(set) var threats: [AssessedThreat] = []
    private(set) var errorMessage: String?

    init(useCases: UseCaseFactory) {
        self.useCases = useCases
        palette = useCases.listTechnologies().execute(ListTechnologiesRequest()).providers
        refresh()
    }

    func add(technologyId: String, x: Double, y: Double) {
        // Sensitivity is fixed until a later milestone gives the user a
        // control for it.
        let response = useCases.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: x, y: y, sensitivity: "internal")
        )

        switch response {
        case .added:
            errorMessage = nil
        case .unknownTechnology:
            errorMessage = "That technology is not in the catalogue."
        case .unknownSensitivity:
            errorMessage = "That data sensitivity is not recognised."
        }

        refresh()
    }

    func move(_ moves: [ComponentMove]) {
        switch useCases.moveComponents().execute(MoveComponentsRequest(moves: moves)) {
        case .moved:
            errorMessage = nil
        case .unknownComponent:
            errorMessage = "That component is no longer on the model."
        }

        refresh()
    }

    func connect(sourceComponentId: String, targetComponentId: String) {
        let response = useCases.connectComponents().execute(
            ConnectComponentsRequest(
                sourceComponentId: sourceComponentId,
                targetComponentId: targetComponentId
            )
        )

        switch response {
        case .connected:
            errorMessage = nil
        // The canvas already shows the user that nothing new was drawn, so
        // neither refusal needs a message.
        case .duplicateConnection, .selfConnection:
            errorMessage = nil
        case .unknownComponent:
            errorMessage = "That component is no longer on the model."
        }

        refresh()
    }

    /// Returns what left the model so the canvas can drop those rows from its
    /// selection.
    @discardableResult
    func removeComponents(_ componentIds: [String]) -> (componentIds: [String], connectionIds: [String]) {
        let response = useCases.removeComponents().execute(
            RemoveComponentsRequest(componentIds: componentIds)
        )

        defer { refresh() }

        switch response {
        case .removed(let removedComponents, let removedConnections):
            errorMessage = nil
            return (removedComponents, removedConnections)
        case .unknownComponent:
            errorMessage = "That component is no longer on the model."
            return ([], [])
        }
    }

    func removeConnection(_ connectionId: String) {
        switch useCases.removeConnection().execute(
            RemoveConnectionRequest(connectionId: connectionId)
        ) {
        case .removed:
            errorMessage = nil
        case .unknownConnection:
            errorMessage = "That connection is no longer on the model."
        }

        refresh()
    }

    /// Spec section 2: the delivery mechanism calls `AssessThreatModel`
    /// explicitly after each change, and reads the canvas the same way.
    private func refresh() {
        canvas = useCases.viewThreatModel().execute(ViewThreatModelRequest())
        threats = useCases.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | tail -5
```

Expected: FAIL to compile `ContentView.swift`, which still calls `session.add(technologyId:)`. Change that one call site to `session.add(technologyId: technology.id, x: 0, y: 0)`; Task 17 replaces it properly. Then the suite passes.

- [ ] **Step 6: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add threatmodeller threatmodellerTests
git commit -m "feat: add CanvasState and the session's canvas methods

CanvasState holds pan, zoom, selection and the drags in flight, so a drag
never changes the object the threat list observes. The session gains one
method per new use case and publishes the canvas snapshot."
```

---

### Task 16: The canvas view

**Files:**
- Create: `threatmodeller/canvas/ConnectionsLayer.swift`
- Create: `threatmodeller/canvas/ComponentNodeView.swift`
- Create: `threatmodeller/canvas/CanvasView.swift`
- Modify: `threatmodeller/ContentView.swift`

**Interfaces:**
- Consumes: `ThreatModelSession`, `CanvasState`, and every geometry struct from Task 14.
- Produces: `CanvasView(session:canvas:)`; accessibility identifiers `canvas`, `node-<technologyId>`, `zoom-in`, `zoom-out`, `zoom-reset`.

Decisions this task fixes, because the spec leaves them open:

- The content layer draws in model coordinates. One modifier applies the transform: `.scaleEffect(zoom, anchor: .topLeading).offset(pan)`. Every gesture reads its location in the named coordinate space `canvas` and converts with `CanvasTransform`.
- A plain drag on the background draws the marquee. A drag on the background with the Command key held pans. Pinch zooms about the pinch centre. Three buttons give zoom in, zoom out and reset, so zoom works without a trackpad.
- A click within `ConnectionPath.hitTolerance` of a link selects the link. A click on empty background clears the selection.

- [ ] **Step 1: Write the connections layer**

Create `threatmodeller/canvas/ConnectionsLayer.swift`:

```swift
import SwiftUI
import ThreatModelKit

/// Every link drawn in one `Canvas` pass, plus the preview line while a
/// connection drag is in flight. Spec section 9 sets this painting order.
struct ConnectionsLayer: View {
    let connections: [ViewedConnection]
    let boxes: [String: ComponentBox]
    let selectedConnectionIds: Set<String>
    let preview: (start: CGPoint, end: CGPoint)?

    var body: some View {
        Canvas { context, _ in
            for connection in connections {
                guard let source = boxes[connection.sourceComponentId],
                      let target = boxes[connection.targetComponentId] else { continue }

                let anchors = AnchorGeometry.nearestPair(from: source, to: target)
                let path = ConnectionPath(
                    from: AnchorGeometry.point(anchors.source, of: source),
                    to: AnchorGeometry.point(anchors.target, of: target)
                )
                draw(path, in: &context, selected: selectedConnectionIds.contains(connection.id))
            }

            if let preview {
                draw(
                    ConnectionPath(from: preview.start, to: preview.end),
                    in: &context,
                    selected: true,
                    dashed: true
                )
            }
        }
        .allowsHitTesting(false)
    }

    private func draw(
        _ connection: ConnectionPath,
        in context: inout GraphicsContext,
        selected: Bool,
        dashed: Bool = false
    ) {
        var curve = Path()
        curve.move(to: connection.start)
        curve.addCurve(to: connection.end, control1: connection.control1, control2: connection.control2)

        let colour: Color = selected ? .accentColor : .secondary
        context.stroke(
            curve,
            with: .color(colour),
            style: StrokeStyle(lineWidth: selected ? 2.5 : 1.5, dash: dashed ? [6, 4] : [])
        )

        let head = connection.arrowhead()
        var arrow = Path()
        arrow.move(to: head[0])
        arrow.addLine(to: head[1])
        arrow.addLine(to: head[2])
        arrow.closeSubpath()
        context.fill(arrow, with: .color(colour))
    }
}
```

- [ ] **Step 2: Write the component node view**

Create `threatmodeller/canvas/ComponentNodeView.swift`:

```swift
import SwiftUI
import ThreatModelKit

/// One component on the canvas, with the four anchor handles a connection
/// drag starts from.
struct ComponentNodeView: View {
    let component: ViewedComponent
    let isSelected: Bool
    let onSelect: (_ addingToSelection: Bool) -> Void
    let onDragChanged: (CGSize) -> Void
    let onDragEnded: (CGSize) -> Void
    let onAnchorDragChanged: (CGPoint) -> Void
    let onAnchorDragEnded: (CGPoint) -> Void

    @State private var isHovering = false

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 10)
                .fill(Color(nsColor: .controlBackgroundColor))
                .overlay(
                    RoundedRectangle(cornerRadius: 10)
                        .strokeBorder(
                            isSelected ? Color.accentColor : Color.secondary.opacity(0.4),
                            lineWidth: isSelected ? 2.5 : 1
                        )
                )
                .shadow(radius: isSelected ? 4 : 1)

            VStack(alignment: .leading, spacing: 4) {
                Text(component.name)
                    .font(.headline)
                    .lineLimit(1)
                HStack(spacing: 6) {
                    Text(component.providerId.isEmpty ? "unknown" : component.providerId.uppercased())
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    Text(component.sensitivityId.capitalized)
                        .font(.caption2)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(Capsule().fill(Color.secondary.opacity(0.15)))
                }
            }
            .frame(width: ComponentBox.size.width - 24, alignment: .leading)

            if isHovering || isSelected {
                ForEach(ConnectionAnchor.allCases, id: \.self) { anchor in
                    anchorHandle(anchor)
                }
            }
        }
        .frame(width: ComponentBox.size.width, height: ComponentBox.size.height)
        .contentShape(Rectangle())
        .onHover { isHovering = $0 }
        .accessibilityIdentifier("node-\(component.technologyId)")
        .gesture(
            SpatialTapGesture().modifiers(.shift).onEnded { _ in onSelect(true) }
                .exclusively(before: SpatialTapGesture().onEnded { _ in onSelect(false) })
        )
        .gesture(
            DragGesture(minimumDistance: 3, coordinateSpace: .named("canvas"))
                .onChanged { onDragChanged($0.translation) }
                .onEnded { onDragEnded($0.translation) }
        )
    }

    private func anchorHandle(_ anchor: ConnectionAnchor) -> some View {
        let box = ComponentBox(x: 0, y: 0)
        let point = AnchorGeometry.point(anchor, of: box)

        return Circle()
            .fill(Color.accentColor)
            .frame(width: 9, height: 9)
            .position(x: point.x, y: point.y)
            .gesture(
                DragGesture(minimumDistance: 1, coordinateSpace: .named("canvas"))
                    .onChanged { onAnchorDragChanged($0.location) }
                    .onEnded { onAnchorDragEnded($0.location) }
            )
    }
}
```

- [ ] **Step 3: Write the canvas view**

Create `threatmodeller/canvas/CanvasView.swift`:

```swift
import SwiftUI
import ThreatModelKit

/// The diagram. Painting order per spec section 9: background, then every
/// connection in one `Canvas` pass, then the component views.
struct CanvasView: View {
    let session: ThreatModelSession
    let canvas: CanvasState

    /// The Command-drag translation already applied to the pan.
    @State private var lastPanTranslation: CGSize = .zero

    private var boxes: [String: ComponentBox] {
        var found: [String: ComponentBox] = [:]
        for component in session.canvas.components {
            found[component.id] = box(for: component)
        }
        return found
    }

    var body: some View {
        ZStack(alignment: .topLeading) {
            Color(nsColor: .textBackgroundColor)
                .contentShape(Rectangle())
                .gesture(backgroundTap)
                .gesture(backgroundDrag)

            content
                .scaleEffect(canvas.transform.zoom, anchor: .topLeading)
                .offset(x: canvas.transform.pan.width, y: canvas.transform.pan.height)
                .allowsHitTesting(true)

            zoomControls
        }
        .coordinateSpace(.named("canvas"))
        .accessibilityIdentifier("canvas")
        .focusable()
        .focusEffectDisabled()
        .onKeyPress(.escape) {
            canvas.cancel() ? .handled : .ignored
        }
        .onKeyPress(.delete) {
            deleteSelection()
            return .handled
        }
        .gesture(
            MagnifyGesture()
                .onChanged { value in
                    canvas.transform = canvas.transform.zoomed(
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
                x: point.x - ComponentBox.size.width / 2,
                y: point.y - ComponentBox.size.height / 2
            )
            return true
        }
    }

    @ViewBuilder
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
                let box = box(for: component)
                ComponentNodeView(
                    component: component,
                    isSelected: canvas.isSelected(componentId: component.id),
                    onSelect: { addingToSelection in
                        canvas.select(componentId: component.id, addingToSelection: addingToSelection)
                    },
                    onDragChanged: { translation in
                        if canvas.isSelected(componentId: component.id) == false {
                            canvas.select(componentId: component.id, addingToSelection: false)
                        }
                        canvas.dragTranslation = canvas.transform.modelDistance(translation)
                    },
                    onDragEnded: { translation in
                        commitDrag(canvas.transform.modelDistance(translation))
                    },
                    onAnchorDragChanged: { location in
                        canvas.connectionDrag = (
                            sourceComponentId: component.id,
                            currentPoint: canvas.transform.modelPoint(location)
                        )
                    },
                    onAnchorDragEnded: { location in
                        commitConnection(from: component.id, to: canvas.transform.modelPoint(location))
                    }
                )
                .position(x: box.centre.x, y: box.centre.y)
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
            Button { zoom(by: 1 / 1.25) } label: { Image(systemName: "minus.magnifyingglass") }
                .accessibilityIdentifier("zoom-out")
            Button { canvas.transform = CanvasTransform() } label: { Image(systemName: "1.magnifyingglass") }
                .accessibilityIdentifier("zoom-reset")
            Button { zoom(by: 1.25) } label: { Image(systemName: "plus.magnifyingglass") }
                .accessibilityIdentifier("zoom-in")
        }
        .buttonStyle(.bordered)
        .padding(8)
    }

    /// The component's position is the box's top-left corner; a drag in flight
    /// shifts every selected component by the same amount.
    private func box(for component: ViewedComponent) -> ComponentBox {
        let shift = canvas.isSelected(componentId: component.id)
            ? (canvas.dragTranslation ?? .zero)
            : .zero
        return ComponentBox(x: component.x + shift.width, y: component.y + shift.height)
    }

    private var previewLine: (start: CGPoint, end: CGPoint)? {
        guard let drag = canvas.connectionDrag,
              let source = boxes[drag.sourceComponentId] else { return nil }
        return (start: source.centre, end: drag.currentPoint)
    }

    private func zoom(by factor: CGFloat) {
        canvas.transform = canvas.transform.zoomed(by: factor, about: CGPoint(x: 400, y: 300))
    }

    private var backgroundTap: some Gesture {
        SpatialTapGesture(coordinateSpace: .named("canvas")).onEnded { value in
            let point = canvas.transform.modelPoint(value.location)
            if let connectionId = connection(under: point) {
                canvas.select(connectionId: connectionId, addingToSelection: false)
            } else {
                canvas.clearSelection()
            }
        }
    }

    private var backgroundDrag: some Gesture {
        // Command-drag pans; a plain drag draws the marquee. A drag reports the
        // translation from where it started, so the pan applies the step since
        // the last change, not the whole translation again.
        DragGesture(minimumDistance: 2, coordinateSpace: .named("canvas"))
            .modifiers(.command)
            .onChanged { value in
                let step = CGSize(
                    width: value.translation.width - lastPanTranslation.width,
                    height: value.translation.height - lastPanTranslation.height
                )
                lastPanTranslation = value.translation
                canvas.transform = canvas.transform.panned(by: step)
            }
            .onEnded { _ in lastPanTranslation = .zero }
            .exclusively(
                before: DragGesture(minimumDistance: 2, coordinateSpace: .named("canvas"))
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
            )
    }

    private func connection(under modelPoint: CGPoint) -> String? {
        for connection in session.canvas.connections {
            guard let source = boxes[connection.sourceComponentId],
                  let target = boxes[connection.targetComponentId] else { continue }
            let anchors = AnchorGeometry.nearestPair(from: source, to: target)
            let path = ConnectionPath(
                from: AnchorGeometry.point(anchors.source, of: source),
                to: AnchorGeometry.point(anchors.target, of: target)
            )
            if path.containsClick(at: modelPoint) { return connection.id }
        }
        return nil
    }

    private func commitDrag(_ translation: CGSize) {
        let moves = session.canvas.components
            .filter { canvas.isSelected(componentId: $0.id) }
            .map {
                ComponentMove(
                    componentId: $0.id,
                    x: $0.x + translation.width,
                    y: $0.y + translation.height
                )
            }
        canvas.dragTranslation = nil
        guard moves.isEmpty == false else { return }
        session.move(moves)
    }

    private func commitConnection(from sourceComponentId: String, to modelPoint: CGPoint) {
        canvas.connectionDrag = nil
        guard let target = session.canvas.components.first(where: {
            ComponentBox(x: $0.x, y: $0.y).contains(modelPoint)
        }) else { return }
        session.connect(sourceComponentId: sourceComponentId, targetComponentId: target.id)
    }

    private func deleteSelection() {
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
}
```

- [ ] **Step 4: Give the window its third column**

In `threatmodeller/ContentView.swift`, replace `ModelView`:

```swift
private struct ModelView: View {
    let session: ThreatModelSession
    @State private var canvas = CanvasState()

    var body: some View {
        NavigationSplitView {
            PaletteView(session: session)
                .navigationSplitViewColumnWidth(min: 220, ideal: 260)
        } content: {
            CanvasView(session: session, canvas: canvas)
                .navigationTitle("Diagram")
                .navigationSplitViewColumnWidth(min: 400, ideal: 700)
        } detail: {
            ThreatListView(session: session)
                .navigationSplitViewColumnWidth(min: 280, ideal: 360)
        }
    }
}
```

- [ ] **Step 5: Build and run the suites**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | tail -5
```

Expected: PASS.

- [ ] **Step 6: Look at it**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' build 2>&1 | tail -3
open "$(xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -showBuildSettings 2>/dev/null | awk -F' = ' '/ BUILT_PRODUCTS_DIR/ {print $2; exit}')/threatmodeller.app"
```

Check by eye: a component added from the palette appears on the canvas; dragging it moves it and it stays where it is dropped; dragging from an anchor to another node draws a link with an arrowhead; clicking the link selects it; the delete key removes the selection; the marquee selects several nodes; the zoom buttons work.

- [ ] **Step 7: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add threatmodeller
git commit -m "feat: draw the threat model on a canvas

Zones, then connections in one Canvas pass, then component views, per the
spec's painting order. Drag moves the selection, an anchor drag draws a link,
a marquee selects, the delete key removes, and escape cancels."
```

---

### Task 17: Drag from the palette, double-click to add

**Files:**
- Modify: `threatmodeller/ContentView.swift`

**Interfaces:**
- Consumes: `CanvasView`'s `dropDestination(for: String.self)` from Task 16.
- Produces: `TechnologyRow` as a drag source carrying the technology id; double-click adds at the canvas centre.

- [ ] **Step 1: Write the failing test**

The drop path is driven by `NSItemProvider` and is not reachable from a unit test. The user interface test in Task 18 covers the double-click path. Write no unit test here; Task 18 is this task's test.

- [ ] **Step 2: Give the session a default drop point**

A double-click carries no canvas location. Put the component near the top left of the canvas, stepped by how many components are already there, so two double-clicks do not stack one on top of another.

Add to `threatmodeller/ThreatModelSession.swift`:

```swift
    /// Where a double-click on a palette row puts a component, in model
    /// coordinates. A drag from the palette uses the drop point instead.
    static let defaultDropPoint = (x: 80.0, y: 80.0)

    /// Adds a component at the default drop point, stepped so repeated
    /// double-clicks do not stack one component on another.
    func addAtDefaultPoint(technologyId: String) {
        let step = Double(canvas.components.count % 8) * 32
        add(
            technologyId: technologyId,
            x: Self.defaultDropPoint.x + step,
            y: Self.defaultDropPoint.y + step
        )
    }
```

- [ ] **Step 3: Make the palette row a drag source and a double-click target**

In `threatmodeller/ContentView.swift`, replace `TechnologyRow`:

```swift
/// A technology row. Drag it onto the canvas to place it where it is dropped,
/// or double-click it to place it near the top left of the canvas.
private struct TechnologyRow: View {
    let technology: ListedTechnology
    let session: ThreatModelSession

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(technology.name)
            Text(technology.description)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(Rectangle())
        .accessibilityIdentifier("technology-\(technology.id)")
        .draggable(technology.id) {
            Text(technology.name)
                .padding(6)
                .background(RoundedRectangle(cornerRadius: 6).fill(Color.accentColor.opacity(0.2)))
        }
        .onTapGesture(count: 2) {
            session.addAtDefaultPoint(technologyId: technology.id)
        }
    }
}
```

Delete the `Button` wrapper Milestone 1 used on this row. A single click now only selects the row; the double-click adds the technology.

- [ ] **Step 4: Cover the stepping with a test**

Add to `threatmodellerTests/threatmodellerTests.swift`:

```swift
    @Test func stepsRepeatedDoubleClicksSoTheyDoNotStack() {
        let session = session()

        session.addAtDefaultPoint(technologyId: "aws-ec2")
        session.addAtDefaultPoint(technologyId: "aws-ec2")

        let points = session.canvas.components.map { CGPoint(x: $0.x, y: $0.y) }
        #expect(points.count == 2)
        #expect(points[0] != points[1])
    }
```

Add `import CoreGraphics` to the top of that file.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | tail -5
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add threatmodeller threatmodellerTests
git commit -m "feat: place a technology by drag or by double-click

A palette row is a drag source carrying the technology id; the canvas drops
it at the pointer. A double-click places it near the top left, stepped so
repeated double-clicks do not stack."
```

---

### Task 18: User interface tests

Deletes the two template leftovers the carry-forward records, and extends the journey to the canvas.

**Files:**
- Modify: `threatmodellerUITests/threatmodellerUITests.swift`
- Delete: `threatmodellerUITests/threatmodellerUITestsLaunchTests.swift`

**Interfaces:**
- Consumes: accessibility identifiers `category-<provider>-<category>`, `technology-<id>`, `node-<technologyId>`, `canvas`.
- Produces: nothing.

- [ ] **Step 1: Delete the template leftovers**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git rm threatmodellerUITests/threatmodellerUITestsLaunchTests.swift
```

Delete the `testLaunchPerformance` method from `threatmodellerUITests/threatmodellerUITests.swift`. Both launch the application and cover nothing.

- [ ] **Step 2: Extend the journey**

In `threatmodellerUITests/threatmodellerUITests.swift`, change the two lines that add the technology. The palette row now adds on a double-click, and the outcome to assert is a node on the canvas as well as the threats.

Replace:

```swift
        // Add the technology.
        mark("clicking the EC2 row")
        technology.click()
```

with:

```swift
        // Add the technology. A single click only selects the row; a
        // double-click places it on the canvas.
        mark("double-clicking the EC2 row")
        technology.doubleClick()

        // If the row were dead, no node would appear on the canvas.
        XCTAssertTrue(
            app.otherElements["node-aws-ec2"].firstMatch.waitForExistence(timeout: 10),
            "Double-clicking the EC2 row did not put a node on the canvas."
        )
```

Leave the threat assertions that follow as they are.

- [ ] **Step 3: Run the user interface suite**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller \
    -destination 'platform=macOS' -only-testing:threatmodellerUITests test 2>&1 | tail -20
```

Expected: PASS.

WARNING: if `node-aws-ec2` is not found, the node view's accessibility element may be reported as a `staticText` or a `button` rather than an `otherElement`. Query `app.descendants(matching: .any)["node-aws-ec2"]` instead of guessing, and keep the identifier.

- [ ] **Step 4: Run every suite**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && time swift test 2>&1 | tail -5
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | tail -20
```

Expected: PASS, package suite under 30 seconds.

- [ ] **Step 5: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add threatmodellerUITests
git commit -m "test: walk the journey as far as the canvas

The two template leftovers that launched the app and covered nothing are
gone. The journey now double-clicks a palette row and asserts a node appears
on the canvas before it reads the threats."
```

---

## Milestone complete

Check every line before you call the milestone done:

- [ ] `swift test` from `ThreatModelKit/` is green and runs in under 30 seconds.
- [ ] `xcodebuild ... test` is green, including the user interface suite.
- [ ] The app target builds in Swift 6 language mode: `grep -c 'SWIFT_VERSION = 6.0;' threatmodeller.xcodeproj/project.pbxproj` reports `6`.
- [ ] `UseCaseFactory` lives in `ThreatModelKit`, and `Dependencies` and `TestDependencies` both conform.
- [ ] `threatmodellerTests` builds `TestDependencies` and names no vendored catalogue number.
- [ ] A duplicate threat and source pair is raised once.
- [ ] Dragging a palette row onto the canvas places the component where it is dropped.
- [ ] A drag moves the whole selection, and the component stays where it is dropped.
- [ ] A drag from an anchor to another node draws a link with an arrowhead, and the link raises its threats.
- [ ] The same pair cannot be linked twice in the same direction; the reverse pair can.
- [ ] Clicking a link selects it; the delete key removes it.
- [ ] Deleting a component removes the links that touch it and their threats.
- [ ] A marquee drag selects every node it touches; shift-click adds and removes.
- [ ] Escape cancels a connection drag, then clears the selection.
- [ ] Pinch and the three zoom buttons change the zoom; Command-drag pans.
- [ ] The catalogue tag is still `v1.0.1`.

Then write `docs/superpowers/specs/MILESTONE-3-CARRY-FORWARD.md` recording what Milestone 2 deliberately deferred, and start the Milestone 3 plan.

Still deferred from Milestone 1, with the trigger unchanged:

- `ThreatModelGateway` has no atomic append. Every caller is synchronous and main-actor isolated. Add the atomic append operation before any caller becomes asynchronous, or in Milestone 6 when documents open concurrently.
- `BundledTechnologyCatalogue.threatsFor` drops a dangling threat id with no signal; the gateway traps on a duplicate technology id; the fake returns the first match where the real one traps. All three are safe against tag `v1.0.1` and must be fixed before the tag rises.
- `IdentityGenerator` and `ThreatModelGateway` still have no shared contract. Add one as each port gains a second implementation.
- `ThreatModelSession` still fixes `sensitivity: "internal"`. A later milestone gives the user a sensitivity control.
- `ContentView` shows `String(describing: error)` when the catalogue fails to load.
