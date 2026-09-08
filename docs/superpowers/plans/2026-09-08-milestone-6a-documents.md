# Milestone 6A: Documents — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The user's work survives quitting the application. A threat model is a file they can name, save, reopen, and open several of at once, and when a saved model meets a newer catalogue the application says what has drifted rather than quietly dropping it.

**Architecture:** A `ThreatModelCodec` in a new `FileGateways` package target turns a `ThreatModel` into the JSON of spec §8 and back. Each open document owns its own `Dependencies` graph and its own `ThreatModelGateway`, as spec §3.5 states. `ThreatModelGateway` gains an atomic `mutate`, because SwiftUI can ask a `FileDocument` for its bytes off the main thread.

**Tech Stack:** Swift 6.3, Swift Package Manager, Swift Testing, SwiftUI, macOS 26.

**Spec:** `docs/superpowers/specs/2026-09-07-native-macos-threat-modeller-design.md`

**Carry-forward:** `docs/superpowers/specs/MILESTONE-6-CARRY-FORWARD.md`

**Read Task 5 before starting Task 1.** Task 5 is the acceptance test — the outer loop.

## Global Constraints

- Everything in the Milestone 5 plan's Global Constraints still holds.
- WARNING: two source files in one module may not share a basename.
- WARNING: a key path passed to a `rethrows` method inside `#expect` fails to compile; use a closure. `#expect` keeps each operand's own type, so convert a `CGFloat` before comparing it with a `Double`.
- WARNING: the app saves its split-view arrangement. If the user interface suite fails at its first assertion with no window, run `osascript -e 'tell application "threatmodeller" to quit'` then `defaults delete uk.craigbass.threatmodeller`.
- UTType `io.threatmodeller.model`, filename extension `.threatmodel`, a single JSON file.
- The document carries its own format version, separate from the catalogue version. A reader that meets a version it does not know refuses the file rather than guessing at it.
- The core must not read or write a file. The codec lives in `FileGateways` and takes and returns `Data`.
- Catalogue pinned at `v1.0.1`.
- Commit after every task. Never commit a red suite.

## Out of scope for this milestone

Undo, redo, copy, cut, paste, duplicate, menu commands and keyboard shortcuts: those are Milestone 6B, and `pushHistory()`, `undo()` and `redo()` stay off `ThreatModelGateway` until then. Custom technologies and external actors are Milestone 7; the document format holds a field for them so a 6A file still reads in Milestone 7, and 6A writes it empty.

Everything on `MILESTONE-6-CARRY-FORWARD.md` keeps its trigger, except the two this milestone closes.

## What this milestone closes from the carry-forward

- **Item 1, the non-atomic gateway append.** SwiftUI can call `fileWrapper(configuration:)` off the main thread, so the concurrent caller the port's own doc comment warned about now exists. Task 1 gives the port an atomic `mutate` and a lock, and every write use case moves onto it.
- **Item 7, the fixed 20000 point drawing square.** A saved model can carry far-apart items, so Task 10 sizes the drawing layer from the model's own bounds.

Item 3, the missing `ThreatModelGateway` contract, is written in Task 1 even though the port still has one implementation: `mutate` has behaviour worth pinning, and a second implementation is easier to add against a contract than to retrofit one to.

## File Structure

**Created:**

| Path | Responsibility |
|---|---|
| `.../catalogue/domain/CatalogueVersion.swift` | `CatalogueVersion` |
| `.../modelling/gateway/Clock.swift` | The `Clock` port, `SystemClock`, and the epoch |
| `.../modelling/usecase/CreateThreatModel.swift` | and its Request/Response |
| `.../modelling/usecase/OpenThreatModel.swift` | and its Request/Response, including the drift report |
| `.../modelling/usecase/SaveThreatModel.swift` | and its Request/Response |
| `.../modelling/usecase/RenameThreatModel.swift` | and its Request/Response |
| `ThreatModelKit/Sources/FileGateways/ThreatModelCodec.swift` | The JSON of spec §8, both ways |
| `ThreatModelKit/Sources/FileGateways/DocumentJSON.swift` | `Codable` shapes mirroring the file |
| `ThreatModelKit/Sources/TestSupport/ThreatModelGatewayContract.swift` | The shared contract |
| `ThreatModelKit/Sources/TestSupport/FixedClock.swift` | Deterministic time |
| `ThreatModelKit/Tests/GatewayContractTests/ThreatModelGatewayContractTests.swift` | The contract run |
| `ThreatModelKit/Tests/UnitTests/DocumentUseCaseTests.swift` | The four document use cases |
| `ThreatModelKit/Tests/GatewayIntegrationTests/ThreatModelCodecTests.swift` | Round-trip and refusal |
| `ThreatModelKit/Tests/AcceptanceTests/KeepingAThreatModelTests.swift` | The milestone's outer loop |
| `threatmodeller/ThreatModelDocument.swift` | The `FileDocument` and its UTType |

**Modified:**

- `ThreatModelKit/Package.swift` — the `FileGateways` target and product
- `.../modelling/gateway/ThreatModelGateway.swift` — `mutate`, and a lock on the in-memory store
- every write use case — read, change and write in one step
- `.../modelling/domain/ThreatModel.swift` — gains `createdAt`, `updatedAt`, `catalogueVersion`
- `.../catalogue/gateway/TechnologyCatalogue.swift` and both implementations — `version()`
- `.../UseCaseFactory.swift`, `.../TestDependencies.swift`, `threatmodeller/Dependencies.swift`
- `threatmodeller/threatmodellerApp.swift` — `DocumentGroup`
- `threatmodeller/ContentView.swift` — takes the document's session
- `threatmodeller/canvas/CanvasView.swift` — the drawing layer follows the model
- `threatmodeller.xcodeproj/project.pbxproj` — the exported type, and the `FileGateways` product
- `threatmodellerUITests/threatmodellerUITests.swift` — the journey opens a window

---

### Task 1: An atomic gateway, and its contract

Closes carry-forward item 1. SwiftUI can ask a `FileDocument` for its bytes on a background thread while the main actor is part-way through a use case, so `current()` then `save(_:)` can lose a change. The port gains one operation that reads, changes and writes without a gap.

**Files:**
- Modify: `.../modelling/gateway/ThreatModelGateway.swift`
- Modify: every use case that writes — `AddComponent`, `MoveComponents`, `RemoveComponents`, `ConnectComponents`, `RemoveConnection`, `AddZone`, `ResizeZone`, `SetZoneProperties`, `RemoveZone`, `OverrideThreatSeverity`, `ClearSeverityOverride`, `RecordControlImplemented`, `RecordControlNotImplemented`, `ConfigurePathwayMitigations`
- Create: `ThreatModelKit/Sources/TestSupport/ThreatModelGatewayContract.swift`
- Create: `ThreatModelKit/Tests/GatewayContractTests/ThreatModelGatewayContractTests.swift`

**Interfaces:**
- Produces: `ThreatModelGateway.mutate<T>(_ change: (inout ThreatModel) -> T) -> T`; `verifyThreatModelGatewayContract(_:)`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Sources/TestSupport/ThreatModelGatewayContract.swift`:

```swift
import Testing
import ThreatModelKit

/// The behaviour every `ThreatModelGateway` must exhibit, expressed entirely in
/// Domain objects. Run it against every implementation.
public func verifyThreatModelGatewayContract(_ make: () -> ThreatModelGateway) {
    let component = Component(
        id: ComponentId("c1"),
        technologyId: TechnologyId("aws-ec2"),
        position: Point(x: 0, y: 0),
        sensitivity: .internalData
    )

    let empty = make()
    #expect(empty.current().components.isEmpty)

    let saved = make()
    saved.save(ThreatModel(name: "Payments", components: [component]))
    #expect(saved.current().name == "Payments")
    #expect(saved.current().components.map(\.id) == [component.id])

    // `mutate` reads, changes and writes without a gap, and hands back
    // whatever the change returns.
    let mutated = make()
    let count = mutated.mutate { model -> Int in
        model.components.append(component)
        return model.components.count
    }
    #expect(count == 1)
    #expect(mutated.current().components.map(\.id) == [component.id])

    // Two hundred appends, each read-modify-write, all from different threads.
    // Every one must survive: that is the whole reason the operation exists.
    let raced = make()
    DispatchQueue.concurrentPerform(iterations: 200) { index in
        raced.mutate { model in
            model.components.append(
                Component(
                    id: ComponentId("c\(index)"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .internalData
                )
            )
        }
    }
    #expect(raced.current().components.count == 200)

    // Reading while others write must not trap or tear.
    let read = make()
    DispatchQueue.concurrentPerform(iterations: 100) { index in
        if index.isMultiple(of: 2) {
            read.mutate { $0.name = "n\(index)" }
        } else {
            _ = read.current().name
        }
    }
    #expect(read.current().name.isEmpty == false)
}
```

WARNING: `DispatchQueue` needs `import Foundation` in that file. Add it.

Create `ThreatModelKit/Tests/GatewayContractTests/ThreatModelGatewayContractTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct ThreatModelGatewayContractTests {
    @Test func theInMemoryStoreHonoursTheContract() {
        verifyThreatModelGatewayContract { InMemoryThreatModelGateway() }
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter ThreatModelGatewayContractTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `has no member 'mutate'`.

- [ ] **Step 3: Give the port its atomic operation**

Replace `.../modelling/gateway/ThreatModelGateway.swift`:

```swift
import Foundation

/// Holds the model currently being edited.
///
/// One gateway serves one model. `current()` and `save(_:)` are each atomic,
/// but a use case that reads, changes and writes has a gap between them, and
/// SwiftUI can ask a document for its bytes on a background thread while the
/// main actor is part-way through one. `mutate` closes that gap: every write
/// use case reads, changes and writes in one step.
public protocol ThreatModelGateway: AnyObject, Sendable {
    func current() -> ThreatModel
    func save(_ model: ThreatModel)
    /// Read, change and write without a gap. Returns whatever the change
    /// returns, so a use case can decide its response inside the same step.
    func mutate<T>(_ change: (inout ThreatModel) -> T) -> T
}

/// The model store for one open document. A document seeds it on open and
/// reads it back on save.
///
/// The lock is the whole point: the document's writer runs wherever SwiftUI
/// puts it, and the editor runs on the main actor.
public final class InMemoryThreatModelGateway: ThreatModelGateway, @unchecked Sendable {
    private let lock = NSLock()
    private var model: ThreatModel

    public init(_ model: ThreatModel = ThreatModel()) {
        self.model = model
    }

    public func current() -> ThreatModel {
        lock.lock()
        defer { lock.unlock() }
        return model
    }

    public func save(_ model: ThreatModel) {
        lock.lock()
        defer { lock.unlock() }
        self.model = model
    }

    public func mutate<T>(_ change: (inout ThreatModel) -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return change(&model)
    }
}
```

`@unchecked Sendable` is stated rather than inferred: the lock is what makes it safe, and the compiler cannot see that.

- [ ] **Step 4: Move every write use case onto it**

Each write use case currently reads with `current()`, changes a local copy and writes with `save(_:)`. Each becomes one `mutate` call whose closure returns the response. `AddComponent` is the pattern; do the same to the other thirteen:

```swift
    public func execute(_ request: AddComponentRequest) -> AddComponentResponse {
        let technologyId = TechnologyId(request.technologyId)
        guard catalogue.findById(technologyId) != nil else {
            return .unknownTechnology
        }
        guard let sensitivity = DataSensitivity(rawValue: request.sensitivity) else {
            return .unknownSensitivity
        }

        let component = Component(
            id: ComponentId(ids.next()),
            technologyId: technologyId,
            position: Point(x: request.x, y: request.y),
            sensitivity: sensitivity
        )

        return models.mutate { model in
            model.components.append(component)
            return .added(componentId: component.id.value)
        }
    }
```

WARNING: anything that must not happen when the use case refuses — taking an identifier from the generator, for one — stays **outside** the `mutate` closure and before it, exactly as it is now. Only the read, the change and the write move inside.

For a use case that must check the model before it decides, the check moves inside too:

```swift
    public func execute(_ request: RemoveConnectionRequest) -> RemoveConnectionResponse {
        let id = ConnectionId(request.connectionId)

        return models.mutate { model in
            guard model.connections.contains(where: { $0.id == id }) else {
                return .unknownConnection
            }
            model.connections.removeAll { $0.id == id }
            return .removed
        }
    }
```

`ConnectComponents` takes an identifier from the generator only after its rules pass. Keep that order: check inside `mutate`, and call `ids.next()` inside the closure after the guards. The generator is called at most once per successful call either way.

- [ ] **Step 5: Run every suite**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

Expected: PASS. No behaviour changed for a single-threaded caller; the contract proves it holds for many.

- [ ] **Step 6: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit
git commit -m "feat: give the model gateway an atomic change, and a contract

SwiftUI can ask a document for its bytes on a background thread while the
main actor is part-way through a use case, so read-then-write could lose a
change. Every write use case now reads, changes and writes in one step, and
the contract races two hundred appends to prove it."
```

---

### Task 2: `Clock`, `CatalogueVersion`, and what a model remembers

**Files:**
- Create: `.../modelling/gateway/Clock.swift`
- Create: `.../catalogue/domain/CatalogueVersion.swift`
- Create: `ThreatModelKit/Sources/TestSupport/FixedClock.swift`
- Modify: `.../modelling/domain/ThreatModel.swift`
- Modify: `.../catalogue/gateway/TechnologyCatalogue.swift` and both implementations
- Modify: `.../TestSupport/CatalogueFixture.swift`, `TechnologyCatalogueContract.swift`
- Modify: `ThreatModelKit/Tests/GatewayIntegrationTests/BundledTechnologyCatalogueTests.swift`

**Interfaces:**
- Produces: `Clock` with `now() -> Date`, `SystemClock`; `FixedClock(_:)` with `advance(by:)`; `CatalogueVersion(repository:tag:)`; `TechnologyCatalogue.version() -> CatalogueVersion`; `ThreatModel.createdAt`, `.updatedAt`, `.catalogueVersion`.

- [ ] **Step 1: Write the failing test**

Add to `verifyTechnologyCatalogueContract`:

```swift
    let version = subject.version()
    #expect(version.repository.isEmpty == false)
    #expect(version.tag.isEmpty == false)
```

Add to `BundledTechnologyCatalogueTests`:

```swift
    @Test func reportsTheVersionItWasVendoredAt() throws {
        let version = try BundledTechnologyCatalogue().version()

        #expect(version.repository == "jib1337/threat-model-library")
        #expect(version.tag == "v1.0.1")
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter TechnologyCatalogueContractTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `has no member 'version'`.

- [ ] **Step 3: Write the two values and the port**

Create `.../catalogue/domain/CatalogueVersion.swift`:

```swift
/// Which vendored catalogue a model was last assessed against.
///
/// A saved model stamps this, so opening it against a newer catalogue can say
/// what has drifted rather than quietly dropping it.
public struct CatalogueVersion: Equatable, Sendable {
    public let repository: String
    public let tag: String

    public init(repository: String, tag: String) {
        self.repository = repository
        self.tag = tag
    }

    public var description: String { "\(repository) \(tag)" }
}
```

Create `.../modelling/gateway/Clock.swift`:

```swift
import Foundation

/// Reads the time. A use case that stamps a document takes one of these, so a
/// test can say what the time is.
public protocol Clock: Sendable {
    func now() -> Date
}

public struct SystemClock: Clock {
    public init() {}
    public func now() -> Date { Date() }
}
```

Create `ThreatModelKit/Sources/TestSupport/FixedClock.swift`:

```swift
import Foundation
import ThreatModelKit

/// A clock that does not move unless a test moves it.
public final class FixedClock: Clock, @unchecked Sendable {
    private let lock = NSLock()
    private var current: Date

    public init(_ start: Date = Date(timeIntervalSince1970: 1_000_000)) {
        current = start
    }

    public func now() -> Date {
        lock.lock()
        defer { lock.unlock() }
        return current
    }

    public func advance(by seconds: TimeInterval) {
        lock.lock()
        defer { lock.unlock() }
        current = current.addingTimeInterval(seconds)
    }
}
```

Add to `TechnologyCatalogue`:

```swift
    /// The vendored catalogue this gateway reads.
    func version() -> CatalogueVersion
```

`InMemoryTechnologyCatalogue` takes one in its initialiser, defaulting to `CatalogueVersion(repository: "fixture", tag: "v0.0.0")`. `BundledTechnologyCatalogue` decodes `repository` and `tag` from `library.lock.json`; add `LockFileJSON` to `CatalogueJSON.swift`:

```swift
struct LockFileJSON: Decodable {
    let repository: String
    let tag: String
}
```

- [ ] **Step 4: Give the model its timestamps and its stamp**

Add to `ThreatModel`, as the last three stored properties and initialiser parameters:

```swift
    /// When the model was first created, and when it last changed. A document
    /// carries both. Spec section 8.
    public var createdAt: Date
    public var updatedAt: Date
    /// The catalogue the model was last assessed against, or nil for a model
    /// that has never been saved.
    public var catalogueVersion: CatalogueVersion?
```

with defaults `Date(timeIntervalSince1970: 0)` for both dates and `nil` for the version, so every existing construction still compiles. `ThreatModel` needs `import Foundation`.

WARNING: defaulting the dates keeps 300 existing test constructions compiling. `CreateThreatModel` sets them properly; nothing else should read them for anything but the file.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit
git commit -m "feat: add a clock, a catalogue version, and what a model remembers

A saved model stamps the catalogue it was last assessed against, so opening
it against a newer one can say what has drifted rather than quietly dropping
it. A use case that stamps a document takes a clock, so a test can say what
the time is."
```

---

### Task 3: The file format

**Files:**
- Modify: `ThreatModelKit/Package.swift`
- Create: `.../modelling/gateway/ThreatModelFileGateway.swift`
- Create: `ThreatModelKit/Sources/FileGateways/DocumentJSON.swift`
- Create: `ThreatModelKit/Sources/FileGateways/ThreatModelCodec.swift`
- Create: `ThreatModelKit/Tests/GatewayIntegrationTests/ThreatModelCodecTests.swift`

**Interfaces:**
- Consumes: every modelling and assessment value the model holds.
- Produces: `ThreatModelFileGateway` with `encode(_:) throws -> Data` and `decode(_:) throws -> ThreatModel`; `ThreatModelFileError`; `ThreatModelCodec()` and `ThreatModelCodec.formatVersion`.

The bytes are the only thing that crosses the boundary. A use case takes and returns `Data`; the delivery mechanism never sees a Domain object, and the core never opens a file.

The file, per spec §8:

```json
{
  "formatVersion": 1,
  "name": "Payments",
  "createdAt": "2026-09-08T09:00:00Z",
  "updatedAt": "2026-09-08T09:30:00Z",
  "catalogue": { "repository": "jib1337/threat-model-library", "tag": "v1.0.1" },
  "components": [
    { "id": "…", "technologyId": "aws-ec2", "x": 100, "y": 100,
      "sensitivity": "confidential", "customName": null, "threatsDisabled": false }
  ],
  "connections": [ { "id": "…", "source": "…", "target": "…" } ],
  "zones": [
    { "id": "…", "x": 0, "y": 0, "width": 600, "height": 500, "name": null,
      "networkZone": "private", "networkType": "generic",
      "riskReductionEnabled": true, "riskReductionPercent": 20 }
  ],
  "customTechnologies": [],
  "severityOverrides": { "aws-ec2::credential-theft": "low" },
  "implementedControls": [ "node:…:credential-theft::0002b606" ],
  "pathwayMitigations": {
    "isMasterEnabled": false,
    "configs": { "waf-protection": { "isEnabled": true, "mode": "reduce", "reductionPercent": 50 } }
  }
}
```

`customTechnologies` is written empty and read back ignored. Milestone 7 fills it, and a 6A file still reads then.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/GatewayIntegrationTests/ThreatModelCodecTests.swift`:

```swift
import Foundation
import Testing
import ThreatModelKit
import FileGateways

struct ThreatModelCodecTests {
    private let codec = ThreatModelCodec()

    private func fullModel() -> ThreatModel {
        ThreatModel(
            name: "Payments",
            components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 100, y: 200),
                    sensitivity: .confidential,
                    customName: "Web tier",
                    threatsDisabled: true
                ),
                Component(
                    id: ComponentId("c2"),
                    technologyId: TechnologyId("aws-rds"),
                    position: Point(x: 500, y: 200),
                    sensitivity: .restricted
                )
            ],
            connections: [
                Connection(id: ConnectionId("k1"), source: ComponentId("c1"), target: ComponentId("c2"))
            ],
            zones: [
                Zone(
                    id: ZoneId("z1"),
                    rect: Rect(x: 0, y: 0, width: 600, height: 500),
                    name: "Payments VPC",
                    networkZone: .privateZone,
                    networkType: .vpc,
                    riskReductionEnabled: true,
                    riskReductionPercent: 35
                )
            ],
            severityOverrides: [
                SeverityOverrideKey("aws-ec2::credential-theft"): "low"
            ],
            implementedControls: [ControlKey("node:c1:credential-theft::0002b606")],
            pathwayMitigations: PathwayMitigationSettings(
                isMasterEnabled: true,
                configs: [
                    PathwayMitigationId("waf-protection"):
                        PathwayMitigationConfig(isEnabled: false, mode: .remove, reductionPercent: 80)
                ]
            ),
            createdAt: Date(timeIntervalSince1970: 1_000_000),
            updatedAt: Date(timeIntervalSince1970: 2_000_000),
            catalogueVersion: CatalogueVersion(repository: "jib1337/threat-model-library", tag: "v1.0.1")
        )
    }

    @Test func carriesEverythingThroughARoundTrip() throws {
        let original = fullModel()

        let read = try codec.decode(try codec.encode(original))

        #expect(read == original)
    }

    @Test func carriesAnEmptyModelThrough() throws {
        let empty = ThreatModel()

        #expect(try codec.decode(try codec.encode(empty)) == empty)
    }

    @Test func writesTheFormatVersionAndTheCatalogueStamp() throws {
        let data = try codec.encode(fullModel())
        let json = try #require(
            try JSONSerialization.jsonObject(with: data) as? [String: Any]
        )

        #expect(json["formatVersion"] as? Int == ThreatModelCodec.formatVersion)
        #expect(ThreatModelCodec.formatVersion == 1)
        let catalogue = try #require(json["catalogue"] as? [String: Any])
        #expect(catalogue["tag"] as? String == "v1.0.1")
        #expect(json["customTechnologies"] as? [Any] != nil)
    }

    @Test func writesSomethingAPersonCanRead() throws {
        let text = try #require(String(data: try codec.encode(fullModel()), encoding: .utf8))

        // A threat model is a document a team reviews in a pull request, so the
        // file is pretty-printed with stable key order.
        #expect(text.contains("\n"))
        #expect(text.contains("\"name\" : \"Payments\""))
    }

    @Test func refusesAFormatVersionItDoesNotKnow() throws {
        var json = try #require(
            try JSONSerialization.jsonObject(with: try codec.encode(ThreatModel())) as? [String: Any]
        )
        json["formatVersion"] = 99
        let data = try JSONSerialization.data(withJSONObject: json)

        #expect(throws: ThreatModelFileError.unsupportedFormatVersion(found: 99, supported: 1)) {
            try codec.decode(data)
        }
    }

    @Test func refusesBytesThatAreNotAThreatModel() {
        #expect(throws: (any Error).self) {
            try codec.decode(Data("not a threat model".utf8))
        }
    }

    @Test func refusesAValueTheVocabularyDoesNotHold() throws {
        var json = try #require(
            try JSONSerialization.jsonObject(with: try codec.encode(fullModel())) as? [String: Any]
        )
        var zones = try #require(json["zones"] as? [[String: Any]])
        zones[0]["networkType"] = "mainframe"
        json["zones"] = zones

        #expect(throws: ThreatModelFileError.unknownValue(field: "networkType", value: "mainframe")) {
            try codec.decode(try JSONSerialization.data(withJSONObject: json))
        }
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter ThreatModelCodecTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `no such module 'FileGateways'`.

- [ ] **Step 3: Add the target**

In `ThreatModelKit/Package.swift`, add the product and the target, and give `GatewayIntegrationTests` the dependency:

```swift
        .library(name: "FileGateways", targets: ["FileGateways"]),
```

```swift
        .target(name: "FileGateways", dependencies: ["ThreatModelKit"]),
```

```swift
        .testTarget(
            name: "GatewayIntegrationTests",
            dependencies: ["ThreatModelKit", "CatalogueGateways", "FileGateways"]
        )
```

- [ ] **Step 4: Write the port**

Create `.../modelling/gateway/ThreatModelFileGateway.swift`:

```swift
import Foundation

public enum ThreatModelFileError: Error, Equatable {
    /// The file says it is a version this application does not read. Refusing
    /// is the point: guessing at an unknown shape loses the user's work
    /// quietly, and a later version can always be taught to read it.
    case unsupportedFormatVersion(found: Int, supported: Int)
    /// A value outside the vocabulary — a sensitivity, a zone kind, a network
    /// type or a mitigation mode this application does not have.
    case unknownValue(field: String, value: String)
}

/// Turns a model into the bytes of a document, and back.
///
/// The only thing that crosses this boundary is `Data`. The core never opens a
/// file, and the delivery mechanism never sees a Domain object.
public protocol ThreatModelFileGateway: Sendable {
    func encode(_ model: ThreatModel) throws -> Data
    func decode(_ data: Data) throws -> ThreatModel
}
```

- [ ] **Step 5: Write the shapes and the codec**

Create `ThreatModelKit/Sources/FileGateways/DocumentJSON.swift`:

```swift
import Foundation

// Mirrors the file of spec section 8 exactly. These types exist only so the
// codec can build Domain objects; nothing outside this target sees them.

struct DocumentJSON: Codable {
    let formatVersion: Int
    let name: String
    let createdAt: Date
    let updatedAt: Date
    let catalogue: CatalogueStampJSON?
    let components: [ComponentJSON]
    let connections: [ConnectionJSON]
    let zones: [ZoneJSON]
    /// Milestone 7 fills this. Written empty and read back ignored, so a
    /// Milestone 6 file still reads once Milestone 7 lands.
    let customTechnologies: [String]
    let severityOverrides: [String: String]
    let implementedControls: [String]
    let pathwayMitigations: PathwayMitigationsJSON
}

struct CatalogueStampJSON: Codable {
    let repository: String
    let tag: String
}

struct ComponentJSON: Codable {
    let id: String
    let technologyId: String
    let x: Double
    let y: Double
    let sensitivity: String
    let customName: String?
    let threatsDisabled: Bool
}

struct ConnectionJSON: Codable {
    let id: String
    let source: String
    let target: String
}

struct ZoneJSON: Codable {
    let id: String
    let x: Double
    let y: Double
    let width: Double
    let height: Double
    let name: String?
    let networkZone: String
    let networkType: String
    let riskReductionEnabled: Bool
    let riskReductionPercent: Int
}

struct PathwayMitigationsJSON: Codable {
    let isMasterEnabled: Bool
    let configs: [String: PathwayMitigationConfigJSON]
}

struct PathwayMitigationConfigJSON: Codable {
    let isEnabled: Bool
    let mode: String
    let reductionPercent: Int
}
```

Create `ThreatModelKit/Sources/FileGateways/ThreatModelCodec.swift`:

```swift
import Foundation
import ThreatModelKit

/// Reads and writes the document format of spec section 8.
///
/// The file is pretty-printed with sorted keys: a threat model is a document a
/// team reviews in a pull request, and a diff of one line should be one line.
public struct ThreatModelCodec: ThreatModelFileGateway {
    /// This application's own format version, separate from the catalogue's.
    public static let formatVersion = 1

    public init() {}

    public func encode(_ model: ThreatModel) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        return try encoder.encode(
            DocumentJSON(
                formatVersion: Self.formatVersion,
                name: model.name,
                createdAt: model.createdAt,
                updatedAt: model.updatedAt,
                catalogue: model.catalogueVersion.map {
                    CatalogueStampJSON(repository: $0.repository, tag: $0.tag)
                },
                components: model.components.map {
                    ComponentJSON(
                        id: $0.id.value,
                        technologyId: $0.technologyId.value,
                        x: $0.position.x,
                        y: $0.position.y,
                        sensitivity: $0.sensitivity.rawValue,
                        customName: $0.customName,
                        threatsDisabled: $0.threatsDisabled
                    )
                },
                connections: model.connections.map {
                    ConnectionJSON(id: $0.id.value, source: $0.source.value, target: $0.target.value)
                },
                zones: model.zones.map {
                    ZoneJSON(
                        id: $0.id.value,
                        x: $0.rect.origin.x,
                        y: $0.rect.origin.y,
                        width: $0.rect.size.width,
                        height: $0.rect.size.height,
                        name: $0.name,
                        networkZone: $0.networkZone.rawValue,
                        networkType: $0.networkType.rawValue,
                        riskReductionEnabled: $0.riskReductionEnabled,
                        riskReductionPercent: $0.riskReductionPercent
                    )
                },
                customTechnologies: [],
                severityOverrides: Dictionary(
                    uniqueKeysWithValues: model.severityOverrides.map { ($0.key.value, $0.value) }
                ),
                implementedControls: model.implementedControls.map(\.value).sorted(),
                pathwayMitigations: PathwayMitigationsJSON(
                    isMasterEnabled: model.pathwayMitigations.isMasterEnabled,
                    configs: Dictionary(
                        uniqueKeysWithValues: model.pathwayMitigations.configs.map {
                            (
                                $0.key.value,
                                PathwayMitigationConfigJSON(
                                    isEnabled: $0.value.isEnabled,
                                    mode: $0.value.mode.rawValue,
                                    reductionPercent: $0.value.reductionPercent
                                )
                            )
                        }
                    )
                )
            )
        )
    }

    public func decode(_ data: Data) throws -> ThreatModel {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let document = try decoder.decode(DocumentJSON.self, from: data)

        guard document.formatVersion == Self.formatVersion else {
            throw ThreatModelFileError.unsupportedFormatVersion(
                found: document.formatVersion,
                supported: Self.formatVersion
            )
        }

        return ThreatModel(
            name: document.name,
            components: try document.components.map { component in
                ThreatModelKit.Component(
                    id: ComponentId(component.id),
                    technologyId: TechnologyId(component.technologyId),
                    position: Point(x: component.x, y: component.y),
                    sensitivity: try Self.value(
                        DataSensitivity(rawValue: component.sensitivity),
                        field: "sensitivity",
                        raw: component.sensitivity
                    ),
                    customName: component.customName,
                    threatsDisabled: component.threatsDisabled
                )
            },
            connections: document.connections.map {
                Connection(
                    id: ConnectionId($0.id),
                    source: ComponentId($0.source),
                    target: ComponentId($0.target)
                )
            },
            zones: try document.zones.map { zone in
                Zone(
                    id: ZoneId(zone.id),
                    rect: Rect(x: zone.x, y: zone.y, width: zone.width, height: zone.height),
                    name: zone.name,
                    networkZone: try Self.value(
                        NetworkZone(rawValue: zone.networkZone),
                        field: "networkZone",
                        raw: zone.networkZone
                    ),
                    networkType: try Self.value(
                        ZoneNetworkType(rawValue: zone.networkType),
                        field: "networkType",
                        raw: zone.networkType
                    ),
                    riskReductionEnabled: zone.riskReductionEnabled,
                    riskReductionPercent: zone.riskReductionPercent
                )
            },
            severityOverrides: Dictionary(
                uniqueKeysWithValues: document.severityOverrides.map {
                    (SeverityOverrideKey($0.key), $0.value)
                }
            ),
            implementedControls: Set(document.implementedControls.map(ControlKey.init)),
            pathwayMitigations: PathwayMitigationSettings(
                isMasterEnabled: document.pathwayMitigations.isMasterEnabled,
                configs: Dictionary(
                    uniqueKeysWithValues: try document.pathwayMitigations.configs.map { id, config in
                        (
                            PathwayMitigationId(id),
                            PathwayMitigationConfig(
                                isEnabled: config.isEnabled,
                                mode: try Self.value(
                                    PathwayMitigationMode(rawValue: config.mode),
                                    field: "mode",
                                    raw: config.mode
                                ),
                                reductionPercent: config.reductionPercent
                            )
                        )
                    }
                )
            ),
            createdAt: document.createdAt,
            updatedAt: document.updatedAt,
            catalogueVersion: document.catalogue.map {
                CatalogueVersion(repository: $0.repository, tag: $0.tag)
            }
        )
    }

    /// A vocabulary value this application does not hold is refused by name, so
    /// the message says which field and which value rather than "corrupt file".
    private static func value<T>(_ decoded: T?, field: String, raw: String) throws -> T {
        guard let decoded else {
            throw ThreatModelFileError.unknownValue(field: field, value: raw)
        }
        return decoded
    }
}
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

Expected: PASS. The round trip is the whole test: everything the model holds must survive it.

- [ ] **Step 7: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit
git commit -m "feat: read and write the document format

One JSON file, pretty-printed with sorted keys, because a threat model is a
document a team reviews in a pull request. The only thing crossing the
boundary is Data: the core never opens a file and the delivery mechanism
never sees a Domain object. A file whose format version this application does
not know is refused rather than guessed at."
```

---

### Task 4: `CreateThreatModel`, `RenameThreatModel`, `SaveThreatModel`, `OpenThreatModel`

**Files:**
- Create: the four use case files under `.../modelling/usecase/`
- Modify: `.../UseCaseFactory.swift`, `.../TestDependencies.swift`, `threatmodeller/Dependencies.swift`
- Create: `ThreatModelKit/Tests/UnitTests/DocumentUseCaseTests.swift`

**Interfaces:**
- Consumes: `ThreatModelGateway.mutate`, `Clock`, `TechnologyCatalogue.version()`, `ThreatModelFileGateway`.
- Produces:
  - `CreateThreatModelUseCase`, `CreateThreatModelRequest(name:)`, `CreateThreatModelResponse` (`.created`, `.emptyName`)
  - `RenameThreatModelUseCase`, `RenameThreatModelRequest(name:)`, `RenameThreatModelResponse` (`.renamed`, `.emptyName`)
  - `SaveThreatModelUseCase`, `SaveThreatModelRequest()`, `SaveThreatModelResponse` (`.saved(data:)`, `.notWritable(reason:)`)
  - `OpenThreatModelUseCase`, `OpenThreatModelRequest(data:)`, `OpenThreatModelResponse` (`.opened(name:drift:)`, `.unreadable(reason:)`), `ThreatModelDrift(savedCatalogueTag:currentCatalogueTag:unknownTechnologyIds:)` with `.hasDrift`

`TestDependencies` gains a `FixedClock` and a `ThreatModelCodec`, so an acceptance test can save and reopen without a file. That makes `TestSupport` depend on `FileGateways`; add it in `Package.swift`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/DocumentUseCaseTests.swift`:

```swift
import Foundation
import Testing
import ThreatModelKit
import TestSupport
import FileGateways

struct DocumentUseCaseTests {
    private let models = InMemoryThreatModelGateway()
    private let catalogue = CatalogueFixture.catalogue()
    private let clock = FixedClock()
    private let codec = ThreatModelCodec()

    private func create(_ name: String) -> CreateThreatModelResponse {
        CreateThreatModel(models: models, catalogue: catalogue, clock: clock)
            .execute(CreateThreatModelRequest(name: name))
    }

    private func rename(_ name: String) -> RenameThreatModelResponse {
        RenameThreatModel(models: models, clock: clock)
            .execute(RenameThreatModelRequest(name: name))
    }

    private func save() -> SaveThreatModelResponse {
        SaveThreatModel(models: models, catalogue: catalogue, clock: clock, files: codec)
            .execute(SaveThreatModelRequest())
    }

    private func open(_ data: Data) -> OpenThreatModelResponse {
        OpenThreatModel(models: models, catalogue: catalogue, files: codec)
            .execute(OpenThreatModelRequest(data: data))
    }

    private func savedData() throws -> Data {
        guard case .saved(let data) = save() else {
            Issue.record("Expected the model to be saved")
            return Data()
        }
        return data
    }

    // MARK: create

    @Test func startsAModelNamedAndStamped() {
        #expect(create("Payments") == .created)

        let model = models.current()
        #expect(model.name == "Payments")
        #expect(model.createdAt == clock.now())
        #expect(model.updatedAt == clock.now())
        #expect(model.catalogueVersion == catalogue.version())
        #expect(model.components.isEmpty)
    }

    @Test func emptiesWhateverWasThereBefore() {
        models.save(
            ThreatModel(components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .internalData
                )
            ])
        )

        _ = create("Fresh")

        #expect(models.current().components.isEmpty)
    }

    @Test func refusesAnEmptyName() {
        #expect(create("   ") == .emptyName)
        #expect(models.current().name == "Untitled")
    }

    // MARK: rename

    @Test func renamesAndTouchesTheModel() {
        _ = create("Payments")
        clock.advance(by: 60)

        #expect(rename("  Payments v2  ") == .renamed)

        #expect(models.current().name == "Payments v2")
        #expect(models.current().updatedAt == clock.now())
        // Creating is not renaming: the created time does not move.
        #expect(models.current().createdAt != models.current().updatedAt)
    }

    @Test func refusesToRenameToNothing() {
        _ = create("Payments")

        #expect(rename("") == .emptyName)
        #expect(models.current().name == "Payments")
    }

    // MARK: save

    @Test func stampsTheSaveWithTheTimeAndTheCatalogue() throws {
        _ = create("Payments")
        clock.advance(by: 3600)

        let data = try savedData()

        #expect(models.current().updatedAt == clock.now())
        #expect(models.current().catalogueVersion == catalogue.version())
        #expect(data.isEmpty == false)
    }

    @Test func savesEverythingTheModelHolds() throws {
        _ = create("Payments")
        _ = AddComponent(models: models, catalogue: catalogue, ids: SequentialIdentityGenerator())
            .execute(AddComponentRequest(technologyId: "aws-ec2", x: 10, y: 20, sensitivity: "restricted"))

        let data = try savedData()
        let reopened = InMemoryThreatModelGateway()
        _ = OpenThreatModel(models: reopened, catalogue: catalogue, files: codec)
            .execute(OpenThreatModelRequest(data: data))

        #expect(reopened.current().components.map(\.technologyId.value) == ["aws-ec2"])
        #expect(reopened.current().components.first?.sensitivity == .restricted)
    }

    // MARK: open

    @Test func opensWhatItSaved() throws {
        _ = create("Payments")
        let data = try savedData()
        models.save(ThreatModel())

        #expect(open(data) == .opened(
            name: "Payments",
            drift: ThreatModelDrift(
                savedCatalogueTag: catalogue.version().tag,
                currentCatalogueTag: catalogue.version().tag,
                unknownTechnologyIds: []
            )
        ))
        #expect(models.current().name == "Payments")
    }

    @Test func leavesTheModelAloneWhenTheBytesAreNotAThreatModel() {
        _ = create("Payments")

        guard case .unreadable(let reason) = open(Data("nonsense".utf8)) else {
            Issue.record("Expected the bytes to be refused")
            return
        }
        #expect(reason.isEmpty == false)
        #expect(models.current().name == "Payments")
    }

    @Test func reportsATechnologyTheCatalogueNoLongerHolds() throws {
        _ = create("Payments")
        models.mutate { model in
            model.components.append(
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-retired"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .internalData
                )
            )
        }
        let data = try savedData()

        guard case .opened(_, let drift) = open(data) else {
            Issue.record("Expected the model to open")
            return
        }
        #expect(drift.unknownTechnologyIds == ["aws-retired"])
        #expect(drift.hasDrift)
    }

    @Test func reportsACatalogueThatHasMovedOn() throws {
        _ = create("Payments")
        let data = try savedData()

        let newer = InMemoryTechnologyCatalogue(
            technologies: [CatalogueFixture.ec2()],
            threats: CatalogueFixture.ec2Threats(),
            taxonomy: CatalogueFixture.taxonomy(),
            providers: CatalogueFixture.providers(),
            version: CatalogueVersion(repository: "fixture", tag: "v9.9.9")
        )

        guard case .opened(_, let drift) = OpenThreatModel(
            models: models,
            catalogue: newer,
            files: codec
        ).execute(OpenThreatModelRequest(data: data)) else {
            Issue.record("Expected the model to open")
            return
        }
        #expect(drift.savedCatalogueTag == "v0.0.0")
        #expect(drift.currentCatalogueTag == "v9.9.9")
        #expect(drift.hasDrift)
    }

    @Test func reportsNoDriftForAModelThatMatches() throws {
        _ = create("Payments")
        let data = try savedData()

        guard case .opened(_, let drift) = open(data) else {
            Issue.record("Expected the model to open")
            return
        }
        #expect(drift.hasDrift == false)
    }

    @Test func neverTouchesTheModelJustByOpeningIt() throws {
        _ = create("Payments")
        let saved = try savedData()
        let savedAt = models.current().updatedAt
        clock.advance(by: 9999)

        _ = open(saved)

        // Opening is reading. The updated time is what the file says.
        #expect(models.current().updatedAt == savedAt)
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter DocumentUseCaseTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'CreateThreatModel' in scope`.

- [ ] **Step 3: Write the four use cases**

Create `.../modelling/usecase/CreateThreatModel.swift`:

```swift
public protocol CreateThreatModelUseCase {
    func execute(_ request: CreateThreatModelRequest) -> CreateThreatModelResponse
}

public struct CreateThreatModelRequest: Equatable, Sendable {
    public let name: String
    public init(name: String) { self.name = name }
}

public enum CreateThreatModelResponse: Equatable, Sendable {
    case created
    case emptyName
}

/// Starts a new, empty model, stamped with the time and the catalogue.
public struct CreateThreatModel: CreateThreatModelUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue
    private let clock: Clock

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue, clock: Clock) {
        self.models = models
        self.catalogue = catalogue
        self.clock = clock
    }

    public func execute(_ request: CreateThreatModelRequest) -> CreateThreatModelResponse {
        let name = request.name.trimmingWhitespace()
        guard name.isEmpty == false else { return .emptyName }

        let now = clock.now()
        models.save(
            ThreatModel(
                name: name,
                createdAt: now,
                updatedAt: now,
                catalogueVersion: catalogue.version()
            )
        )

        return .created
    }
}
```

Create `.../modelling/usecase/RenameThreatModel.swift`:

```swift
public protocol RenameThreatModelUseCase {
    func execute(_ request: RenameThreatModelRequest) -> RenameThreatModelResponse
}

public struct RenameThreatModelRequest: Equatable, Sendable {
    public let name: String
    public init(name: String) { self.name = name }
}

public enum RenameThreatModelResponse: Equatable, Sendable {
    case renamed
    case emptyName
}

/// Renames the model. A model with no name is not a document anyone can find
/// again, so an empty name is refused rather than accepted and hidden.
public struct RenameThreatModel: RenameThreatModelUseCase {
    private let models: ThreatModelGateway
    private let clock: Clock

    public init(models: ThreatModelGateway, clock: Clock) {
        self.models = models
        self.clock = clock
    }

    public func execute(_ request: RenameThreatModelRequest) -> RenameThreatModelResponse {
        let name = request.name.trimmingWhitespace()
        guard name.isEmpty == false else { return .emptyName }

        let now = clock.now()
        return models.mutate { model in
            model.name = name
            model.updatedAt = now
            return .renamed
        }
    }
}
```

Create `.../modelling/usecase/SaveThreatModel.swift`:

```swift
import Foundation

public protocol SaveThreatModelUseCase {
    func execute(_ request: SaveThreatModelRequest) -> SaveThreatModelResponse
}

public struct SaveThreatModelRequest: Equatable, Sendable {
    public init() {}
}

public enum SaveThreatModelResponse: Equatable, Sendable {
    /// The bytes to write. The delivery mechanism owns the file; the core owns
    /// what goes in it.
    case saved(data: Data)
    case notWritable(reason: String)
}

/// Stamps the model with the time and the catalogue it was last assessed
/// against, then turns it into bytes.
public struct SaveThreatModel: SaveThreatModelUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue
    private let clock: Clock
    private let files: ThreatModelFileGateway

    public init(
        models: ThreatModelGateway,
        catalogue: TechnologyCatalogue,
        clock: Clock,
        files: ThreatModelFileGateway
    ) {
        self.models = models
        self.catalogue = catalogue
        self.clock = clock
        self.files = files
    }

    public func execute(_ request: SaveThreatModelRequest) -> SaveThreatModelResponse {
        let now = clock.now()
        let version = catalogue.version()

        let stamped = models.mutate { model -> ThreatModel in
            model.updatedAt = now
            model.catalogueVersion = version
            return model
        }

        do {
            return .saved(data: try files.encode(stamped))
        } catch {
            return .notWritable(reason: String(describing: error))
        }
    }
}
```

Create `.../modelling/usecase/OpenThreatModel.swift`:

```swift
import Foundation

public protocol OpenThreatModelUseCase {
    func execute(_ request: OpenThreatModelRequest) -> OpenThreatModelResponse
}

public struct OpenThreatModelRequest: Equatable, Sendable {
    public let data: Data
    public init(data: Data) { self.data = data }
}

/// What has moved under a saved model since it was last assessed.
///
/// Spec section 8: the catalogue version stamp lets the application report
/// drift rather than quietly dropping what no longer exists.
public struct ThreatModelDrift: Equatable, Sendable {
    /// The catalogue the model was last assessed against, or nil for a file
    /// that carries no stamp.
    public let savedCatalogueTag: String?
    public let currentCatalogueTag: String
    /// Technologies the model uses that this catalogue no longer holds. Their
    /// components still draw; they raise no threats.
    public let unknownTechnologyIds: [String]

    public init(savedCatalogueTag: String?, currentCatalogueTag: String, unknownTechnologyIds: [String]) {
        self.savedCatalogueTag = savedCatalogueTag
        self.currentCatalogueTag = currentCatalogueTag
        self.unknownTechnologyIds = unknownTechnologyIds
    }

    public var hasDrift: Bool {
        unknownTechnologyIds.isEmpty == false || savedCatalogueTag != currentCatalogueTag
    }
}

public enum OpenThreatModelResponse: Equatable, Sendable {
    case opened(name: String, drift: ThreatModelDrift)
    case unreadable(reason: String)
}

/// Reads a document into this gateway, and says what has drifted.
///
/// Opening is reading: the model's updated time is whatever the file says, not
/// the time it was opened.
public struct OpenThreatModel: OpenThreatModelUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue
    private let files: ThreatModelFileGateway

    public init(
        models: ThreatModelGateway,
        catalogue: TechnologyCatalogue,
        files: ThreatModelFileGateway
    ) {
        self.models = models
        self.catalogue = catalogue
        self.files = files
    }

    public func execute(_ request: OpenThreatModelRequest) -> OpenThreatModelResponse {
        let model: ThreatModel
        do {
            model = try files.decode(request.data)
        } catch {
            return .unreadable(reason: String(describing: error))
        }

        models.save(model)

        let unknown = model.components
            .map(\.technologyId)
            .filter { catalogue.findById($0) == nil }
            .map(\.value)

        return .opened(
            name: model.name,
            drift: ThreatModelDrift(
                savedCatalogueTag: model.catalogueVersion?.tag,
                currentCatalogueTag: catalogue.version().tag,
                unknownTechnologyIds: Array(Set(unknown)).sorted()
            )
        )
    }
}
```

- [ ] **Step 4: Vend them, and give the test root a clock and a codec**

Add the four to `UseCaseFactory`. In `Package.swift`, give `TestSupport` the dependency:

```swift
        .target(name: "TestSupport", dependencies: ["ThreatModelKit", "FileGateways"]),
```

`TestDependencies` gains `private let clock = FixedClock()` and `private let files = ThreatModelCodec()`, exposes `public let time: FixedClock` so an acceptance test can move it, and vends the four. `Dependencies` uses `SystemClock()` and `ThreatModelCodec()`.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit
git commit -m "feat: create, rename, save and open a threat model

Saving stamps the model with the time and the catalogue it was last assessed
against. Opening is reading, so the updated time is what the file says, and
the response names every technology the catalogue no longer holds."
```

---

### Task 5: The acceptance test

**Files:**
- Create: `ThreatModelKit/Tests/AcceptanceTests/KeepingAThreatModelTests.swift`

- [ ] **Step 1: Write the test**

```swift
import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// Given a threat model I have built
/// When I save it and open it again
/// Then everything I did is still there
struct KeepingAThreatModelTests {
    private let app = TestDependencies()

    private func add(_ technologyId: String, x: Double, sensitivity: String) -> String {
        let response = app.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: x, y: 100, sensitivity: sensitivity)
        )
        guard case .added(let componentId) = response else {
            Issue.record("Expected the component to be added, got \(response)")
            return ""
        }
        return componentId
    }

    private func save() -> Data {
        guard case .saved(let data) = app.saveThreatModel().execute(SaveThreatModelRequest()) else {
            Issue.record("Expected the model to be saved")
            return Data()
        }
        return data
    }

    private func threats() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    @Test func keepsEverythingIBuiltAcrossASaveAndAnOpen() throws {
        #expect(app.createThreatModel().execute(
            CreateThreatModelRequest(name: "Payments")
        ) == .created)

        let web = add("aws-ec2", x: 100, sensitivity: "confidential")
        let database = add("aws-rds", x: 900, sensitivity: "restricted")
        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: web, targetComponentId: database)
        )
        _ = app.addZone().execute(AddZoneRequest(x: 0, y: 0, width: 700, height: 600))
        let control = try #require(threats().first?.controls.first)
        _ = app.recordControlImplemented().execute(
            RecordControlImplementedRequest(controlKey: control.key)
        )
        _ = app.overrideThreatSeverity().execute(
            OverrideThreatSeverityRequest(
                overrideKey: try #require(threats().first).overrideKey,
                severityId: "low"
            )
        )
        _ = app.configurePathwayMitigations().execute(
            ConfigurePathwayMitigationsRequest(
                isMasterEnabled: true,
                mitigationId: "waf-protection",
                isEnabled: true,
                mode: "remove",
                reductionPercent: 0
            )
        )

        let before = app.viewThreatModel().execute(ViewThreatModelRequest())
        let beforeThreats = threats()
        let beforeSummary = app.summariseRisk().execute(SummariseRiskRequest())

        let file = save()

        // Everything is thrown away, and the file is all that is left.
        #expect(app.createThreatModel().execute(
            CreateThreatModelRequest(name: "Something else")
        ) == .created)
        #expect(threats().isEmpty)

        guard case .opened(let name, let drift) = app.openThreatModel().execute(
            OpenThreatModelRequest(data: file)
        ) else {
            Issue.record("Expected the file to open")
            return
        }

        #expect(name == "Payments")
        #expect(drift.hasDrift == false)
        // The model comes back, not the editing history: opening a document
        // is not something to undo back out of. Milestone 6B adds the history.
        let after = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(after.name == before.name)
        #expect(after.components == before.components)
        #expect(after.connections == before.connections)
        #expect(after.zones == before.zones)
        #expect(threats() == beforeThreats)
        #expect(app.summariseRisk().execute(SummariseRiskRequest()) == beforeSummary)
    }

    @Test func remembersWhenItWasMadeAndWhenItLastChanged() throws {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        let created = app.time.now()

        app.time.advance(by: 86_400)
        _ = add("aws-ec2", x: 0, sensitivity: "internal")
        let file = save()

        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Blank"))
        _ = app.openThreatModel().execute(OpenThreatModelRequest(data: file))

        // The document says when it was made and when it last changed. Both
        // survive the round trip; only the second one moves.
        let reopened = try #require(String(data: file, encoding: .utf8))
        #expect(reopened.contains("\"createdAt\""))
        #expect(reopened.contains("\"updatedAt\""))
        #expect(created != app.time.now())
    }

    @Test func saysWhatHasDriftedWhenTheCatalogueMovesOn() throws {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        _ = add("aws-ec2", x: 0, sensitivity: "internal")
        let file = save()

        // A file from another machine, naming a technology this catalogue does
        // not hold.
        let text = try #require(String(data: file, encoding: .utf8))
            .replacingOccurrences(of: "\"aws-ec2\"", with: "\"aws-retired\"")

        guard case .opened(_, let drift) = app.openThreatModel().execute(
            OpenThreatModelRequest(data: Data(text.utf8))
        ) else {
            Issue.record("Expected the file to open")
            return
        }

        #expect(drift.unknownTechnologyIds == ["aws-retired"])
        #expect(drift.hasDrift)
        // The component still draws; it just raises nothing.
        #expect(app.viewThreatModel().execute(ViewThreatModelRequest()).components.count == 1)
        #expect(threats().isEmpty)
    }

    @Test func refusesAFileItCannotRead() {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        _ = add("aws-ec2", x: 0, sensitivity: "internal")

        guard case .unreadable = app.openThreatModel().execute(
            OpenThreatModelRequest(data: Data("not a threat model".utf8))
        ) else {
            Issue.record("Expected the bytes to be refused")
            return
        }

        // The work that was open is untouched.
        #expect(app.viewThreatModel().execute(ViewThreatModelRequest()).components.count == 1)
    }
}
```

- [ ] **Step 2: Run it, then the whole suite**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter KeepingAThreatModelTests 2>&1 | tail -5
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && time swift test 2>&1 | tail -3
```

Expected: PASS, whole suite under 30 seconds.

- [ ] **Step 3: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit/Tests/AcceptanceTests/KeepingAThreatModelTests.swift
git commit -m "test: accept the milestone 6A core at the use case boundary

Everything built survives a save and an open: the canvas, the threats, the
scores, the ticks, the override and the mitigation settings. A file naming a
technology this catalogue no longer holds opens and says so."
```

---

### Task 6: The document, and a window per document

**Files:**
- Create: `threatmodeller/ThreatModelDocument.swift`
- Create: `threatmodeller/Info.plist`
- Modify: `threatmodeller/Dependencies.swift`, `threatmodellerApp.swift`, `ContentView.swift`
- Modify: `threatmodeller.xcodeproj/project.pbxproj`

**Interfaces:**
- Produces: `UTType.threatModel`; `DocumentStore` with `.useCases`, `.startupError`, `.create(named:)`, `.open(_:)`, `.data()`; `ThreatModelDocument`; `ContentView(document:)`.

- [ ] **Step 1: Make the composition root callable from anywhere**

`Dependencies` holds gateways and nothing else, and SwiftUI asks a document for its bytes wherever it likes. Mark it `nonisolated` so its conformance is not main-actor isolated:

```swift
nonisolated final class Dependencies: UseCaseFactory {
```

- [ ] **Step 2: Write the document**

Create `threatmodeller/ThreatModelDocument.swift`:

```swift
import Foundation
import SwiftUI
import UniformTypeIdentifiers
import ThreatModelKit
import FileGateways

extension UTType {
    /// Spec section 8. Declared in `Info.plist` as an exported type.
    static let threatModel = UTType(exportedAs: "io.threatmodeller.model")
}

enum DocumentStoreError: Error, LocalizedError {
    case catalogueUnavailable(String)
    case notWritable(String)
    case unreadable(String)

    var errorDescription: String? {
        switch self {
        case .catalogueUnavailable(let reason): "The catalogue could not be loaded. \(reason)"
        case .notWritable(let reason): "The model could not be written. \(reason)"
        case .unreadable(let reason): "The file could not be read. \(reason)"
        }
    }
}

/// One open document's dependency graph. Spec section 3.5: one graph per open
/// document, each owning its own model gateway.
///
/// Declared `nonisolated` on purpose. SwiftUI asks a `FileDocument` for its
/// bytes wherever it likes, and every gateway underneath is safe to call from
/// anywhere.
nonisolated final class DocumentStore: @unchecked Sendable {
    /// Nil when the catalogue could not be loaded. The window says so rather
    /// than showing an empty diagram.
    let useCases: UseCaseFactory?
    let startupError: String?

    init() {
        do {
            useCases = try Dependencies()
            startupError = nil
        } catch {
            useCases = nil
            startupError = String(describing: error)
        }
    }

    func create(named name: String) {
        _ = useCases?.createThreatModel().execute(CreateThreatModelRequest(name: name))
    }

    func open(_ data: Data) throws -> ThreatModelDrift {
        guard let useCases else {
            throw DocumentStoreError.catalogueUnavailable(startupError ?? "")
        }
        switch useCases.openThreatModel().execute(OpenThreatModelRequest(data: data)) {
        case .opened(_, let drift):
            return drift
        case .unreadable(let reason):
            throw DocumentStoreError.unreadable(reason)
        }
    }

    func data() throws -> Data {
        guard let useCases else {
            throw DocumentStoreError.catalogueUnavailable(startupError ?? "")
        }
        switch useCases.saveThreatModel().execute(SaveThreatModelRequest()) {
        case .saved(let data):
            return data
        case .notWritable(let reason):
            throw DocumentStoreError.notWritable(reason)
        }
    }
}

/// The document SwiftUI opens, saves and closes.
///
/// The struct holds a reference to the store, so SwiftUI copying it never
/// copies the model. The bytes are the only thing that crosses the boundary.
struct ThreatModelDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.threatModel] }

    let store: DocumentStore
    /// What had moved under this file since it was last saved, or nil for a
    /// new document.
    let drift: ThreatModelDrift?

    init() {
        store = DocumentStore()
        store.create(named: "Untitled")
        drift = nil
    }

    init(configuration: ReadConfiguration) throws {
        store = DocumentStore()
        guard let data = configuration.file.regularFileContents else {
            throw CocoaError(.fileReadCorruptFile)
        }
        drift = try store.open(data)
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: try store.data())
    }
}
```

- [ ] **Step 3: Declare the type to the system**

Create `threatmodeller/Info.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDocumentTypes</key>
	<array>
		<dict>
			<key>CFBundleTypeName</key>
			<string>Threat Model</string>
			<key>CFBundleTypeRole</key>
			<string>Editor</string>
			<key>LSHandlerRank</key>
			<string>Owner</string>
			<key>LSItemContentTypes</key>
			<array>
				<string>io.threatmodeller.model</string>
			</array>
		</dict>
	</array>
	<key>UTExportedTypeDeclarations</key>
	<array>
		<dict>
			<key>UTTypeConformsTo</key>
			<array>
				<string>public.json</string>
			</array>
			<key>UTTypeDescription</key>
			<string>Threat Model</string>
			<key>UTTypeIdentifier</key>
			<string>io.threatmodeller.model</string>
			<key>UTTypeTagSpecification</key>
			<dict>
				<key>public.filename-extension</key>
				<array>
					<string>threatmodel</string>
				</array>
			</dict>
		</dict>
	</array>
</dict>
</plist>
```

Point the app target at it. `GENERATE_INFOPLIST_FILE` stays `YES`, so the existing `INFOPLIST_KEY_*` settings are merged on top of this file.

```bash
cd /Users/craigjbass/Projects/threat-modeller
python3 - threatmodeller.xcodeproj/project.pbxproj <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()

# The app target's two build configurations are the ones carrying
# INFOPLIST_KEY_NSHumanReadableCopyright. Point both at the file.
needle = "\t\t\t\tINFOPLIST_KEY_NSHumanReadableCopyright = \"\";"
assert s.count(needle) == 2, "expected the app target's two configurations"
s = s.replace(needle, "\t\t\t\tINFOPLIST_FILE = threatmodeller/Info.plist;\n" + needle)

open(p, "w").write(s)
print("app target points at Info.plist")
PY
```

WARNING: if `INFOPLIST_KEY_NSHumanReadableCopyright` is absent or appears a different number of times, `grep -n 'INFOPLIST_KEY' threatmodeller.xcodeproj/project.pbxproj` and pick a key that appears exactly twice and only in the app target.

Also link the `FileGateways` product into the app target, the same way `TestSupport` was linked into the test target in Milestone 2. Reuse that script's shape with fresh identifiers `A0000000000000000000008` (build file) and `A0000000000000000000009` (product), attached to the app target's Frameworks phase `46EEEDC3304F3231000F014D` and its `packageProductDependencies`.

- [ ] **Step 4: One window per document**

Replace `threatmodeller/threatmodellerApp.swift`:

```swift
import SwiftUI

@main
struct ThreatModellerApp: App {
    var body: some Scene {
        DocumentGroup(newDocument: ThreatModelDocument()) { file in
            ContentView(document: file.document)
        }
        .defaultSize(width: 1400, height: 900)
    }
}
```

Change `ContentView` to take the document, and to say what drifted:

```swift
struct ContentView: View {
    let document: ThreatModelDocument

    @State private var session: ThreatModelSession?

    var body: some View {
        Group {
            if let session {
                ModelView(session: session, drift: document.drift)
            } else if let startupError = document.store.startupError {
                ContentUnavailableView(
                    "The catalogue could not be loaded",
                    systemImage: "exclamationmark.triangle",
                    description: Text(startupError)
                )
            } else {
                ProgressView()
            }
        }
        .task {
            guard session == nil, let useCases = document.store.useCases else { return }
            session = ThreatModelSession(useCases: useCases)
        }
    }
}
```

`ModelView` takes the drift and shows it above the three columns, once, dismissible:

```swift
private struct ModelView: View {
    let session: ThreatModelSession
    let drift: ThreatModelDrift?

    @State private var canvas = CanvasState()
    @State private var isDriftDismissed = false

    private var driftMessage: String? {
        guard isDriftDismissed == false, let drift, drift.hasDrift else { return nil }

        if drift.unknownTechnologyIds.isEmpty == false {
            return "This model uses \(drift.unknownTechnologyIds.count) technology "
                + "the catalogue no longer holds: "
                + "\(drift.unknownTechnologyIds.joined(separator: ", ")). "
                + "Those components raise no threats."
        }
        return "This model was last assessed against catalogue "
            + "\(drift.savedCatalogueTag ?? "an earlier version"). "
            + "This application holds \(drift.currentCatalogueTag)."
    }

    var body: some View {
        VStack(spacing: 0) {
            if let driftMessage {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                    Text(driftMessage).font(.callout)
                    Spacer(minLength: 8)
                    Button("Dismiss") { isDriftDismissed = true }
                }
                .padding(8)
                .background(.yellow.opacity(0.25))
                .accessibilityIdentifier("drift-banner")
            }

            NavigationSplitView {
                // … the three columns, unchanged …
            }
        }
    }
}
```

- [ ] **Step 5: Build and run every suite**

```bash
cd /Users/craigjbass/Projects/threat-modeller
osascript -e 'tell application "threatmodeller" to quit' 2>/dev/null
defaults delete uk.craigbass.threatmodeller 2>/dev/null
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'error:|Failing tests|\*\* TEST' -A4 | head -10
```

Expected: PASS.

WARNING: `DocumentGroup` opens an open-panel on launch instead of a window, so the user interface journey must create a new document first. Task 8 handles that. If the suite fails here with no window, that is why; do Task 8 and re-run.

- [ ] **Step 6: Look at it**

Build, open the app, make a model, save it with Command-S, close it, open it again from the Finder. Check the title bar carries the file name and the diagram comes back.

- [ ] **Step 7: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add threatmodeller threatmodeller.xcodeproj
git commit -m "feat: make a threat model a document

One window per document, each with its own dependency graph and its own model
gateway. The document struct holds a reference to that graph, so SwiftUI
copying it never copies the model. Opening a file that has drifted says what
moved, once, above the diagram."
```

---

### Task 7: The canvas follows the model

Closes carry-forward item 7. A saved model can carry items far from the origin, and a fixed 20000 point square draws no connection beyond it.

**Files:**
- Modify: `threatmodeller/canvas/CanvasHitTest.swift`
- Modify: `threatmodeller/canvas/CanvasView.swift`
- Modify: `threatmodellerTests/canvas/CanvasHitTestTests.swift`

**Interfaces:**
- Produces: `CanvasHitTest.contentSize(components:zones:)`.

- [ ] **Step 1: Write the failing test**

Add to `CanvasHitTestTests`:

```swift
    @Test func givesAnEmptyModelARoomySquare() {
        let size = CanvasHitTest.contentSize(components: [], zones: [])

        #expect(size.width == CanvasHitTest.minimumContentSize.width)
        #expect(size.height == CanvasHitTest.minimumContentSize.height)
    }

    @Test func growsToHoldTheFarthestComponent() {
        let size = CanvasHitTest.contentSize(
            components: [component("c1", x: 9000, y: 40)],
            zones: []
        )

        #expect(size.width > 9000 + ComponentBox.size.width)
        #expect(size.height == CanvasHitTest.minimumContentSize.height)
    }

    @Test func growsToHoldTheFarthestZone() {
        let size = CanvasHitTest.contentSize(
            components: [],
            zones: [viewedZone("z1", x: 0, y: 8000)]
        )

        #expect(size.height > 8000)
    }

    @Test func leavesRoomToDragPastTheFarthestThing() {
        let size = CanvasHitTest.contentSize(
            components: [component("c1", x: 3000, y: 3000)],
            zones: []
        )

        // The user has to be able to drag a node past whatever is currently
        // farthest out, so the layer is bigger than what it holds.
        #expect(size.width >= 3000 + ComponentBox.size.width + CanvasHitTest.contentMargin)
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `type 'CanvasHitTest' has no member 'contentSize'`.

- [ ] **Step 3: Size the layer from the model**

Append to `CanvasHitTest`:

```swift
    /// A canvas with nothing on it is still somewhere to draw.
    static let minimumContentSize = CGSize(width: 4000, height: 3000)
    /// Room past the farthest thing, so a node can always be dragged further
    /// out than whatever is currently farthest.
    static let contentMargin: CGFloat = 1000

    /// How big the drawing layer has to be to hold everything, with room to
    /// spare. A fixed square either wastes memory or clips a saved model that
    /// reaches past it.
    static func contentSize(components: [ViewedComponent], zones: [ViewedZone]) -> CGSize {
        var width = minimumContentSize.width - contentMargin
        var height = minimumContentSize.height - contentMargin

        for component in components {
            width = max(width, component.x + ComponentBox.size.width)
            height = max(height, component.y + ComponentBox.size.height)
        }
        for zone in zones {
            width = max(width, zone.x + zone.width)
            height = max(height, zone.y + zone.height)
        }

        return CGSize(width: width + contentMargin, height: height + contentMargin)
    }
```

In `CanvasView.content`, replace the fixed frame on `ConnectionsLayer`:

```swift
            ConnectionsLayer(
                connections: session.canvas.connections,
                boxes: boxes,
                selectedConnectionIds: canvas.selectedConnectionIds,
                preview: previewLine
            )
            .frame(width: contentSize.width, height: contentSize.height)
```

and add:

```swift
    /// The drawing layer follows the model, so a saved diagram that reaches
    /// far from the origin still draws its links.
    private var contentSize: CGSize {
        CanvasHitTest.contentSize(
            components: session.canvas.components,
            zones: session.canvas.zones
        )
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
git add threatmodeller threatmodellerTests
git commit -m "feat: size the drawing layer from the model

A saved model can carry items far from the origin, and the fixed 20000 point
square either wasted memory or clipped them. The layer now holds what the
model holds, with room to drag past it."
```

---

### Task 8: The user interface journey

`DocumentGroup` opens an open-panel on launch rather than a window, so the journey has to make a document first.

**Files:**
- Modify: `threatmodellerUITests/threatmodellerUITests.swift`

- [ ] **Step 1: Make a document before the journey starts**

After `app.launch()`, before the palette assertion:

```swift
        // A document-based application offers to open a file on launch. The
        // journey needs a new, empty document.
        mark("making a new document")
        let newDocument = XCUIApplication().menuBars.menuItems["New"]
        if newDocument.waitForExistence(timeout: 10) {
            newDocument.click()
        }
        XCTAssertTrue(
            app.windows.firstMatch.waitForExistence(timeout: 15),
            "No document window appeared."
        )
```

WARNING: if the open-panel takes the keyboard first, the menu click may not land. Dismiss it with `app.typeKey(.escape, modifierFlags: [])` before clicking `New`, and if the menu item is not found, dump `app.menuBars.debugDescription` and read the real title. Remove the dump before committing.

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
git commit -m "test: make a document before walking the journey

A document-based application offers to open a file on launch rather than
showing a window, so the journey starts by making a new one."
```

---

## Milestone complete

- [ ] `swift test` from `ThreatModelKit/` is green and runs in under 30 seconds.
- [ ] `xcodebuild ... test` is green, including the user interface suite.
- [ ] The catalogue tag is still `v1.0.1`.
- [ ] `grep -rn 'current()' ThreatModelKit/Sources/ThreatModelKit/*/usecase/` finds only reads: every write goes through `mutate`.
- [ ] The gateway contract races two hundred concurrent appends and loses none.
- [ ] A model saved and reopened is the same model: canvas, threats, scores, ticks, override, mitigation settings.
- [ ] A file whose format version this application does not know is refused, not guessed at.
- [ ] Opening a file that names a technology the catalogue no longer holds says so, and those components still draw.
- [ ] Two documents can be open at once, each with its own model.
- [ ] The drawing layer holds what the model holds; `grep -rn '20000' threatmodeller/` finds nothing.

Then write `docs/superpowers/specs/MILESTONE-6B-CARRY-FORWARD.md` and start the Milestone 6B plan: undo and redo over the history gateway, copy, cut, paste, duplicate, menu commands and keyboard shortcuts.

Deferred, with the trigger unchanged: the three catalogue faults tied to a tag bump; the missing `IdentityGenerator` contract; the fixed `internal` sensitivity, which is still the largest gap; the palette's missing keyboard path and the pointer bindings, which 6B revisits; the unmeasured resolver arithmetic; the single-zone selection and the zone drawing order; the un-debounced name and slider fields; the missing undo, which 6B closes; the gestures no user interface test reaches; the unpruned control keys; the two override key shapes that a technology could collide with; and the split-view arrangement nothing validates.
