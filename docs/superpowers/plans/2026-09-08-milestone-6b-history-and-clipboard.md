# Milestone 6B: History and Clipboard — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every change can be taken back. A selection can be copied, cut, pasted into the same diagram or another one, and duplicated in place. Everything the toolbar does has a menu item and a key.

**Architecture:** The gateway takes a snapshot inside every `mutate`, so one use case is one undo step and no use case can forget to record one. `UndoLastChange` and `RedoChange` move between snapshots. A selection is turned into clipboard **text** by the same `ThreatModelFileGateway` that writes documents, so it crosses documents and applications, and pasting always mints fresh identifiers.

**Tech Stack:** Swift 6.3, Swift Package Manager, Swift Testing, SwiftUI, macOS 26.

**Spec:** `docs/superpowers/specs/2026-09-07-native-macos-threat-modeller-design.md`

**Carry-forward:** `docs/superpowers/specs/MILESTONE-6B-CARRY-FORWARD.md`

**Read Task 5 before starting Task 1.** Task 5 is the acceptance test — the outer loop.

## Global Constraints

- Everything in the Milestone 6A plan's Global Constraints still holds.
- WARNING: two source files in one module may not share a basename.
- WARNING: a key path passed to a `rethrows` method inside `#expect` fails to compile; use a closure. `#expect` keeps each operand's own type, so convert a `CGFloat` before comparing it with a `Double`.
- WARNING: the app saves its split-view arrangement. If the user interface suite fails at its first assertion with no window, run `osascript -e 'tell application "threatmodeller" to quit'` then `defaults delete uk.craigbass.threatmodeller`.
- WARNING: the user interface journey must ask for a new document and scope every query to one window.
- One use case is one undo step. The gateway snapshots inside `mutate` and discards the snapshot when the model did not actually change, so a refused change is not an undo step.
- Pasting always mints fresh identifiers. Identifiers are unique within a document only, and the clipboard crosses documents.
- The clipboard carries text.
- Catalogue pinned at `v1.0.1`.
- Commit after every task. Never commit a red suite.

## Out of scope for this milestone

`LabelConnection` — spec §9 lists double-clicking a connection to edit its label under keyboard parity, but the label is not on the `Connection` domain object and Milestone 2 deliberately left it out. It stays out, and the carry-forward records it.

Custom technologies, external actors, exports, samples: Milestones 7 to 9. The component property panel and the fixed `internal` sensitivity stay open.

## File Structure

**Created:**

| Path | Responsibility |
|---|---|
| `.../modelling/domain/SelectionSnippet.swift` | What a copy holds |
| `.../modelling/usecase/UndoLastChange.swift` | and its Request/Response |
| `.../modelling/usecase/RedoChange.swift` | and its Request/Response |
| `.../modelling/usecase/CopySelection.swift` | and its Request/Response |
| `.../modelling/usecase/PasteSelection.swift` | and its Request/Response |
| `.../modelling/usecase/DuplicateSelection.swift` | and its Request/Response |
| `ThreatModelKit/Tests/UnitTests/HistoryTests.swift` | Undo and redo |
| `ThreatModelKit/Tests/UnitTests/ClipboardUseCaseTests.swift` | Copy, paste and duplicate |
| `ThreatModelKit/Tests/AcceptanceTests/TakingItBackTests.swift` | The milestone's outer loop |
| `threatmodeller/ThreatModelCommands.swift` | The menu, and what each item calls |

**Modified:**

- `.../modelling/gateway/ThreatModelGateway.swift` — snapshots, `undo()`, `redo()`, `canUndo`, `canRedo`
- `.../modelling/gateway/ThreatModelFileGateway.swift` — the selection, both ways
- `ThreatModelKit/Sources/FileGateways/ThreatModelCodec.swift`, `DocumentJSON.swift` — the snippet
- `ThreatModelKit/Sources/TestSupport/ThreatModelGatewayContract.swift` — history
- `.../UseCaseFactory.swift`, `.../TestDependencies.swift`, `threatmodeller/Dependencies.swift`
- `threatmodeller/ThreatModelSession.swift` — undo, redo, and the clipboard
- `threatmodeller/threatmodellerApp.swift` — the commands
- `threatmodeller/canvas/CanvasView.swift` — select all and the arrow nudge
- `threatmodellerUITests/threatmodellerUITests.swift` — the journey takes a change back

---

### Task 1: The gateway remembers

**Files:**
- Modify: `.../modelling/gateway/ThreatModelGateway.swift`
- Modify: `ThreatModelKit/Sources/TestSupport/ThreatModelGatewayContract.swift`

**Interfaces:**
- Produces: `ThreatModelGateway.undo() -> Bool`, `.redo() -> Bool`, `.canUndo: Bool`, `.canRedo: Bool`; `InMemoryThreatModelGateway.historyLimit`.

The snapshot is taken **inside** `mutate`, before the change, and kept only when the model actually changed. A use case cannot forget to record one, and a refused change is not an undo step. `save(_:)` — which only `CreateThreatModel` and `OpenThreatModel` call — clears the history instead: opening a different document is not something to undo back out of.

- [ ] **Step 1: Write the failing test**

Add to `verifyThreatModelGatewayContract`, after the existing clauses:

```swift
    // MARK: history

    let history = make()
    #expect(history.canUndo == false)
    #expect(history.canRedo == false)
    #expect(history.undo() == false)
    #expect(history.redo() == false)

    history.mutate { $0.name = "one" }
    history.mutate { $0.name = "two" }
    #expect(history.canUndo)

    #expect(history.undo())
    #expect(history.current().name == "one")
    #expect(history.canRedo)

    #expect(history.undo())
    #expect(history.current().name == "Untitled")
    #expect(history.canUndo == false)

    #expect(history.redo())
    #expect(history.current().name == "one")
    #expect(history.redo())
    #expect(history.current().name == "two")
    #expect(history.canRedo == false)

    // A change after an undo drops what was redoable: the user has taken a
    // different branch, and offering to redo the abandoned one would be a lie.
    #expect(history.undo())
    history.mutate { $0.name = "three" }
    #expect(history.canRedo == false)
    #expect(history.current().name == "three")

    // A change that changes nothing is not a step to take back.
    let noChange = make()
    noChange.mutate { $0.name = "one" }
    noChange.mutate { _ in }
    noChange.mutate { model in model.name = model.name }
    #expect(noChange.undo())
    #expect(noChange.current().name == "Untitled")
    #expect(noChange.canUndo == false)

    // Replacing the model outright — opening a different document — is not
    // something to undo back out of.
    let replaced = make()
    replaced.mutate { $0.name = "one" }
    replaced.save(ThreatModel(name: "another document"))
    #expect(replaced.canUndo == false)
    #expect(replaced.canRedo == false)
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter ThreatModelGatewayContractTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `has no member 'canUndo'`.

- [ ] **Step 3: Give the port its history**

Add to the protocol:

```swift
    /// Takes the model back one change. Returns false when there is nothing to
    /// take back.
    func undo() -> Bool
    /// Puts back a change that was taken back. Returns false when there is
    /// nothing to put back.
    func redo() -> Bool
    var canUndo: Bool { get }
    var canRedo: Bool { get }
```

and extend the doc comment:

```swift
/// `mutate` also records history. The snapshot is taken inside it, before the
/// change, and kept only when the model actually changed: one use case is one
/// undo step, no use case can forget to record one, and a refused change is
/// not a step. `save(_:)` clears the history instead — replacing the model
/// outright is opening a different document, not a change to take back.
```

Replace the in-memory store's body:

```swift
public final class InMemoryThreatModelGateway: ThreatModelGateway, @unchecked Sendable {
    /// How far back the user can go. Deep enough that nobody reaches it in a
    /// session, shallow enough that a long session does not grow without end.
    public static let historyLimit = 100

    private let lock = NSLock()
    private var model: ThreatModel
    private var past: [ThreatModel] = []
    private var future: [ThreatModel] = []

    public init(_ model: ThreatModel = ThreatModel()) {
        self.model = model
    }

    public func current() -> ThreatModel {
        lock.lock()
        defer { lock.unlock() }
        return model
    }

    /// Replaces the model and forgets the history. Only `CreateThreatModel` and
    /// `OpenThreatModel` call this.
    public func save(_ model: ThreatModel) {
        lock.lock()
        defer { lock.unlock() }
        self.model = model
        past = []
        future = []
    }

    public func mutate<T>(_ change: (inout ThreatModel) -> T) -> T {
        lock.lock()
        defer { lock.unlock() }

        let before = model
        let result = change(&model)

        if model != before {
            past.append(before)
            if past.count > Self.historyLimit { past.removeFirst() }
            // The user has taken a different branch. Offering to redo the
            // abandoned one would be a lie.
            future = []
        }

        return result
    }

    public func undo() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let previous = past.popLast() else { return false }
        future.append(model)
        model = previous
        return true
    }

    public func redo() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let next = future.popLast() else { return false }
        past.append(model)
        model = next
        return true
    }

    public var canUndo: Bool {
        lock.lock()
        defer { lock.unlock() }
        return past.isEmpty == false
    }

    public var canRedo: Bool {
        lock.lock()
        defer { lock.unlock() }
        return future.isEmpty == false
    }
}
```

- [ ] **Step 4: Run every suite**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

Expected: PASS. Nothing else changes: every existing test drives the gateway through the same operations.

- [ ] **Step 5: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit
git commit -m "feat: give the model gateway a history

The snapshot is taken inside every change, before it, and kept only when the
model actually changed. One use case is one undo step, no use case can forget
to record one, and a refused change is not a step. Replacing the model
outright clears the history: opening a different document is not a change to
take back."
```

---

### Task 2: `UndoLastChange` and `RedoChange`

**Files:**
- Create: `.../modelling/usecase/UndoLastChange.swift`, `RedoChange.swift`
- Modify: `.../UseCaseFactory.swift`, `.../TestDependencies.swift`, `threatmodeller/Dependencies.swift`
- Create: `ThreatModelKit/Tests/UnitTests/HistoryTests.swift`

**Interfaces:**
- Produces: `UndoLastChangeUseCase`, `UndoLastChangeRequest()`, `UndoLastChangeResponse` (`.undone(canUndoMore:)`, `.nothingToUndo`); `RedoChangeUseCase`, `RedoChangeRequest()`, `RedoChangeResponse` (`.redone(canRedoMore:)`, `.nothingToRedo`).

The response says whether there is more, so a menu item can dim itself without asking a second question.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/HistoryTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

struct HistoryTests {
    private let models = InMemoryThreatModelGateway()
    private let catalogue = CatalogueFixture.catalogue()
    private let ids = SequentialIdentityGenerator()

    private func addComponent(x: Double = 0) {
        _ = AddComponent(models: models, catalogue: catalogue, ids: ids)
            .execute(AddComponentRequest(technologyId: "aws-ec2", x: x, y: 0, sensitivity: "internal"))
    }

    private func undo() -> UndoLastChangeResponse {
        UndoLastChange(models: models).execute(UndoLastChangeRequest())
    }

    private func redo() -> RedoChangeResponse {
        RedoChange(models: models).execute(RedoChangeRequest())
    }

    @Test func saysThereIsNothingToTakeBackOnAFreshModel() {
        #expect(undo() == .nothingToUndo)
        #expect(redo() == .nothingToRedo)
    }

    @Test func takesBackOneChange() {
        addComponent()
        addComponent(x: 300)
        #expect(models.current().components.count == 2)

        #expect(undo() == .undone(canUndoMore: true))
        #expect(models.current().components.count == 1)

        #expect(undo() == .undone(canUndoMore: false))
        #expect(models.current().components.isEmpty)

        #expect(undo() == .nothingToUndo)
    }

    @Test func putsBackWhatWasTakenBack() {
        addComponent()
        _ = undo()

        #expect(redo() == .redone(canRedoMore: false))
        #expect(models.current().components.count == 1)
        #expect(redo() == .nothingToRedo)
    }

    @Test func takesBackEveryKindOfChange() {
        addComponent()
        let id = models.current().components[0].id.value

        _ = MoveComponents(models: models)
            .execute(MoveComponentsRequest(moves: [ComponentMove(componentId: id, x: 500, y: 500)]))
        #expect(models.current().components[0].position == Point(x: 500, y: 500))

        _ = undo()
        #expect(models.current().components[0].position == Point(x: 0, y: 0))

        _ = AddZone(models: models, ids: ids).execute(AddZoneRequest(x: 0, y: 0, width: 400, height: 300))
        #expect(models.current().zones.count == 1)
        _ = undo()
        #expect(models.current().zones.isEmpty)

        _ = RecordControlImplemented(models: models)
            .execute(RecordControlImplementedRequest(controlKey: "node:x:y::deadbeef"))
        _ = undo()
        #expect(models.current().implementedControls.isEmpty)
    }

    @Test func neverCountsARefusedChangeAsAStep() {
        addComponent()

        // Every one of these is refused and changes nothing.
        _ = AddComponent(models: models, catalogue: catalogue, ids: ids)
            .execute(AddComponentRequest(technologyId: "aws-imaginary", x: 0, y: 0, sensitivity: "internal"))
        _ = MoveComponents(models: models)
            .execute(MoveComponentsRequest(moves: [ComponentMove(componentId: "nope", x: 1, y: 1)]))
        _ = RemoveZone(models: models).execute(RemoveZoneRequest(zoneId: "nope"))

        // One undo takes the model back to empty, because only one thing
        // actually happened.
        #expect(undo() == .undone(canUndoMore: false))
        #expect(models.current().components.isEmpty)
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter HistoryTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'UndoLastChange' in scope`.

- [ ] **Step 3: Write both use cases**

Create `.../modelling/usecase/UndoLastChange.swift`:

```swift
public protocol UndoLastChangeUseCase {
    func execute(_ request: UndoLastChangeRequest) -> UndoLastChangeResponse
}

public struct UndoLastChangeRequest: Equatable, Sendable {
    public init() {}
}

public enum UndoLastChangeResponse: Equatable, Sendable {
    /// Says whether there is more to take back, so a menu item can dim itself
    /// without asking a second question.
    case undone(canUndoMore: Bool)
    case nothingToUndo
}

/// Takes the model back one change.
public struct UndoLastChange: UndoLastChangeUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: UndoLastChangeRequest) -> UndoLastChangeResponse {
        guard models.undo() else { return .nothingToUndo }
        return .undone(canUndoMore: models.canUndo)
    }
}
```

Create `.../modelling/usecase/RedoChange.swift`, the same shape:

```swift
public protocol RedoChangeUseCase {
    func execute(_ request: RedoChangeRequest) -> RedoChangeResponse
}

public struct RedoChangeRequest: Equatable, Sendable {
    public init() {}
}

public enum RedoChangeResponse: Equatable, Sendable {
    case redone(canRedoMore: Bool)
    case nothingToRedo
}

/// Puts back a change that was taken back.
public struct RedoChange: RedoChangeUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RedoChangeRequest) -> RedoChangeResponse {
        guard models.redo() else { return .nothingToRedo }
        return .redone(canRedoMore: models.canRedo)
    }
}
```

Vend both from `UseCaseFactory`, `TestDependencies` and `Dependencies`, each taking `models`.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit threatmodeller/Dependencies.swift
git commit -m "feat: add UndoLastChange and RedoChange

Each says whether there is more, so a menu item can dim itself without asking
a second question."
```

---

### Task 3: What a copy holds, and how it travels

**Files:**
- Create: `.../modelling/domain/SelectionSnippet.swift`
- Modify: `.../modelling/gateway/ThreatModelFileGateway.swift`
- Modify: `ThreatModelKit/Sources/FileGateways/DocumentJSON.swift`, `ThreatModelCodec.swift`
- Modify: `ThreatModelKit/Tests/GatewayIntegrationTests/ThreatModelCodecTests.swift`

**Interfaces:**
- Produces: `SelectionSnippet(components:connections:zones:)` with `.isEmpty`; `ThreatModelFileGateway.encodeSelection(_:) throws -> String` and `.decodeSelection(_:) throws -> SelectionSnippet`.

A snippet is text so it crosses documents, crosses copies of the application, and can be read by a person. It carries the same format version as a document, and a snippet from a version this application does not know is refused the same way.

- [ ] **Step 1: Write the failing test**

Add to `ThreatModelCodecTests`:

```swift
    private func snippet() -> SelectionSnippet {
        SelectionSnippet(
            components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 10, y: 20),
                    sensitivity: .restricted,
                    customName: "Web tier",
                    threatsDisabled: true
                )
            ],
            connections: [
                Connection(id: ConnectionId("k1"), source: ComponentId("c1"), target: ComponentId("c1"))
            ],
            zones: [
                Zone(id: ZoneId("z1"), rect: Rect(x: 0, y: 0, width: 400, height: 300), name: "Edge")
            ]
        )
    }

    @Test func carriesASelectionThroughARoundTrip() throws {
        let original = snippet()

        #expect(try codec.decodeSelection(try codec.encodeSelection(original)) == original)
    }

    @Test func carriesAnEmptySelectionThrough() throws {
        let empty = SelectionSnippet(components: [], connections: [], zones: [])

        #expect(try codec.decodeSelection(try codec.encodeSelection(empty)) == empty)
        #expect(empty.isEmpty)
    }

    @Test func putsASelectionOnTheClipboardAsSomethingAPersonCanRead() throws {
        let text = try codec.encodeSelection(snippet())

        #expect(text.contains("\"formatVersion\""))
        #expect(text.contains("\"aws-ec2\""))
    }

    @Test func refusesASnippetFromAVersionItDoesNotKnow() throws {
        let text = try codec.encodeSelection(snippet())
            .replacingOccurrences(of: "\"formatVersion\" : 1", with: "\"formatVersion\" : 99")

        #expect(throws: ThreatModelFileError.unsupportedFormatVersion(found: 99, supported: 1)) {
            try codec.decodeSelection(text)
        }
    }

    @Test func refusesClipboardTextThatIsNotASelection() {
        #expect(throws: (any Error).self) {
            try codec.decodeSelection("just some words someone copied")
        }
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter ThreatModelCodecTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'SelectionSnippet' in scope`.

- [ ] **Step 3: Write the snippet**

Create `.../modelling/domain/SelectionSnippet.swift`:

```swift
/// What a copy holds.
///
/// The identifiers inside are the ones the copy was taken from. They are unique
/// within one document only, and a snippet crosses documents, so `PasteSelection`
/// always mints fresh ones and rewrites the links between them.
public struct SelectionSnippet: Equatable, Sendable {
    public let components: [Component]
    /// Only the links whose both ends are in `components`. A link to something
    /// that was not copied has nothing to attach to.
    public let connections: [Connection]
    public let zones: [Zone]

    public init(components: [Component], connections: [Connection], zones: [Zone]) {
        self.components = components
        self.connections = connections
        self.zones = zones
    }

    public var isEmpty: Bool {
        components.isEmpty && connections.isEmpty && zones.isEmpty
    }
}
```

Add to `ThreatModelFileGateway`:

```swift
    /// A selection as clipboard text, so it crosses documents and copies of the
    /// application, and a person can read it.
    func encodeSelection(_ selection: SelectionSnippet) throws -> String
    func decodeSelection(_ text: String) throws -> SelectionSnippet
```

- [ ] **Step 4: Teach the codec**

Add to `DocumentJSON.swift`:

```swift
struct SelectionJSON: Codable {
    let formatVersion: Int
    let components: [ComponentJSON]
    let connections: [ConnectionJSON]
    let zones: [ZoneJSON]
}
```

Add to `ThreatModelCodec`, reusing the mapping the document already does. Pull the four per-value mappings out into private helpers so the document and the snippet share them:

```swift
    public func encodeSelection(_ selection: SelectionSnippet) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        let data = try encoder.encode(
            SelectionJSON(
                formatVersion: Self.formatVersion,
                components: selection.components.map(Self.json(from:)),
                connections: selection.connections.map(Self.json(from:)),
                zones: selection.zones.map(Self.json(from:))
            )
        )
        return String(decoding: data, as: UTF8.self)
    }

    public func decodeSelection(_ text: String) throws -> SelectionSnippet {
        let snippet = try JSONDecoder().decode(SelectionJSON.self, from: Data(text.utf8))

        guard snippet.formatVersion == Self.formatVersion else {
            throw ThreatModelFileError.unsupportedFormatVersion(
                found: snippet.formatVersion,
                supported: Self.formatVersion
            )
        }

        return SelectionSnippet(
            components: try snippet.components.map(Self.component(from:)),
            connections: snippet.connections.map(Self.connection(from:)),
            zones: try snippet.zones.map(Self.zone(from:))
        )
    }
```

WARNING: extracting those helpers changes `encode` and `decode` too. Run the document round-trip tests as well as the snippet ones; they are the check that the extraction lost nothing.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit
git commit -m "feat: turn a selection into clipboard text

A snippet is text, so it crosses documents, crosses copies of the
application, and a person can read it. It carries the same format version as
a document and is refused the same way."
```

---

### Task 4: `CopySelection`, `PasteSelection`, `DuplicateSelection`

**Files:**
- Create: the three use case files under `.../modelling/usecase/`
- Modify: `.../UseCaseFactory.swift`, `.../TestDependencies.swift`, `threatmodeller/Dependencies.swift`
- Create: `ThreatModelKit/Tests/UnitTests/ClipboardUseCaseTests.swift`

**Interfaces:**
- Produces:
  - `CopySelectionUseCase`, `CopySelectionRequest(componentIds:zoneIds:)`, `CopySelectionResponse` (`.copied(payload:componentCount:zoneCount:)`, `.nothingSelected`)
  - `PasteSelectionUseCase`, `PasteSelectionRequest(payload:offsetX:offsetY:)`, `PasteSelectionResponse` (`.pasted(componentIds:zoneIds:)`, `.nothingToPaste`, `.unreadable(reason:)`)
  - `DuplicateSelectionUseCase`, `DuplicateSelectionRequest(componentIds:zoneIds:offsetX:offsetY:)`, `DuplicateSelectionResponse` (`.duplicated(componentIds:zoneIds:)`, `.nothingSelected`)
  - `PasteSelection.defaultOffset`

Decisions this task fixes:

- **A copied link needs both its ends.** Copying one end of a link and pasting it would leave a link to nothing, so `CopySelection` keeps only the links whose source and target are both in the selection.
- **Pasting always mints fresh identifiers**, and rewrites the copied links onto them. Identifiers are unique within one document, and the clipboard crosses documents.
- **Pasting offsets by 40 points**, so the copy is visibly not the original.
- **Each of the three is one undo step.** All the work happens inside one `mutate`.
- **Pasting does not carry ticks or overrides.** A control key names a component id that no longer exists after the paste, and a severity override is keyed by technology and already applies. Copying a component copies the component, not the user's answers about it.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/ClipboardUseCaseTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport
import FileGateways

struct ClipboardUseCaseTests {
    private let models = InMemoryThreatModelGateway()
    private let catalogue = CatalogueFixture.catalogue()
    private let ids = SequentialIdentityGenerator()
    private let codec = ThreatModelCodec()

    private func seed() -> (web: String, database: String, zone: String) {
        _ = CreateThreatModel(models: models, catalogue: catalogue, clock: FixedClock())
            .execute(CreateThreatModelRequest(name: "Payments"))

        let add = AddComponent(models: models, catalogue: catalogue, ids: ids)
        guard case .added(let web) = add.execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 100, y: 100, sensitivity: "confidential")
        ), case .added(let database) = add.execute(
            AddComponentRequest(technologyId: "aws-rds", x: 500, y: 100, sensitivity: "restricted")
        ) else {
            Issue.record("Expected two components")
            return ("", "", "")
        }
        _ = ConnectComponents(models: models, ids: ids)
            .execute(ConnectComponentsRequest(sourceComponentId: web, targetComponentId: database))
        guard case .added(let zone) = AddZone(models: models, ids: ids)
            .execute(AddZoneRequest(x: 0, y: 0, width: 700, height: 600)) else {
            Issue.record("Expected a zone")
            return ("", "", "")
        }
        return (web, database, zone)
    }

    private func copy(components: [String], zones: [String] = []) -> CopySelectionResponse {
        CopySelection(models: models, files: codec)
            .execute(CopySelectionRequest(componentIds: components, zoneIds: zones))
    }

    private func paste(_ payload: String) -> PasteSelectionResponse {
        PasteSelection(models: models, ids: ids, files: codec).execute(
            PasteSelectionRequest(
                payload: payload,
                offsetX: PasteSelection.defaultOffset,
                offsetY: PasteSelection.defaultOffset
            )
        )
    }

    private func payload(_ response: CopySelectionResponse) -> String {
        guard case .copied(let payload, _, _) = response else {
            Issue.record("Expected the selection to be copied")
            return ""
        }
        return payload
    }

    @Test func copiesNothingWhenNothingIsSelected() {
        _ = seed()

        #expect(copy(components: []) == .nothingSelected)
    }

    @Test func copiesWhatWasSelected() {
        let seeded = seed()

        guard case .copied(_, let componentCount, let zoneCount) = copy(
            components: [seeded.web, seeded.database],
            zones: [seeded.zone]
        ) else {
            Issue.record("Expected the selection to be copied")
            return
        }
        #expect(componentCount == 2)
        #expect(zoneCount == 1)
    }

    @Test func keepsOnlyTheLinksWithBothEndsInTheSelection() throws {
        let seeded = seed()

        let both = try codec.decodeSelection(payload(copy(components: [seeded.web, seeded.database])))
        #expect(both.connections.count == 1)

        let one = try codec.decodeSelection(payload(copy(components: [seeded.web])))
        #expect(one.components.count == 1)
        #expect(one.connections.isEmpty)
    }

    @Test func pastesFreshComponentsBesideTheOriginals() throws {
        let seeded = seed()
        let text = payload(copy(components: [seeded.web]))

        guard case .pasted(let componentIds, _) = paste(text) else {
            Issue.record("Expected the selection to be pasted")
            return
        }

        #expect(componentIds.count == 1)
        #expect(componentIds.first != seeded.web)
        #expect(models.current().components.count == 3)

        let pasted = try #require(models.current().component(ComponentId(try #require(componentIds.first))))
        let original = try #require(models.current().component(ComponentId(seeded.web)))
        #expect(pasted.position == Point(
            x: original.position.x + PasteSelection.defaultOffset,
            y: original.position.y + PasteSelection.defaultOffset
        ))
        #expect(pasted.technologyId == original.technologyId)
        #expect(pasted.sensitivity == original.sensitivity)
    }

    @Test func rewiresACopiedLinkOntoTheNewComponents() throws {
        let seeded = seed()
        let text = payload(copy(components: [seeded.web, seeded.database]))

        guard case .pasted(let componentIds, _) = paste(text) else {
            Issue.record("Expected the selection to be pasted")
            return
        }

        #expect(models.current().connections.count == 2)
        let pasted = try #require(models.current().connections.last)
        #expect(componentIds.contains(pasted.source.value))
        #expect(componentIds.contains(pasted.target.value))
        // The copy is a copy, not a second reference to the original.
        #expect(pasted.source.value != seeded.web)
    }

    @Test func pastesAZoneToo() throws {
        let seeded = seed()
        let text = payload(copy(components: [], zones: [seeded.zone]))

        guard case .pasted(_, let zoneIds) = paste(text) else {
            Issue.record("Expected the selection to be pasted")
            return
        }

        #expect(zoneIds.count == 1)
        #expect(zoneIds.first != seeded.zone)
        #expect(models.current().zones.count == 2)
    }

    @Test func refusesClipboardTextItCannotRead() {
        _ = seed()
        let before = models.current()

        guard case .unreadable = paste("someone copied a sentence") else {
            Issue.record("Expected the text to be refused")
            return
        }
        #expect(models.current() == before)
    }

    @Test func saysThereIsNothingToPasteForAnEmptySnippet() throws {
        _ = seed()
        let empty = try codec.encodeSelection(
            SelectionSnippet(components: [], connections: [], zones: [])
        )

        #expect(paste(empty) == .nothingToPaste)
    }

    @Test func pastesAsOneStepToTakeBack() {
        let seeded = seed()
        let text = payload(copy(components: [seeded.web, seeded.database]))
        let before = models.current()

        _ = paste(text)
        #expect(models.current().components.count == 4)

        #expect(UndoLastChange(models: models).execute(UndoLastChangeRequest())
                == .undone(canUndoMore: true))
        #expect(models.current() == before)
    }

    @Test func duplicatesWithoutTouchingTheClipboard() throws {
        let seeded = seed()

        guard case .duplicated(let componentIds, _) = DuplicateSelection(
            models: models,
            ids: ids,
            files: codec
        ).execute(
            DuplicateSelectionRequest(
                componentIds: [seeded.web],
                zoneIds: [],
                offsetX: PasteSelection.defaultOffset,
                offsetY: PasteSelection.defaultOffset
            )
        ) else {
            Issue.record("Expected the selection to be duplicated")
            return
        }

        #expect(componentIds.count == 1)
        #expect(componentIds.first != seeded.web)
        #expect(models.current().components.count == 3)
    }

    @Test func duplicatesNothingWhenNothingIsSelected() {
        _ = seed()

        #expect(DuplicateSelection(models: models, ids: ids, files: codec).execute(
            DuplicateSelectionRequest(componentIds: [], zoneIds: [], offsetX: 0, offsetY: 0)
        ) == .nothingSelected)
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter ClipboardUseCaseTests 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `cannot find 'CopySelection' in scope`.

- [ ] **Step 3: Write `CopySelection`**

```swift
public protocol CopySelectionUseCase {
    func execute(_ request: CopySelectionRequest) -> CopySelectionResponse
}

public struct CopySelectionRequest: Equatable, Sendable {
    public let componentIds: [String]
    public let zoneIds: [String]

    public init(componentIds: [String], zoneIds: [String]) {
        self.componentIds = componentIds
        self.zoneIds = zoneIds
    }
}

public enum CopySelectionResponse: Equatable, Sendable {
    /// Clipboard text, and what it holds, so the delivery mechanism can say
    /// what it copied.
    case copied(payload: String, componentCount: Int, zoneCount: Int)
    case nothingSelected
}

/// Turns what the user selected into clipboard text.
///
/// Only the links whose source and target are both selected come along:
/// pasting a link with one end missing would leave a link to nothing.
public struct CopySelection: CopySelectionUseCase {
    private let models: ThreatModelGateway
    private let files: ThreatModelFileGateway

    public init(models: ThreatModelGateway, files: ThreatModelFileGateway) {
        self.models = models
        self.files = files
    }

    public func execute(_ request: CopySelectionRequest) -> CopySelectionResponse {
        let snippet = Self.snippet(
            of: models.current(),
            componentIds: request.componentIds,
            zoneIds: request.zoneIds
        )
        guard snippet.isEmpty == false else { return .nothingSelected }

        do {
            return .copied(
                payload: try files.encodeSelection(snippet),
                componentCount: snippet.components.count,
                zoneCount: snippet.zones.count
            )
        } catch {
            return .nothingSelected
        }
    }

    /// Shared with `DuplicateSelection`, which takes the same slice of a model
    /// without going near the clipboard.
    static func snippet(
        of model: ThreatModel,
        componentIds: [String],
        zoneIds: [String]
    ) -> SelectionSnippet {
        let components = Set(componentIds.map(ComponentId.init))
        let zones = Set(zoneIds.map(ZoneId.init))

        return SelectionSnippet(
            components: model.components.filter { components.contains($0.id) },
            connections: model.connections.filter {
                components.contains($0.source) && components.contains($0.target)
            },
            zones: model.zones.filter { zones.contains($0.id) }
        )
    }
}
```

- [ ] **Step 4: Write `PasteSelection`**

```swift
public protocol PasteSelectionUseCase {
    func execute(_ request: PasteSelectionRequest) -> PasteSelectionResponse
}

public struct PasteSelectionRequest: Equatable, Sendable {
    public let payload: String
    public let offsetX: Double
    public let offsetY: Double

    public init(payload: String, offsetX: Double, offsetY: Double) {
        self.payload = payload
        self.offsetX = offsetX
        self.offsetY = offsetY
    }
}

public enum PasteSelectionResponse: Equatable, Sendable {
    /// The new identifiers, so the canvas can select what was just pasted.
    case pasted(componentIds: [String], zoneIds: [String])
    case nothingToPaste
    case unreadable(reason: String)
}

/// Puts a copied selection back onto the model.
///
/// Every identifier is fresh and the copied links are rewritten onto them:
/// identifiers are unique within one document and the clipboard crosses
/// documents. The paste is offset so the copy is visibly not the original.
///
/// Ticks and overrides do not come along. A control key names a component that
/// no longer exists after the paste, and a severity override is keyed by
/// technology and already applies. Copying a component copies the component,
/// not the user's answers about it.
public struct PasteSelection: PasteSelectionUseCase {
    /// Far enough to see, near enough to still be beside the original.
    public static let defaultOffset = 40.0

    private let models: ThreatModelGateway
    private let ids: IdentityGenerator
    private let files: ThreatModelFileGateway

    public init(models: ThreatModelGateway, ids: IdentityGenerator, files: ThreatModelFileGateway) {
        self.models = models
        self.ids = ids
        self.files = files
    }

    public func execute(_ request: PasteSelectionRequest) -> PasteSelectionResponse {
        let snippet: SelectionSnippet
        do {
            snippet = try files.decodeSelection(request.payload)
        } catch {
            return .unreadable(reason: String(describing: error))
        }
        guard snippet.isEmpty == false else { return .nothingToPaste }

        let placed = SelectionPlacement.place(
            snippet,
            offsetX: request.offsetX,
            offsetY: request.offsetY,
            ids: ids
        )

        return models.mutate { model in
            model.components.append(contentsOf: placed.components)
            model.connections.append(contentsOf: placed.connections)
            model.zones.append(contentsOf: placed.zones)
            return .pasted(
                componentIds: placed.components.map(\.id.value),
                zoneIds: placed.zones.map(\.id.value)
            )
        }
    }
}

/// Gives a copied selection fresh identifiers and a new place to sit.
///
/// Shared by pasting and duplicating, which differ only in where the selection
/// came from.
enum SelectionPlacement {
    static func place(
        _ snippet: SelectionSnippet,
        offsetX: Double,
        offsetY: Double,
        ids: IdentityGenerator
    ) -> SelectionSnippet {
        var componentIds: [ComponentId: ComponentId] = [:]

        let components = snippet.components.map { component -> Component in
            let fresh = ComponentId(ids.next())
            componentIds[component.id] = fresh
            return Component(
                id: fresh,
                technologyId: component.technologyId,
                position: Point(
                    x: component.position.x + offsetX,
                    y: component.position.y + offsetY
                ),
                sensitivity: component.sensitivity,
                customName: component.customName,
                threatsDisabled: component.threatsDisabled
            )
        }

        let connections = snippet.connections.compactMap { connection -> Connection? in
            guard let source = componentIds[connection.source],
                  let target = componentIds[connection.target] else { return nil }
            return Connection(id: ConnectionId(ids.next()), source: source, target: target)
        }

        let zones = snippet.zones.map { zone in
            Zone(
                id: ZoneId(ids.next()),
                rect: Rect(
                    x: zone.rect.origin.x + offsetX,
                    y: zone.rect.origin.y + offsetY,
                    width: zone.rect.size.width,
                    height: zone.rect.size.height
                ),
                name: zone.name,
                networkZone: zone.networkZone,
                networkType: zone.networkType,
                riskReductionEnabled: zone.riskReductionEnabled,
                riskReductionPercent: zone.riskReductionPercent
            )
        }

        return SelectionSnippet(components: components, connections: connections, zones: zones)
    }
}
```

- [ ] **Step 5: Write `DuplicateSelection`**

```swift
public protocol DuplicateSelectionUseCase {
    func execute(_ request: DuplicateSelectionRequest) -> DuplicateSelectionResponse
}

public struct DuplicateSelectionRequest: Equatable, Sendable {
    public let componentIds: [String]
    public let zoneIds: [String]
    public let offsetX: Double
    public let offsetY: Double

    public init(componentIds: [String], zoneIds: [String], offsetX: Double, offsetY: Double) {
        self.componentIds = componentIds
        self.zoneIds = zoneIds
        self.offsetX = offsetX
        self.offsetY = offsetY
    }
}

public enum DuplicateSelectionResponse: Equatable, Sendable {
    case duplicated(componentIds: [String], zoneIds: [String])
    case nothingSelected
}

/// Copies and pastes in one step, without going near the clipboard: what the
/// user had copied before is still there afterwards.
public struct DuplicateSelection: DuplicateSelectionUseCase {
    private let models: ThreatModelGateway
    private let ids: IdentityGenerator
    private let files: ThreatModelFileGateway

    public init(models: ThreatModelGateway, ids: IdentityGenerator, files: ThreatModelFileGateway) {
        self.models = models
        self.ids = ids
        self.files = files
    }

    public func execute(_ request: DuplicateSelectionRequest) -> DuplicateSelectionResponse {
        models.mutate { model in
            let snippet = CopySelection.snippet(
                of: model,
                componentIds: request.componentIds,
                zoneIds: request.zoneIds
            )
            guard snippet.isEmpty == false else { return .nothingSelected }

            let placed = SelectionPlacement.place(
                snippet,
                offsetX: request.offsetX,
                offsetY: request.offsetY,
                ids: ids
            )
            model.components.append(contentsOf: placed.components)
            model.connections.append(contentsOf: placed.connections)
            model.zones.append(contentsOf: placed.zones)

            return .duplicated(
                componentIds: placed.components.map(\.id.value),
                zoneIds: placed.zones.map(\.id.value)
            )
        }
    }
}
```

WARNING: `DuplicateSelection` never uses `files`, but takes it so the three use cases are wired the same way and a later change to how a snippet is built has one shape to follow. If that reads as clutter when you get there, drop the parameter and say so in the commit.

- [ ] **Step 6: Vend all three, and run the tests**

Add the three to `UseCaseFactory`, `TestDependencies` and `Dependencies`.

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test 2>&1 | tail -3
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit threatmodeller/Dependencies.swift
git commit -m "feat: copy, paste and duplicate a selection

Only the links with both ends selected come along, and pasting mints fresh
identifiers and rewrites those links onto them, because identifiers are
unique within one document and the clipboard crosses documents. Each is one
step to take back."
```

---

### Task 5: The acceptance test

**Files:**
- Create: `ThreatModelKit/Tests/AcceptanceTests/TakingItBackTests.swift`
- Modify: `.../modelling/usecase/ViewThreatModel.swift` — the canvas says whether there is anything to take back

`ViewThreatModelResponse` gains `canUndo` and `canRedo`, so a menu item can dim itself from the same read that draws the canvas.

- [ ] **Step 1: Write the test**

```swift
import Testing
import ThreatModelKit
import TestSupport

/// Given a change I did not mean to make
/// When I take it back
/// Then the model is as it was, and I can put the change back again
struct TakingItBackTests {
    private let app = TestDependencies()

    private func add(_ technologyId: String, x: Double) -> String {
        guard case .added(let componentId) = app.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: x, y: 100, sensitivity: "confidential")
        ) else {
            Issue.record("Expected the component to be added")
            return ""
        }
        return componentId
    }

    private func canvas() -> ViewThreatModelResponse {
        app.viewThreatModel().execute(ViewThreatModelRequest())
    }

    private func threats() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    @Test func takesBackTheLastThingIDid() {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        #expect(canvas().canUndo == false)

        let web = add("aws-ec2", x: 100)
        #expect(threats().isEmpty == false)
        #expect(canvas().canUndo)

        #expect(app.undoLastChange().execute(UndoLastChangeRequest())
                == .undone(canUndoMore: false))

        #expect(canvas().components.isEmpty)
        #expect(threats().isEmpty)
        #expect(canvas().canRedo)

        #expect(app.redoChange().execute(RedoChangeRequest()) == .redone(canRedoMore: false))
        #expect(canvas().components.map(\.id) == [web])
        #expect(threats().isEmpty == false)
    }

    @Test func takesBackEachStepInTurn() {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        _ = add("aws-ec2", x: 100)
        _ = add("aws-rds", x: 500)
        _ = app.addZone().execute(AddZoneRequest(x: 0, y: 0, width: 700, height: 600))

        #expect(canvas().zones.count == 1)
        _ = app.undoLastChange().execute(UndoLastChangeRequest())
        #expect(canvas().zones.isEmpty)
        #expect(canvas().components.count == 2)

        _ = app.undoLastChange().execute(UndoLastChangeRequest())
        #expect(canvas().components.count == 1)

        _ = app.undoLastChange().execute(UndoLastChangeRequest())
        #expect(canvas().components.isEmpty)
        #expect(canvas().canUndo == false)
    }

    @Test func forgetsTheAbandonedBranchOnceIDoSomethingElse() {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        _ = add("aws-ec2", x: 100)
        _ = app.undoLastChange().execute(UndoLastChangeRequest())
        #expect(canvas().canRedo)

        _ = add("aws-rds", x: 500)

        #expect(canvas().canRedo == false)
        #expect(canvas().components.count == 1)
    }

    @Test func copiesAndPastesAcrossTheSameModel() throws {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        let web = add("aws-ec2", x: 100)
        let database = add("aws-rds", x: 500)
        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: web, targetComponentId: database)
        )
        let before = threats().count

        guard case .copied(let payload, let componentCount, _) = app.copySelection().execute(
            CopySelectionRequest(componentIds: [web, database], zoneIds: [])
        ) else {
            Issue.record("Expected the selection to be copied")
            return
        }
        #expect(componentCount == 2)

        guard case .pasted(let componentIds, _) = app.pasteSelection().execute(
            PasteSelectionRequest(
                payload: payload,
                offsetX: PasteSelection.defaultOffset,
                offsetY: PasteSelection.defaultOffset
            )
        ) else {
            Issue.record("Expected the selection to be pasted")
            return
        }

        #expect(componentIds.count == 2)
        #expect(canvas().components.count == 4)
        #expect(canvas().connections.count == 2)
        // Twice the diagram is twice the threats.
        #expect(threats().count == before * 2)

        // And the whole paste comes back out in one step.
        _ = app.undoLastChange().execute(UndoLastChangeRequest())
        #expect(canvas().components.count == 2)
        #expect(threats().count == before)
    }

    @Test func pastesIntoADifferentModel() throws {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        let web = add("aws-ec2", x: 100)

        guard case .copied(let payload, _, _) = app.copySelection().execute(
            CopySelectionRequest(componentIds: [web], zoneIds: [])
        ) else {
            Issue.record("Expected the selection to be copied")
            return
        }

        // A different document entirely.
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Reporting"))
        #expect(canvas().components.isEmpty)

        guard case .pasted(let componentIds, _) = app.pasteSelection().execute(
            PasteSelectionRequest(payload: payload, offsetX: 0, offsetY: 0)
        ) else {
            Issue.record("Expected the selection to be pasted")
            return
        }

        #expect(canvas().components.count == 1)
        #expect(componentIds.first != web)
        #expect(canvas().components.first?.name == "EC2")
    }

    @Test func duplicatesInPlaceWithoutTouchingWhatIsOnTheClipboard() throws {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        let web = add("aws-ec2", x: 100)
        let database = add("aws-rds", x: 500)

        guard case .copied(let payload, _, _) = app.copySelection().execute(
            CopySelectionRequest(componentIds: [web], zoneIds: [])
        ) else {
            Issue.record("Expected the selection to be copied")
            return
        }

        _ = app.duplicateSelection().execute(
            DuplicateSelectionRequest(
                componentIds: [database],
                zoneIds: [],
                offsetX: PasteSelection.defaultOffset,
                offsetY: PasteSelection.defaultOffset
            )
        )
        #expect(canvas().components.count == 3)

        // What was copied is still what is on the clipboard.
        guard case .pasted = app.pasteSelection().execute(
            PasteSelectionRequest(payload: payload, offsetX: 0, offsetY: 0)
        ) else {
            Issue.record("Expected the earlier copy to still paste")
            return
        }
        #expect(canvas().components.count == 4)
    }

    @Test func neverOffersToTakeBackOpeningADocument() throws {
        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Payments"))
        _ = add("aws-ec2", x: 100)
        guard case .saved(let file) = app.saveThreatModel().execute(SaveThreatModelRequest()) else {
            Issue.record("Expected the model to be saved")
            return
        }

        _ = app.createThreatModel().execute(CreateThreatModelRequest(name: "Blank"))
        _ = add("aws-rds", x: 0)
        #expect(canvas().canUndo)

        _ = app.openThreatModel().execute(OpenThreatModelRequest(data: file))

        // Undoing back into a document the user closed would be a surprise.
        #expect(canvas().canUndo == false)
        #expect(canvas().canRedo == false)
    }
}
```

- [ ] **Step 2: Add `canUndo` and `canRedo` to the canvas snapshot**

`ViewThreatModelResponse` gains the two as its last stored properties and initialiser parameters, defaulting to `false` so existing constructions compile, and `ViewThreatModel.execute` fills them from `models.canUndo` and `models.canRedo`.

- [ ] **Step 3: Run it, then the whole suite**

```bash
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && swift test --filter TakingItBackTests 2>&1 | tail -5
cd /Users/craigjbass/Projects/threat-modeller/ThreatModelKit && time swift test 2>&1 | tail -3
```

Expected: PASS, whole suite under 30 seconds.

- [ ] **Step 4: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add ThreatModelKit
git commit -m "test: accept the milestone 6B core at the use case boundary

Every change comes back out in one step and goes back in again. A paste is
one step whatever it holds. A selection copied from one model pastes into
another. Opening a document is never something to undo back out of."
```

---

### Task 6: The session takes it back, and reaches the clipboard

**Files:**
- Modify: `threatmodeller/ThreatModelSession.swift`
- Modify: `threatmodellerTests/threatmodellerTests.swift`

**Interfaces:**
- Produces: `ThreatModelSession.canUndo`, `.canRedo`, `.undo()`, `.redo()`, `.copySelection(componentIds:zoneIds:)`, `.cutSelection(componentIds:zoneIds:)`, `.paste() -> (componentIds: [String], zoneIds: [String])`, `.duplicate(componentIds:zoneIds:)`.

The session owns the pasteboard, because a pasteboard is an IO mechanism and the core must not know one exists. The payload is a string, so `NSPasteboard.general` carries it as `.string` and any other application can read it.

- [ ] **Step 1: Write the failing test**

Add to `threatmodellerTests/threatmodellerTests.swift`:

```swift
    @Test func takesBackTheLastChange() {
        let session = session()
        #expect(session.canUndo == false)

        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        #expect(session.canUndo)
        #expect(session.threats.isEmpty == false)

        session.undo()

        #expect(session.canvas.components.isEmpty)
        #expect(session.threats.isEmpty)
        #expect(session.canRedo)

        session.redo()
        #expect(session.canvas.components.count == 1)
    }

    @Test func saysNothingWhenThereIsNothingToTakeBack() {
        let session = session()

        session.undo()

        #expect(session.errorMessage == nil)
    }

    @Test func copiesAndPastesASelection() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        let web = try #require(session.canvas.components.first).id

        session.copySelection(componentIds: [web], zoneIds: [])
        let pasted = session.paste()

        #expect(pasted.componentIds.count == 1)
        #expect(session.canvas.components.count == 2)
        #expect(session.errorMessage == nil)
    }

    @Test func cutRemovesWhatItCopied() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        let web = try #require(session.canvas.components.first).id

        session.cutSelection(componentIds: [web], zoneIds: [])
        #expect(session.canvas.components.isEmpty)

        let pasted = session.paste()
        #expect(pasted.componentIds.count == 1)
        #expect(session.canvas.components.count == 1)
    }

    @Test func duplicatesWithoutTouchingTheClipboard() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        session.add(technologyId: "aws-rds", x: 500, y: 100)
        let ids = session.canvas.components.map(\.id)

        session.copySelection(componentIds: [ids[0]], zoneIds: [])
        let duplicated = session.duplicate(componentIds: [ids[1]], zoneIds: [])

        #expect(duplicated.componentIds.count == 1)
        #expect(session.canvas.components.count == 3)

        // The earlier copy is still what pastes.
        _ = session.paste()
        #expect(session.canvas.components.count == 4)
    }

    @Test func saysNothingWhenTheClipboardHoldsSomethingElse() {
        let session = session()
        session.putOnClipboard("a sentence someone copied from a web page")

        let pasted = session.paste()

        #expect(pasted.componentIds.isEmpty)
        #expect(session.errorMessage == "There is no threat model on the clipboard.")
    }
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'error:' | head -3
```

Expected: FAIL with `has no member 'canUndo'`.

- [ ] **Step 3: Give the session the commands**

Add to `ThreatModelSession`:

```swift
import AppKit
```

```swift
    var canUndo: Bool { canvas.canUndo }
    var canRedo: Bool { canvas.canRedo }

    func undo() {
        // Nothing to take back is not worth a message: the menu item is
        // already dim, and a key pressed once too often is not a mistake.
        _ = useCases.undoLastChange().execute(UndoLastChangeRequest())
        errorMessage = nil
        refresh()
    }

    func redo() {
        _ = useCases.redoChange().execute(RedoChangeRequest())
        errorMessage = nil
        refresh()
    }

    func copySelection(componentIds: [String], zoneIds: [String]) {
        switch useCases.copySelection().execute(
            CopySelectionRequest(componentIds: componentIds, zoneIds: zoneIds)
        ) {
        case .copied(let payload, _, _):
            putOnClipboard(payload)
            errorMessage = nil
        case .nothingSelected:
            errorMessage = nil
        }
    }

    /// Cut is copy then delete, and the delete is what can be taken back.
    func cutSelection(componentIds: [String], zoneIds: [String]) {
        copySelection(componentIds: componentIds, zoneIds: zoneIds)
        for zoneId in zoneIds { removeZone(zoneId) }
        if componentIds.isEmpty == false { removeComponents(componentIds) }
    }

    @discardableResult
    func paste() -> (componentIds: [String], zoneIds: [String]) {
        defer { refresh() }

        guard let payload = clipboardText() else {
            errorMessage = "There is no threat model on the clipboard."
            return ([], [])
        }

        switch useCases.pasteSelection().execute(
            PasteSelectionRequest(
                payload: payload,
                offsetX: PasteSelection.defaultOffset,
                offsetY: PasteSelection.defaultOffset
            )
        ) {
        case .pasted(let componentIds, let zoneIds):
            errorMessage = nil
            return (componentIds, zoneIds)
        case .nothingToPaste:
            errorMessage = nil
            return ([], [])
        case .unreadable:
            errorMessage = "There is no threat model on the clipboard."
            return ([], [])
        }
    }

    @discardableResult
    func duplicate(componentIds: [String], zoneIds: [String]) -> (componentIds: [String], zoneIds: [String]) {
        defer { refresh() }

        switch useCases.duplicateSelection().execute(
            DuplicateSelectionRequest(
                componentIds: componentIds,
                zoneIds: zoneIds,
                offsetX: PasteSelection.defaultOffset,
                offsetY: PasteSelection.defaultOffset
            )
        ) {
        case .duplicated(let componentIds, let zoneIds):
            errorMessage = nil
            return (componentIds, zoneIds)
        case .nothingSelected:
            errorMessage = nil
            return ([], [])
        }
    }

    /// The pasteboard is an IO mechanism, so it lives here and not in the core.
    /// The payload is a string, so any other application can read it.
    func putOnClipboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    private func clipboardText() -> String? {
        NSPasteboard.general.string(forType: .string)
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/craigjbass/Projects/threat-modeller
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'Failing tests|\*\* TEST' -A3 | head -8
```

Expected: PASS.

WARNING: these tests use the real system pasteboard, so they change what the person running them has copied. That is a real cost and it is recorded on the carry-forward. If it becomes a problem, put a `Clipboard` port behind the session.

- [ ] **Step 5: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add threatmodeller threatmodellerTests
git commit -m "feat: undo, redo and the clipboard on the session

The pasteboard lives in the delivery mechanism, because the core must not
know one exists, and the payload is a string so any other application can
read it. Cut is copy then delete, and the delete is what comes back."
```

---

### Task 7: Menu commands and keys

**Files:**
- Create: `threatmodeller/ThreatModelCommands.swift`
- Modify: `threatmodeller/threatmodellerApp.swift`, `ContentView.swift`, `canvas/CanvasView.swift`, `canvas/CanvasState.swift`

**Interfaces:**
- Produces: `FocusedValues.threatModelSession`, `.threatModelCanvas`; `ThreatModelCommands`; `CanvasState.selectAll(componentIds:zoneIds:)`.

Spec §9's keyboard parity, and which of it this task adds:

| Key | Command | Status |
|---|---|---|
| ⌘Z / ⇧⌘Z | Undo / Redo | this task, replacing the document's own pair |
| ⌘C / ⌘X / ⌘V / ⌘D | Copy / Cut / Paste / Duplicate | this task |
| ⌘A | Select all | this task |
| ⌫ | Delete | already on the canvas |
| ⎋ | Cancel or deselect | already on the canvas |
| ← ↑ → ↓ | Nudge 10 points | this task |
| ⇧ + arrow | Nudge 1 point | this task |
| shift-click | Add or remove from the selection | already on the canvas |
| double-click a palette row | Add | already on the palette |
| double-click a link | Edit its label | out of scope; the carry-forward records it |

- [ ] **Step 1: Let the menu reach the focused document**

Add to `threatmodeller/ThreatModelCommands.swift`:

```swift
import SwiftUI
import ThreatModelKit

/// The menu has to act on whichever document is in front. SwiftUI's focused
/// values carry that; a global would be wrong the moment a second window opens.
struct ThreatModelSessionKey: FocusedValueKey {
    typealias Value = ThreatModelSession
}

struct ThreatModelCanvasKey: FocusedValueKey {
    typealias Value = CanvasState
}

extension FocusedValues {
    var threatModelSession: ThreatModelSession? {
        get { self[ThreatModelSessionKey.self] }
        set { self[ThreatModelSessionKey.self] = newValue }
    }

    var threatModelCanvas: CanvasState? {
        get { self[ThreatModelCanvasKey.self] }
        set { self[ThreatModelCanvasKey.self] = newValue }
    }
}

/// Everything the toolbar and the canvas do, with a menu item and a key.
///
/// Undo and redo **replace** the document's own pair rather than sitting beside
/// them: `DocumentGroup` installs `NSUndoManager`'s, and two undo stacks that
/// disagree is worse than one.
struct ThreatModelCommands: Commands {
    @FocusedValue(\.threatModelSession) private var session
    @FocusedValue(\.threatModelCanvas) private var canvas

    var body: some Commands {
        CommandGroup(replacing: .undoRedo) {
            Button("Undo") { session?.undo() }
                .keyboardShortcut("z", modifiers: .command)
                .disabled(session?.canUndo != true)

            Button("Redo") { session?.redo() }
                .keyboardShortcut("z", modifiers: [.command, .shift])
                .disabled(session?.canRedo != true)
        }

        CommandGroup(replacing: .pasteboard) {
            Button("Cut") { withSelection { session?.cutSelection(componentIds: $0, zoneIds: $1) } }
                .keyboardShortcut("x", modifiers: .command)
                .disabled(hasSelection == false)

            Button("Copy") { withSelection { session?.copySelection(componentIds: $0, zoneIds: $1) } }
                .keyboardShortcut("c", modifiers: .command)
                .disabled(hasSelection == false)

            Button("Paste") {
                guard let session, let canvas else { return }
                let pasted = session.paste()
                canvas.selectAll(componentIds: pasted.componentIds, zoneIds: pasted.zoneIds)
            }
            .keyboardShortcut("v", modifiers: .command)

            Button("Duplicate") {
                guard let session, let canvas else { return }
                withSelection { componentIds, zoneIds in
                    let made = session.duplicate(componentIds: componentIds, zoneIds: zoneIds)
                    canvas.selectAll(componentIds: made.componentIds, zoneIds: made.zoneIds)
                }
            }
            .keyboardShortcut("d", modifiers: .command)
            .disabled(hasSelection == false)

            Divider()

            Button("Select All") {
                guard let session, let canvas else { return }
                canvas.selectAll(
                    componentIds: session.canvas.components.map(\.id),
                    zoneIds: []
                )
            }
            .keyboardShortcut("a", modifiers: .command)
        }
    }

    private var hasSelection: Bool {
        (canvas?.selectedComponentIds.isEmpty == false) || (canvas?.selectedZoneIds.isEmpty == false)
    }

    private func withSelection(_ act: (_ componentIds: [String], _ zoneIds: [String]) -> Void) {
        guard let canvas else { return }
        act(Array(canvas.selectedComponentIds), Array(canvas.selectedZoneIds))
    }
}
```

WARNING: `CommandGroup(replacing: .pasteboard)` removes the standard Cut/Copy/Paste items everywhere, including in a text field. If the zone name field stops accepting ⌘V, use `CommandGroup(after: .pasteboard)` and give the four items different keys, or scope them with `CommandMenu("Diagram")`. Try the replacement first; a diagram application whose ⌘C copies the diagram is what a user expects.

- [ ] **Step 2: Publish the focused values, and install the commands**

In `ModelView`, on the outermost `VStack`:

```swift
        .focusedSceneValue(\.threatModelSession, session)
        .focusedSceneValue(\.threatModelCanvas, canvas)
```

In `threatmodellerApp.swift`:

```swift
        DocumentGroup(newDocument: ThreatModelDocument()) { file in
            ContentView(document: file.document)
        }
        .defaultSize(width: 1400, height: 900)
        .commands { ThreatModelCommands() }
```

- [ ] **Step 3: Add select-all and the arrow nudge**

Add to `CanvasState`:

```swift
    /// Selects exactly what is named. Used by Select All and by what a paste
    /// just made, so the user can move it straight away.
    func selectAll(componentIds: [String], zoneIds: [String]) {
        selectedComponentIds = Set(componentIds)
        selectedZoneIds = Set(zoneIds)
        selectedConnectionIds = []
    }
```

Add to `CanvasGestures`:

```swift
    /// Spec section 9: an arrow moves the selection 10 points, and shift-arrow
    /// moves it 1. The small step is for lining things up; the large one is for
    /// getting somewhere.
    static let nudgeStep = 10.0
    static let fineNudgeStep = 1.0

    func nudge(dx: Double, dy: Double) {
        let moves = session.canvas.components
            .filter { canvas.isSelected(componentId: $0.id) }
            .map { ComponentMove(componentId: $0.id, x: $0.x + dx, y: $0.y + dy) }
        guard moves.isEmpty == false else { return }
        session.move(moves)
    }
```

Add to `CanvasView.body`, beside the existing key presses:

```swift
        .onKeyPress(keys: [.leftArrow, .rightArrow, .upArrow, .downArrow]) { press in
            let step = press.modifiers.contains(.shift)
                ? CanvasGestures.fineNudgeStep
                : CanvasGestures.nudgeStep
            switch press.key {
            case .leftArrow: gestures.nudge(dx: -step, dy: 0)
            case .rightArrow: gestures.nudge(dx: step, dy: 0)
            case .upArrow: gestures.nudge(dx: 0, dy: -step)
            case .downArrow: gestures.nudge(dx: 0, dy: step)
            default: return .ignored
            }
            return .handled
        }
```

- [ ] **Step 4: Build, run the suites, and look at it**

```bash
cd /Users/craigjbass/Projects/threat-modeller
osascript -e 'tell application "threatmodeller" to quit' 2>/dev/null
defaults delete uk.craigbass.threatmodeller 2>/dev/null
xcodebuild -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' test 2>&1 | grep -E 'error:|Failing tests|\*\* TEST' -A3 | head -8
```

Expected: PASS.

Then open the app and check by eye: ⌘Z takes back the last change and the Edit menu dims when there is nothing to take back; ⌘C then ⌘V puts a copy beside the original and selects it; ⌘D duplicates; ⌘A selects everything; an arrow moves the selection 10 points and shift-arrow moves it 1; ⌘V still works inside the zone name field.

- [ ] **Step 5: Commit**

```bash
cd /Users/craigjbass/Projects/threat-modeller
git add threatmodeller
git commit -m "feat: give every command a menu item and a key

Undo and redo replace the document's own pair rather than sitting beside
them. Copy, cut, paste, duplicate and select all act on whichever document is
in front, through SwiftUI's focused values rather than a global. An arrow
moves the selection 10 points and shift-arrow moves it 1."
```

---

### Task 8: The user interface journey

**Files:**
- Modify: `threatmodellerUITests/threatmodellerUITests.swift`

- [ ] **Step 1: Take a change back**

At the end of the journey:

```swift
        // Take the last change back, and put it in again.
        mark("taking a change back")
        let zoneThreat = window.staticTexts["Lateral Movement"].firstMatch
        XCTAssertTrue(zoneThreat.exists, "The zone threat was not there to take back.")

        app.typeKey("z", modifierFlags: .command)

        let gone = XCTNSPredicateExpectation(
            predicate: NSPredicate(format: "exists == false"),
            object: zoneThreat
        )
        XCTAssertEqual(
            XCTWaiter().wait(for: [gone], timeout: 10),
            .completed,
            "Undo did not take the zone back out."
        )

        app.typeKey("z", modifierFlags: [.command, .shift])
        XCTAssertTrue(
            window.staticTexts["Lateral Movement"].firstMatch.waitForExistence(timeout: 10),
            "Redo did not put the zone back."
        )
        mark("change taken back and put in again")
```

WARNING: the last change before this point is switching the pathway mitigations on, not drawing the zone. Undo will take that back first. Put this block immediately after the zone assertions and before the control tick and the mitigation switch, or expect the mitigation change to be what comes back out. Read the journey and place it where the assertion is true.

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
git commit -m "test: walk the journey through an undo and a redo"
```

---

## Milestone complete

- [ ] `swift test` from `ThreatModelKit/` is green and runs in under 30 seconds.
- [ ] `xcodebuild ... test` is green, including the user interface suite.
- [ ] The catalogue tag is still `v1.0.1`.
- [ ] One use case is one undo step, and a refused change is not a step.
- [ ] Opening a document clears the history.
- [ ] A copied selection pastes into a different model with fresh identifiers.
- [ ] A copied link with one end missing does not come along.
- [ ] A paste comes back out in one undo.
- [ ] Duplicating leaves the clipboard alone.
- [ ] ⌘Z, ⇧⌘Z, ⌘C, ⌘X, ⌘V, ⌘D and ⌘A all work, and the Edit menu dims what is not available.
- [ ] An arrow moves the selection 10 points; shift-arrow moves it 1.
- [ ] ⌘V still pastes text into the zone name field.

Then write `docs/superpowers/specs/MILESTONE-7-CARRY-FORWARD.md` and start the Milestone 7 plan: custom technologies and external actors.

New and deferred from this milestone: `LabelConnection` is still unwritten, so spec §9's "double-click a connection to edit its label" is the one line of keyboard parity not met; the session's clipboard tests use the real system pasteboard and change what the person running them has copied; and the history is a hundred steps of whole-model snapshots per document, which is memory nothing has measured.
