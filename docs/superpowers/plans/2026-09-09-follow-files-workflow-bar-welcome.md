# Follow the files, show the workflow, open on a welcome window — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The project window redraws when its source files change on disk, the project workflow gets large buttons in the window, and the application opens on a welcome window rather than on the file open panel.

**Architecture:** A new read-only use case answers a fingerprint of the project source files. An application-layer watcher reports that something under the project directory changed; `ProjectSession` then compares fingerprints and either reloads or asks. The workflow buttons are a new view above the three columns. A new welcome scene is declared first in the `App` body, and recent project roots are stored as app-scoped bookmarks.

**Tech Stack:** Swift 6, SwiftUI, AppKit, `FSEvents`, Swift Testing (`import Testing`), Xcode project `threatmodeller.xcodeproj`, local package `ThreatModelKit`.

**Spec:** `docs/superpowers/specs/2026-09-09-follow-files-workflow-bar-welcome-design.md`

## Global Constraints

- Swift 6 language mode. `ProjectSession`, `ThreatModelSession` and every view are `@MainActor`.
- Clean architecture. A use case names a gateway port, never a concrete type. Watching and bookmarks hold no business rule, so they stay in `threatmodeller/` and never enter `ThreatModelKit`.
- A use case added to `UseCaseFactory` does not compile until `Dependencies` and `TestDependencies` both vend it.
- Tests use Swift Testing: `@Test func name() { #expect(...) }`.
- Package tests: `cd ThreatModelKit && swift test`.
- Application tests: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`.
- A run of `xcodebuild test` that prints nothing for two minutes is the `testmanagerd` fault. Recover with `pkill -f 'Developer/usr/bin/xcodebuild'; pkill -x threatmodeller; kill -9 $(pgrep -x testmanagerd)`. Never `pkill` a runner mid-run by choice.
- Prose in code comments follows the repository style: short sentences, active voice, present tense, name the actor.
- The application is sandboxed. `threatmodeller.entitlements` already grants `com.apple.security.files.user-selected.read-write` and `com.apple.security.files.bookmarks.app-scope`. Do not add an entitlement.

---

### Task 1: The project fingerprint use case

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/ReadProjectFingerprint.swift`
- Create: `ThreatModelKit/Tests/UnitTests/ReadProjectFingerprintTests.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`
- Modify: `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`
- Modify: `threatmodeller/Dependencies.swift`

**Interfaces:**
- Consumes: `ProjectSourceGateway` (`discover(root:)`, `read(path:)`, `exists(path:)`), `ProjectLayout`, `ProjectSystem`, `ProjectError`.
- Produces: `ReadProjectFingerprintUseCase`, `ReadProjectFingerprintRequest(root: String)`, `ReadProjectFingerprintResponse.read(fingerprint: [String: Int])`, `.notAProject(reason: String)`, and `UseCaseFactory.readProjectFingerprint() -> ReadProjectFingerprintUseCase`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/UnitTests/ReadProjectFingerprintTests.swift`:

```swift
import Testing
import ThreatModelKit
import TestSupport

/// The fingerprint is what tells the application that a file under the project
/// changed since it last read one.
struct ReadProjectFingerprintTests {
    private let payments = """
    system "Payments" {
      component "api" { technology = "aws-ec2" }
    }
    """

    private func aProject() -> InMemoryProject {
        let project = InMemoryProject(root: "/work")
        project.put(payments, at: "/work/threatmodel/payments.arch")
        project.put("system \"Reporting\" { component \"r\" { technology = \"aws-rds\" } }",
                    at: "/work/threatmodel/reporting.arch")
        return project
    }

    private func read(_ project: InMemoryProject) -> ReadProjectFingerprintResponse {
        ReadProjectFingerprint(projects: project).execute(
            ReadProjectFingerprintRequest(root: "/work")
        )
    }

    @Test func namesEveryArchitectureFile() {
        guard case .read(let fingerprint) = read(aProject()) else {
            Issue.record("the project was not read")
            return
        }

        #expect(fingerprint.keys.sorted() == [
            "/work/threatmodel/payments.arch",
            "/work/threatmodel/reporting.arch"
        ])
    }

    @Test func namesAControlsFileThatExists() {
        let project = aProject()
        project.put("system \"Payments\" {}", at: "/work/threatmodel/payments.controls")

        guard case .read(let fingerprint) = read(project) else {
            Issue.record("the project was not read")
            return
        }

        #expect(fingerprint["/work/threatmodel/payments.controls"] != nil)
    }

    @Test func answersTheSameFingerprintForTheSameText() {
        let project = aProject()

        guard case .read(let first) = read(project), case .read(let second) = read(project) else {
            Issue.record("the project was not read")
            return
        }

        #expect(first == second)
    }

    @Test func answersADifferentFingerprintForChangedText() {
        let project = aProject()
        guard case .read(let before) = read(project) else {
            Issue.record("the project was not read")
            return
        }

        project.put(payments + "\n// changed\n", at: "/work/threatmodel/payments.arch")

        guard case .read(let after) = read(project) else {
            Issue.record("the project was not read")
            return
        }
        #expect(before != after)
    }

    @Test func refusesARootThatIsNotAProject() {
        let response = ReadProjectFingerprint(projects: InMemoryProject(root: "/work")).execute(
            ReadProjectFingerprintRequest(root: "/elsewhere")
        )

        #expect(response == .notAProject(reason: "/elsewhere is not a directory"))
    }
}
```

- [ ] **Step 2: Run the test and watch it fail**

Run: `cd ThreatModelKit && swift test --filter ReadProjectFingerprintTests`
Expected: FAIL — `cannot find 'ReadProjectFingerprint' in scope`.

- [ ] **Step 3: Write the use case**

Create `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/ReadProjectFingerprint.swift`:

```swift
public protocol ReadProjectFingerprintUseCase {
    func execute(_ request: ReadProjectFingerprintRequest) -> ReadProjectFingerprintResponse
}

public struct ReadProjectFingerprintRequest: Equatable, Sendable {
    public let root: String
    public init(root: String) { self.root = root }
}

public enum ReadProjectFingerprintResponse: Equatable, Sendable {
    /// One number per file, by path. Two reads of the same text answer the
    /// same number inside one run of the application.
    case read(fingerprint: [String: Int])
    case notAProject(reason: String)
}

/// Answers a number per source file, so a caller can tell whether a file
/// changed since it last read one.
///
/// The number is `String.hashValue`. Swift seeds that hash once per process,
/// so it is stable while the application runs and means nothing after it
/// stops. Nothing writes it to a file.
public struct ReadProjectFingerprint: ReadProjectFingerprintUseCase {
    private let projects: ProjectSourceGateway

    public init(projects: ProjectSourceGateway) {
        self.projects = projects
    }

    public func execute(_ request: ReadProjectFingerprintRequest) -> ReadProjectFingerprintResponse {
        do {
            let layout = try projects.discover(root: request.root)
            var fingerprint: [String: Int] = [:]

            for system in layout.systems {
                for path in [system.architecturePath, system.controlsPath] {
                    guard projects.exists(path: path) else { continue }
                    fingerprint[path] = try projects.read(path: path).hashValue
                }
            }
            return .read(fingerprint: fingerprint)
        } catch ProjectError.notADirectory(let path) {
            return .notAProject(reason: "\(path) is not a directory")
        } catch {
            return .notAProject(reason: String(describing: error))
        }
    }
}
```

- [ ] **Step 4: Add the factory method to the protocol and both roots**

In `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`, under `func openProject() -> OpenProjectUseCase`, add:

```swift
    func readProjectFingerprint() -> ReadProjectFingerprintUseCase
```

In `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`, beside `openProject()`, add:

```swift
    public func readProjectFingerprint() -> ReadProjectFingerprintUseCase {
        ReadProjectFingerprint(projects: projects)
    }
```

In `threatmodeller/Dependencies.swift`, beside `openProject()`, add:

```swift
    func readProjectFingerprint() -> ReadProjectFingerprintUseCase {
        ReadProjectFingerprint(projects: projects)
    }
```

- [ ] **Step 5: Run the tests and watch them pass**

Run: `cd ThreatModelKit && swift test`
Expected: PASS, with the five new tests among them.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/ReadProjectFingerprint.swift \
        ThreatModelKit/Tests/UnitTests/ReadProjectFingerprintTests.swift \
        ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift \
        ThreatModelKit/Sources/TestSupport/TestDependencies.swift \
        threatmodeller/Dependencies.swift
git commit -m "feat: answer a fingerprint of the project source files"
```

---

### Task 2: The session counts its revisions

**Files:**
- Modify: `threatmodeller/ThreatModelSession.swift:632` (the `refresh()` method) and the stored properties above it
- Test: `threatmodellerTests/threatmodellerTests.swift`

**Interfaces:**
- Produces: `ThreatModelSession.revision: Int`, readable, raised by one on every `refresh()`.

- [ ] **Step 1: Write the failing test**

Append to `threatmodellerTests/threatmodellerTests.swift`, inside the existing test struct or as a new `@MainActor struct` at the end of the file:

```swift
@MainActor
struct ThreatModelSessionRevisionTests {
    @Test func startsAtOneAndRisesWithEachChange() {
        let session = ThreatModelSession(useCases: TestDependencies())
        let first = session.revision

        session.addAtDefaultPoint(technologyId: "aws-ec2")

        #expect(first == 1)
        #expect(session.revision == 2)
    }

    @Test func doesNotRiseWhenNothingIsAsked() {
        let session = ThreatModelSession(useCases: TestDependencies())

        _ = session.canvas
        _ = session.threats

        #expect(session.revision == 1)
    }
}
```

`TestDependencies` needs `import TestSupport`, which the file already has. If it does not, add `import TestSupport` and `import ThreatModelKit` at the top.

- [ ] **Step 2: Run the test and watch it fail**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ThreatModelSessionRevisionTests`
Expected: FAIL — `value of type 'ThreatModelSession' has no member 'revision'`.

- [ ] **Step 3: Add the counter**

In `threatmodeller/ThreatModelSession.swift`, beside the other stored properties, add:

```swift
    /// How many times this session has read the model back. It starts at 1,
    /// and every change raises it. `ProjectSession` compares it with the
    /// number it recorded to answer whether anything on screen is unsaved.
    private(set) var revision = 0
```

Then raise it as the first line of `refresh()`:

```swift
    private func refresh() {
        revision += 1
        palette = useCases.listTechnologies().execute(ListTechnologiesRequest()).providers
        ...
    }
```

- [ ] **Step 4: Run the test and watch it pass**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ThreatModelSessionRevisionTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add threatmodeller/ThreatModelSession.swift threatmodellerTests/threatmodellerTests.swift
git commit -m "feat: count the revisions of a drawn model"
```

---

### Task 3: The project session follows its files

**Files:**
- Create: `threatmodeller/project/ProjectWatching.swift`
- Modify: `threatmodeller/project/ProjectSession.swift`
- Modify: `threatmodellerTests/ProjectSessionTests.swift`

**Interfaces:**
- Consumes: `ReadProjectFingerprintUseCase` from Task 1, `ThreatModelSession.revision` from Task 2.
- Produces: `protocol ProjectWatching`, `ProjectSession.init(useCases:watcher:)`, `ProjectSession.hasUnsavedChanges: Bool`, `ProjectSession.hasFilesChangedOnDisk: Bool`, `ProjectSession.reloadFromDisk()`, `ProjectSession.keepMine()`, `ProjectSession.open(root:preferring:)`.

- [ ] **Step 1: Write the protocol and a fake for the tests**

Create `threatmodeller/project/ProjectWatching.swift` with the protocol only. The real implementation is Task 4.

```swift
/// Reports that a file under a project directory changed.
///
/// It holds no rule and answers no question: it says only that something
/// changed, and `ProjectSession` decides what that means.
@MainActor
protocol ProjectWatching: AnyObject {
    func watch(directory: String, onChange: @escaping () -> Void)
    func stop()
}
```

- [ ] **Step 2: Write the failing tests**

In `threatmodellerTests/ProjectSessionTests.swift`, add the fake above the test struct:

```swift
/// A watcher a test drives by hand.
@MainActor
final class FakeProjectWatcher: ProjectWatching {
    private(set) var watchedDirectory: String?
    private var onChange: (() -> Void)?

    func watch(directory: String, onChange: @escaping () -> Void) {
        watchedDirectory = directory
        self.onChange = onChange
    }

    func stop() {
        watchedDirectory = nil
        onChange = nil
    }

    /// What the real watcher calls when a file changes.
    func fire() { onChange?() }
}
```

Change the existing `aProject()` helper so every test gets a watcher, and keep the two-value shape the other tests already use by adding a third:

```swift
    private func aProject() -> (ProjectSession, TestDependencies) {
        let (session, useCases, _) = aWatchedProject()
        return (session, useCases)
    }

    private func aWatchedProject() -> (ProjectSession, TestDependencies, FakeProjectWatcher) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        useCases.project.put("system \"Reporting\" { component \"r\" { technology = \"aws-rds\" } }",
                             at: "/work/threatmodel/reporting.arch")
        let watcher = FakeProjectWatcher()
        return (ProjectSession(useCases: useCases, watcher: watcher), useCases, watcher)
    }
```

Then add the tests:

```swift
    @Test func watchesTheProjectDirectory() {
        let (session, _, watcher) = aWatchedProject()

        session.open(root: "/work")

        #expect(watcher.watchedDirectory == "/work/threatmodel")
    }

    @Test func doesNothingWhenTheFilesDidNotChange() {
        let (session, _, watcher) = aWatchedProject()
        session.open(root: "/work")
        let drawn = session.model

        watcher.fire()

        #expect(session.model === drawn)
        #expect(session.hasFilesChangedOnDisk == false)
    }

    @Test func redrawsWhenTheFilesChangedAndNothingIsUnsaved() {
        let (session, useCases, watcher) = aWatchedProject()
        session.open(root: "/work")
        useCases.project.put(
            """
            system "Payments" {
              component "api" { technology = "aws-ec2" }
              component "db"  { technology = "aws-rds" }
            }
            """,
            at: "/work/threatmodel/payments.arch"
        )

        watcher.fire()

        #expect(session.model?.canvas.components.map(\.id) == ["api", "db"])
        #expect(session.hasFilesChangedOnDisk == false)
    }

    @Test func asksWhenTheFilesChangedAndSomethingIsUnsaved() {
        let (session, useCases, watcher) = aWatchedProject()
        session.open(root: "/work")
        session.model?.addAtDefaultPoint(technologyId: "aws-rds")
        let drawn = session.model
        useCases.project.put("system \"Payments\" { component \"other\" { technology = \"aws-rds\" } }",
                             at: "/work/threatmodel/payments.arch")

        watcher.fire()

        #expect(session.hasUnsavedChanges)
        #expect(session.hasFilesChangedOnDisk)
        #expect(session.model === drawn)
    }

    @Test func reloadsWhenTheUserAsksForIt() {
        let (session, useCases, watcher) = aWatchedProject()
        session.open(root: "/work")
        session.model?.addAtDefaultPoint(technologyId: "aws-rds")
        useCases.project.put("system \"Payments\" { component \"other\" { technology = \"aws-rds\" } }",
                             at: "/work/threatmodel/payments.arch")
        watcher.fire()

        session.reloadFromDisk()

        #expect(session.model?.canvas.components.map(\.id) == ["other"])
        #expect(session.hasFilesChangedOnDisk == false)
    }

    @Test func keepsWhatIsOnScreenWhenTheUserAsksForThat() {
        let (session, useCases, watcher) = aWatchedProject()
        session.open(root: "/work")
        session.model?.addAtDefaultPoint(technologyId: "aws-rds")
        let drawn = session.model
        useCases.project.put("system \"Payments\" { component \"other\" { technology = \"aws-rds\" } }",
                             at: "/work/threatmodel/payments.arch")
        watcher.fire()

        session.keepMine()

        #expect(session.hasFilesChangedOnDisk == false)
        #expect(session.model === drawn)
    }

    @Test func doesNotRedrawAfterItsOwnSave() {
        let (session, _, watcher) = aWatchedProject()
        session.open(root: "/work")
        session.model?.addAtDefaultPoint(technologyId: "aws-rds")
        session.save()
        let drawn = session.model

        watcher.fire()

        #expect(session.model === drawn)
        #expect(session.hasFilesChangedOnDisk == false)
        #expect(session.hasUnsavedChanges == false)
    }

    @Test func aReloadKeepsTheChosenSystem() {
        let (session, useCases, watcher) = aWatchedProject()
        session.open(root: "/work")
        session.choose("reporting")
        useCases.project.put("system \"Reporting\" { component \"r2\" { technology = \"aws-rds\" } }",
                             at: "/work/threatmodel/reporting.arch")

        watcher.fire()

        #expect(session.chosenSystem == "reporting")
        #expect(session.model?.canvas.components.map(\.id) == ["r2"])
    }
```

- [ ] **Step 3: Run the tests and watch them fail**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ProjectSessionTests`
Expected: FAIL — `extra argument 'watcher' in call`.

- [ ] **Step 4: Change the project session**

In `threatmodeller/project/ProjectSession.swift`:

Add the stored state beside the existing properties:

```swift
    private let watcher: ProjectWatching
    /// The numbers the last read or write of the source files answered.
    private var fingerprint: [String: Int] = [:]
    /// The revision the drawn model had when this session last read or wrote
    /// the files.
    private var savedRevision = 0
    /// True when a file changed on disk and this session did not reload,
    /// because something on screen is unsaved.
    private(set) var hasFilesChangedOnDisk = false
```

Change the initialiser:

```swift
    init(useCases: UseCaseFactory, watcher: ProjectWatching = FSEventsProjectWatcher()) {
        self.useCases = useCases
        self.watcher = watcher
    }
```

Add the two questions and the two answers:

```swift
    /// True when the drawn model holds a change no file holds.
    var hasUnsavedChanges: Bool {
        guard let model else { return false }
        return model.revision > savedRevision
    }

    /// Reads the files again and draws them. It keeps the chosen system when
    /// the project still holds it.
    func reloadFromDisk() {
        guard let root else { return }
        hasFilesChangedOnDisk = false
        open(root: root, preferring: chosenSystem)
    }

    /// Leaves what is on screen alone. The notice returns when a file changes
    /// again.
    func keepMine() {
        hasFilesChangedOnDisk = false
        fingerprint = currentFingerprint()
    }

    /// What the watcher calls. A change this application wrote itself answers
    /// the same fingerprint, so nothing happens.
    private func filesChanged() {
        let current = currentFingerprint()
        guard current != fingerprint else { return }

        if hasUnsavedChanges {
            hasFilesChangedOnDisk = true
        } else {
            reloadFromDisk()
        }
    }

    private func currentFingerprint() -> [String: Int] {
        guard let root else { return [:] }
        switch useCases.readProjectFingerprint().execute(
            ReadProjectFingerprintRequest(root: root)
        ) {
        case .read(let fingerprint): return fingerprint
        case .notAProject: return [:]
        }
    }
```

Change `open` so it takes the system to prefer, starts the watcher, and records
the fingerprint:

```swift
    func open(root: String, preferring wanted: String? = nil) {
        switch useCases.openProject().execute(OpenProjectRequest(root: root)) {
        case .opened(let systems, let directory):
            self.root = root
            self.directory = directory
            self.systems = systems
            errorMessage = systems.isEmpty
                ? "\(directory) holds no .arch files. Start from an example, or write one."
                : nil
            fingerprint = currentFingerprint()
            watcher.stop()
            watcher.watch(directory: directory) { [weak self] in self?.filesChanged() }
            let chosen = systems.contains(wanted ?? "") ? wanted : systems.first
            if let chosen { choose(chosen) }
        case .notAProject(let reason):
            self.root = nil
            systems = []
            model = nil
            watcher.stop()
            errorMessage = "That is not a project: \(reason)"
        }
    }
```

Record the revision at the end of `choose(_:)`. In the `.opened` branch, after
`model = ThreatModelSession(useCases: useCases)`, add:

```swift
            savedRevision = model?.revision ?? 0
            hasFilesChangedOnDisk = false
```

In `save()`, in the `.saved` branch, after `saveAnswers(root:systemName:)`, add:

```swift
            savedRevision = model?.revision ?? 0
            fingerprint = currentFingerprint()
```

- [ ] **Step 5: Run the tests and watch them pass**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ProjectSessionTests`
Expected: FAIL at compile with `cannot find 'FSEventsProjectWatcher' in scope`. Task 4 writes it. Do Task 4, then run this again and expect PASS.

- [ ] **Step 6: Commit after Task 4 passes**

Commit Task 3 and Task 4 together, because neither compiles without the other.

---

### Task 4: The watcher that reads the file system

**Files:**
- Modify: `threatmodeller/project/ProjectWatching.swift`

**Interfaces:**
- Consumes: `ProjectWatching` from Task 3.
- Produces: `final class FSEventsProjectWatcher: ProjectWatching`.

- [ ] **Step 1: Write the implementation**

Append to `threatmodeller/project/ProjectWatching.swift`:

```swift
import CoreServices
import Foundation

/// Watches a directory with `FSEvents`.
///
/// `FSEvents` reports a write into a file that already exists, which a
/// `DispatchSource` on the directory does not. A text editor that saves in
/// place is the common case, so this application needs the file events.
@MainActor
final class FSEventsProjectWatcher: ProjectWatching {
    private var stream: FSEventStreamRef?
    private var onChange: (() -> Void)?

    /// How long `FSEvents` gathers events before it reports them. A short
    /// wait joins the several writes one save makes into one report.
    private static let latency = 0.3

    func watch(directory: String, onChange: @escaping () -> Void) {
        stop()
        self.onChange = onChange

        var context = FSEventStreamContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )

        let callback: FSEventStreamCallback = { _, info, _, _, _, _ in
            guard let info else { return }
            let watcher = Unmanaged<FSEventsProjectWatcher>.fromOpaque(info)
                .takeUnretainedValue()
            // The stream reports on the main queue, and the session it calls
            // is main-actor isolated.
            MainActor.assumeIsolated { watcher.report() }
        }

        guard let stream = FSEventStreamCreate(
            nil,
            callback,
            &context,
            [directory] as CFArray,
            FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
            Self.latency,
            UInt32(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer)
        ) else { return }

        self.stream = stream
        FSEventStreamSetDispatchQueue(stream, DispatchQueue.main)
        FSEventStreamStart(stream)
    }

    func stop() {
        guard let stream else { return }
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        FSEventStreamRelease(stream)
        self.stream = nil
        onChange = nil
    }

    private func report() {
        onChange?()
    }

    deinit {
        guard let stream else { return }
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        FSEventStreamRelease(stream)
    }
}
```

- [ ] **Step 2: Run the tests and watch them pass**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ProjectSessionTests`
Expected: PASS, with the eight new session tests among them.

- [ ] **Step 3: Run every test**

Run: `cd ThreatModelKit && swift test` then `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add threatmodeller/project/ProjectWatching.swift threatmodeller/project/ProjectSession.swift \
        threatmodellerTests/ProjectSessionTests.swift
git commit -m "feat: redraw the project when its source files change"
```

---

### Task 5: The project window says what the last action did

**Files:**
- Modify: `threatmodeller/project/ProjectSession.swift`
- Modify: `threatmodellerTests/ProjectSessionTests.swift`

**Interfaces:**
- Produces: `ProjectSession.lastActionMessage: String?`.

- [ ] **Step 1: Write the failing tests**

Add to `threatmodellerTests/ProjectSessionTests.swift`:

```swift
    @Test func saysWhatTheSaveDid() {
        let (session, _) = aProject()
        session.open(root: "/work")

        session.save()

        #expect(session.lastActionMessage?.hasPrefix("Saved") == true)
    }

    @Test func saysWhereTheReportWent() {
        let (session, _) = aProject()
        session.open(root: "/work")

        session.compileReport()

        #expect(session.lastActionMessage == "Report: \(session.reportPath ?? "")")
    }

    @Test func clearsTheMessageWhenAnotherSystemIsPicked() {
        let (session, _) = aProject()
        session.open(root: "/work")
        session.compileReport()

        session.choose("reporting")

        #expect(session.lastActionMessage == nil)
    }
```

- [ ] **Step 2: Run the tests and watch them fail**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ProjectSessionTests`
Expected: FAIL — `value of type 'ProjectSession' has no member 'lastActionMessage'`.

- [ ] **Step 3: Add the message**

In `threatmodeller/project/ProjectSession.swift`, add the property:

```swift
    /// What the last save or compile did, for the bar above the diagram.
    private(set) var lastActionMessage: String?
```

In `choose(_:)`, in every branch that sets `chosenSystem`, add `lastActionMessage = nil`.

In `saveAnswers(root:systemName:)`, in the `.saved` branch, after
`unansweredThreats = unanswered`, add:

```swift
            lastActionMessage = unanswered == 0
                ? "Saved."
                : "Saved. \(unanswered) threats have no answer."
```

In `compileReport()`, in the `.written` branch, after `reportPath = path`, add:

```swift
            lastActionMessage = "Report: \(path)"
```

- [ ] **Step 4: Run the tests and watch them pass**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ProjectSessionTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add threatmodeller/project/ProjectSession.swift threatmodellerTests/ProjectSessionTests.swift
git commit -m "feat: say what the last project action did"
```

---

### Task 6: The workflow bar and the changed-on-disk notice

**Files:**
- Create: `threatmodeller/project/WorkflowBar.swift`
- Modify: `threatmodeller/project/ProjectWindow.swift`
- Modify: `threatmodellerTests/ViewRenderTests.swift`

**Interfaces:**
- Consumes: `ProjectSession.save()`, `.compileReport()`, `.lastActionMessage`, `.chosenSystem`, `.hasFilesChangedOnDisk`, `.reloadFromDisk()`, `.keepMine()`.
- Produces: `struct WorkflowBar: View` with `init(session: ProjectSession)`.

- [ ] **Step 1: Write the failing render test**

Add to `threatmodellerTests/ViewRenderTests.swift`:

```swift
    @Test func drawsTheWorkflowBar() {
        let useCases = TestDependencies()
        useCases.project.put(
            "system \"Payments\" { component \"api\" { technology = \"aws-ec2\" } }",
            at: "/work/threatmodel/payments.arch"
        )
        let session = ProjectSession(useCases: useCases, watcher: FakeProjectWatcher())
        session.open(root: "/work")

        let image = draw(WorkflowBar(session: session), width: 900, height: 90)

        #expect(image != nil)
        #expect(image.map(hasContent) == true)
    }
```

- [ ] **Step 2: Run the test and watch it fail**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ViewRenderTests`
Expected: FAIL — `cannot find 'WorkflowBar' in scope`.

- [ ] **Step 3: Write the bar**

Create `threatmodeller/project/WorkflowBar.swift`:

```swift
import SwiftUI

/// The two things a user does with a project, as buttons in the window.
///
/// The menu carries the same two commands and the same shortcuts. This bar is
/// what tells a user who never opens a menu that they exist.
struct WorkflowBar: View {
    let session: ProjectSession

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 12) {
                Button {
                    session.save()
                } label: {
                    Label("Save System", systemImage: "square.and.arrow.down")
                        .frame(minWidth: 130)
                }
                .controlSize(.large)
                .keyboardShortcut("s", modifiers: [.command, .option])
                .disabled(session.chosenSystem == nil)
                .accessibilityIdentifier("save-system")

                Button {
                    session.compileReport()
                } label: {
                    Label("Compile Report", systemImage: "doc.text")
                        .frame(minWidth: 150)
                }
                .controlSize(.large)
                .keyboardShortcut("r", modifiers: [.command, .option])
                .disabled(session.chosenSystem == nil)
                .accessibilityIdentifier("compile-report")

                Spacer(minLength: 8)
            }

            if let message = session.lastActionMessage {
                Text(message)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("last-action-message")
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.bar)
        .accessibilityIdentifier("workflow-bar")
    }
}
```

- [ ] **Step 4: Draw the bar and the notice in the window**

In `threatmodeller/project/ProjectWindow.swift`, replace the `chrome` property
with one that holds both strips, and put the bar above them:

```swift
    @ViewBuilder
    private var chrome: some View {
        VStack(spacing: 0) {
            WorkflowBar(session: session)
            filesChangedNotice
            diagnosticsNotice
        }
    }

    /// A file changed on disk while something on screen was unsaved. The user
    /// picks which one wins.
    @ViewBuilder
    private var filesChangedNotice: some View {
        if session.hasFilesChangedOnDisk {
            HStack(spacing: 8) {
                Image(systemName: "arrow.clockwise")
                Text("The files changed on disk. Your unsaved changes are still on screen.")
                    .font(.callout)
                Spacer(minLength: 8)
                Button("Reload") { session.reloadFromDisk() }
                    .accessibilityIdentifier("reload-from-disk")
                Button("Keep Mine") { session.keepMine() }
                    .accessibilityIdentifier("keep-mine")
            }
            .padding(8)
            .background(Color.blue.opacity(0.18))
            .accessibilityIdentifier("files-changed-notice")
        }
    }

    @ViewBuilder
    private var diagnosticsNotice: some View {
        if session.diagnostics.isEmpty == false || session.errorMessage != nil {
            HStack(spacing: 8) {
                Image(systemName: session.hasErrors ? "xmark.octagon.fill" : "exclamationmark.triangle.fill")
                Text(noticeText)
                    .font(.callout)
                Spacer(minLength: 8)
                if session.diagnostics.isEmpty == false {
                    Button("Show") { isShowingDiagnostics = true }
                        .accessibilityIdentifier("show-diagnostics")
                }
                Button("Dismiss") { session.dismissDiagnostics() }
            }
            .padding(8)
            .background(session.hasErrors ? Color.red.opacity(0.2) : Color.yellow.opacity(0.25))
            .accessibilityIdentifier("project-notice")
        }
    }
```

Leave `.safeAreaInset(edge: .top) { chrome }` as it is.

- [ ] **Step 5: Run the tests and watch them pass**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ViewRenderTests`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add threatmodeller/project/WorkflowBar.swift threatmodeller/project/ProjectWindow.swift \
        threatmodellerTests/ViewRenderTests.swift
git commit -m "feat: put the project workflow in the window"
```

---

### Task 7: Recent projects, kept as bookmarks

**Files:**
- Create: `threatmodeller/project/RecentProjects.swift`
- Create: `threatmodellerTests/RecentProjectsTests.swift`

**Interfaces:**
- Produces: `struct RecentProject: Identifiable, Equatable` with `id: String`, `path: String`, `name: String`; `final class RecentProjects` with `init(defaults: UserDefaults = .standard)`, `record(url: URL)`, `list() -> [RecentProject]`, `resolve(_ entry: RecentProject) -> URL?`.

- [ ] **Step 1: Write the failing test**

Create `threatmodellerTests/RecentProjectsTests.swift`:

```swift
import Foundation
import Testing
@testable import threatmodeller

/// The recent list is what lets a user open a project again without the panel.
/// These tests run over a defaults suite made for the test, so nothing they
/// write reaches the application's own defaults.
@MainActor
struct RecentProjectsTests {
    private func aStore(named name: String) -> (RecentProjects, UserDefaults) {
        let defaults = UserDefaults(suiteName: "recent-projects-test-\(name)")!
        defaults.removePersistentDomain(forName: "recent-projects-test-\(name)")
        return (RecentProjects(defaults: defaults), defaults)
    }

    @Test func listsARecordedRoot() {
        let (store, _) = aStore(named: "one")

        store.record(url: URL(fileURLWithPath: NSTemporaryDirectory()))

        #expect(store.list().count == 1)
        #expect(store.list().first?.path == URL(fileURLWithPath: NSTemporaryDirectory()).path)
    }

    @Test func recordsOneRootOnce() {
        let (store, _) = aStore(named: "two")
        let url = URL(fileURLWithPath: NSTemporaryDirectory())

        store.record(url: url)
        store.record(url: url)

        #expect(store.list().count == 1)
    }

    @Test func namesTheLastDirectoryOfThePath() {
        let (store, _) = aStore(named: "three")
        let url = URL(fileURLWithPath: NSTemporaryDirectory())

        store.record(url: url)

        #expect(store.list().first?.name == url.lastPathComponent)
    }

    @Test func keepsTenAtMost() {
        let (store, _) = aStore(named: "four")
        let base = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("recent-projects-test", isDirectory: true)
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)

        for index in 0..<12 {
            let child = base.appendingPathComponent("p\(index)", isDirectory: true)
            try? FileManager.default.createDirectory(at: child, withIntermediateDirectories: true)
            store.record(url: child)
        }

        #expect(store.list().count == 10)
        #expect(store.list().first?.name == "p11")
    }
}
```

- [ ] **Step 2: Run the test and watch it fail**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/RecentProjectsTests`
Expected: FAIL — `cannot find 'RecentProjects' in scope`.

- [ ] **Step 3: Write the store**

Create `threatmodeller/project/RecentProjects.swift`:

```swift
import Foundation

/// One project root the user opened before.
struct RecentProject: Identifiable, Equatable {
    /// The path, which is unique in the list.
    var id: String { path }
    let path: String
    /// The last part of the path, which is what the welcome window shows.
    let name: String
    /// The bookmark that reopens the root without an open panel.
    let bookmark: Data
}

/// Remembers the project roots the user opened.
///
/// The application is sandboxed, so a path alone cannot be opened again after
/// a relaunch. Each entry keeps an app-scoped bookmark, which
/// `threatmodeller.entitlements` grants.
@MainActor
final class RecentProjects {
    private let defaults: UserDefaults
    private static let key = "recentProjects"
    private static let limit = 10

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    /// Puts a root at the top of the list. A root already in the list moves to
    /// the top rather than appearing twice.
    func record(url: URL) {
        guard let bookmark = try? url.bookmarkData(
            options: .withSecurityScope,
            includingResourceValuesForKeys: nil,
            relativeTo: nil
        ) else { return }

        var rows = storedRows().filter { $0["path"] as? String != url.path }
        rows.insert(["path": url.path, "bookmark": bookmark], at: 0)
        defaults.set(Array(rows.prefix(Self.limit)), forKey: Self.key)
    }

    /// Newest first, at most ten.
    func list() -> [RecentProject] {
        storedRows().compactMap { row in
            guard let path = row["path"] as? String,
                  let bookmark = row["bookmark"] as? Data else { return nil }
            return RecentProject(
                path: path,
                name: (path as NSString).lastPathComponent,
                bookmark: bookmark
            )
        }
    }

    /// Answers the root this entry names, or nil when the bookmark no longer
    /// resolves. A stale entry is dropped from the list.
    func resolve(_ entry: RecentProject) -> URL? {
        var isStale = false
        guard let url = try? URL(
            resolvingBookmarkData: entry.bookmark,
            options: .withSecurityScope,
            relativeTo: nil,
            bookmarkDataIsStale: &isStale
        ), isStale == false else {
            forget(path: entry.path)
            return nil
        }
        return url
    }

    private func forget(path: String) {
        defaults.set(storedRows().filter { $0["path"] as? String != path }, forKey: Self.key)
    }

    private func storedRows() -> [[String: Any]] {
        defaults.array(forKey: Self.key) as? [[String: Any]] ?? []
    }
}
```

- [ ] **Step 4: Run the tests and watch them pass**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/RecentProjectsTests`
Expected: PASS.

WARNING: `bookmarkData(options: .withSecurityScope,…)` answers a bookmark only
for a URL the sandbox already grants. A test that records a temporary directory
the test process created is granted it. If a test fails with an empty list,
read the thrown error before changing the test.

- [ ] **Step 5: Commit**

```bash
git add threatmodeller/project/RecentProjects.swift threatmodellerTests/RecentProjectsTests.swift
git commit -m "feat: remember the project roots the user opened"
```

---

### Task 8: The welcome window

**Files:**
- Create: `threatmodeller/WelcomeWindow.swift`
- Modify: `threatmodellerTests/ViewRenderTests.swift`

**Interfaces:**
- Consumes: `RecentProjects` from Task 7, `ViewCatalogueVersionResponse` from `ThreatModelKit`.
- Produces: `struct WelcomeWindow: View` with `init(catalogue:recents:openProject:openRecentProject:)`.

- [ ] **Step 1: Write the failing render test**

Add to `threatmodellerTests/ViewRenderTests.swift`:

```swift
    @Test func drawsTheWelcomeWindow() {
        let defaults = UserDefaults(suiteName: "welcome-render-test")!
        defaults.removePersistentDomain(forName: "welcome-render-test")

        let view = WelcomeWindow(
            catalogue: ViewCatalogueVersionResponse(
                repository: "threat-catalogue",
                tag: "v1.4.2",
                technologyCount: 42
            ),
            recents: RecentProjects(defaults: defaults),
            openProject: {},
            openRecentProject: { _ in }
        )

        let image = draw(view, width: 620, height: 520)

        #expect(image != nil)
        #expect(image.map(hasContent) == true)
    }

    @Test func drawsTheWelcomeWindowWithNoCatalogue() {
        let defaults = UserDefaults(suiteName: "welcome-render-test-empty")!
        defaults.removePersistentDomain(forName: "welcome-render-test-empty")

        let view = WelcomeWindow(
            catalogue: nil,
            recents: RecentProjects(defaults: defaults),
            openProject: {},
            openRecentProject: { _ in }
        )

        let image = draw(view, width: 620, height: 520)

        #expect(image != nil)
        #expect(image.map(hasContent) == true)
    }
```

- [ ] **Step 2: Run the test and watch it fail**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ViewRenderTests`
Expected: FAIL — `cannot find 'WelcomeWindow' in scope`.

- [ ] **Step 3: Write the window**

Create `threatmodeller/WelcomeWindow.swift`:

```swift
import AppKit
import SwiftUI
import ThreatModelKit

/// What the application opens on.
///
/// It offers the two ways in: a project, which is a directory of `.arch`
/// files, and a model file, which is one document. The file open panel is no
/// longer the first thing a user meets.
struct WelcomeWindow: View {
    /// Nil when the catalogue could not be loaded. The window then offers no
    /// route, because neither route would work.
    let catalogue: ViewCatalogueVersionResponse?
    let recents: RecentProjects
    /// Runs the same open panel the File menu runs.
    let openProject: () -> Void
    let openRecentProject: (RecentProject) -> Void

    var body: some View {
        VStack(spacing: 18) {
            header

            if catalogue == nil {
                ContentUnavailableView(
                    "The catalogue could not be loaded",
                    systemImage: "exclamationmark.triangle",
                    description: Text("This application cannot open a model until it loads.")
                )
            } else {
                routes
                Button("New Model File") { NSDocumentController.shared.newDocument(nil) }
                    .accessibilityIdentifier("welcome-new-model")
                recentList
            }
        }
        .padding(28)
        .frame(width: 620, height: 520)
        .accessibilityIdentifier("welcome-window")
    }

    private var header: some View {
        VStack(spacing: 4) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 40))
                .foregroundStyle(.tint)
            Text("Threat Modeller")
                .font(.largeTitle.bold())
            if let catalogue {
                Text("catalogue \(catalogue.tag)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var routes: some View {
        HStack(spacing: 16) {
            route(
                title: "Open Project\u{2026}",
                explanation: "A folder of .arch files, one per system.",
                systemImage: "folder",
                identifier: "welcome-open-project",
                action: openProject
            )
            route(
                title: "Open Model File\u{2026}",
                explanation: "One document you drew in this application.",
                systemImage: "doc",
                identifier: "welcome-open-file",
                action: { NSDocumentController.shared.openDocument(nil) }
            )
        }
    }

    private func route(
        title: String,
        explanation: String,
        systemImage: String,
        identifier: String,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            VStack(spacing: 8) {
                Image(systemName: systemImage)
                    .font(.system(size: 30))
                Text(title)
                    .font(.headline)
                Text(explanation)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .frame(width: 220, height: 140)
            .contentShape(Rectangle())
        }
        .buttonStyle(.bordered)
        .accessibilityIdentifier(identifier)
    }

    @ViewBuilder
    private var recentList: some View {
        let projects = recents.list()
        let files = NSDocumentController.shared.recentDocumentURLs.prefix(5)

        if projects.isEmpty == false || files.isEmpty == false {
            VStack(alignment: .leading, spacing: 4) {
                Text("Recent")
                    .font(.headline)

                List {
                    ForEach(projects) { project in
                        Button {
                            openRecentProject(project)
                        } label: {
                            Label(project.name, systemImage: "folder")
                        }
                        .buttonStyle(.plain)
                    }
                    ForEach(Array(files), id: \.self) { url in
                        Button {
                            NSDocumentController.shared.openDocument(
                                withContentsOf: url,
                                display: true
                            ) { _, _, _ in }
                        } label: {
                            Label(url.lastPathComponent, systemImage: "doc")
                        }
                        .buttonStyle(.plain)
                    }
                }
                .frame(height: 120)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityIdentifier("welcome-recent")
        }
    }
}
```

- [ ] **Step 4: Run the tests and watch them pass**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ViewRenderTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add threatmodeller/WelcomeWindow.swift threatmodellerTests/ViewRenderTests.swift
git commit -m "feat: draw a welcome window with both ways in"
```

---

### Task 9: The application opens on the welcome window

**Files:**
- Modify: `threatmodeller/threatmodellerApp.swift`

**Interfaces:**
- Consumes: `WelcomeWindow` from Task 8, `RecentProjects` from Task 7, `ProjectSession.open(root:preferring:)` from Task 3.

- [ ] **Step 1: Declare the welcome scene first**

In `threatmodeller/threatmodellerApp.swift`, add the identifier and the store:

```swift
    static let welcomeWindowId = "welcome"

    private let recents = RecentProjects()
```

Put this scene at the top of `body`, above `DocumentGroup`:

```swift
        Window("Threat Modeller", id: Self.welcomeWindowId) {
            WelcomeWindow(
                catalogue: catalogue,
                recents: recents,
                openProject: { openProject() },
                openRecentProject: { entry in openRecent(entry) }
            )
        }
        .windowResizability(.contentSize)
```

- [ ] **Step 2: Close the welcome window when a project opens, and open recents**

Add these methods:

```swift
    /// A recent root was chosen. The bookmark grants the sandbox access, so
    /// the panel is not needed.
    private func openRecent(_ entry: RecentProject) {
        guard let project, let url = recents.resolve(entry) else { return }
        guard url.startAccessingSecurityScopedResource() else { return }
        openWindow(id: Self.projectWindowId)
        project.open(root: url.path)
        dismissWindow(id: Self.welcomeWindowId)
    }
```

Change `openProject()` so it records the root and closes the welcome window:

```swift
    private func openProject() {
        guard let project else { return }

        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Open Project"
        guard panel.runModal() == .OK, let url = panel.url else { return }

        recents.record(url: url)
        openWindow(id: Self.projectWindowId)
        project.open(root: url.path)
        dismissWindow(id: Self.welcomeWindowId)
    }
```

Add the environment value beside `openWindow`:

```swift
    @Environment(\.dismissWindow) private var dismissWindow
```

- [ ] **Step 3: Add the menu item that opens it again**

Inside `.commands`, add:

```swift
            CommandGroup(after: .windowList) {
                Button("Welcome") { openWindow(id: Self.welcomeWindowId) }
            }
```

- [ ] **Step 4: Stop the untitled document at launch**

Add the delegate above the `App` struct:

```swift
/// macOS opens an untitled document at launch when the application declares a
/// document type. This application opens on the welcome window instead.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldOpenUntitledFile(_ sender: NSApplication) -> Bool { false }

    /// Clicking the Dock icon with no window open opens the welcome window.
    func applicationShouldHandleReopen(
        _ sender: NSApplication,
        hasVisibleWindows: Bool
    ) -> Bool {
        hasVisibleWindows
    }
}
```

Attach it inside the `App` struct:

```swift
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
```

- [ ] **Step 5: Run every test**

Run: `cd ThreatModelKit && swift test`
Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
Expected: PASS.

- [ ] **Step 6: Run the application and read what it opens on**

Run:

```bash
xcodebuild build -project threatmodeller.xcodeproj -scheme threatmodeller \
  -destination 'platform=macOS' -derivedDataPath /tmp/tm-build
open /tmp/tm-build/Build/Products/Debug/threatmodeller.app
```

Expected: the welcome window appears and no open panel appears.

If an open panel still appears, the scene order was not enough. The delegate in
Step 4 is the fix; check it is attached with `@NSApplicationDelegateAdaptor`
and that `applicationShouldOpenUntitledFile` answers false.

- [ ] **Step 7: Commit**

```bash
git add threatmodeller/threatmodellerApp.swift
git commit -m "feat: open the application on a welcome window"
```

---

### Task 10: Record what changed

**Files:**
- Modify: `docs/superpowers/specs/2026-09-09-follow-files-workflow-bar-welcome-design.md`

- [ ] **Step 1: Write down what the run of the built application showed**

Add a short section at the end of the spec, headed `## 8. What the build showed`,
stating whether the scene order alone stopped the open panel, or whether the
delegate was needed.

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/specs/2026-09-09-follow-files-workflow-bar-welcome-design.md
git commit -m "docs: record what the built application opened on"
```
