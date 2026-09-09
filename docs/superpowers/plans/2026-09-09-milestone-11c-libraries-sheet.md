# Milestone 11C: the Libraries sheet — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A user opens Libraries from the project window, adds
`git@github.com:acme/threat-elements` at `v2.1.0` with their own SSH key, and
sees the new group in the palette without leaving the application.

**Architecture:** The sheet is a view over `LibrarySession`, which calls the
same use cases the verbs call. The application drops the sandbox, because a
child process inherits its parent's container and `git` inside one cannot read
the user's keys.

**Tech Stack:** Swift 6.3, SwiftUI, Swift Testing.

**Spec:** `docs/superpowers/specs/2026-09-09-shared-element-library-design.md`

**Depends on:** Milestones 11A and 11B.

## Global Constraints

- Swift 6.3, `swift-tools-version: 6.2`, `platforms: [.macOS(.v26)]`.
- The application target keeps the Hardened Runtime, the Developer ID signature
  and notarization. Only the sandbox goes.
- No test runs `git` against a network. `LibrarySession`'s tests use
  `FakeLibraryFetcher`.
- Every task ends with both suites green and one commit.
- Commits are unsigned: `git -c commit.gpgsign=false commit`.
- UI copy is written for its reader, not in ASD-STE100. Everything else is.

---

### Task 1: drop the sandbox and the bookmarks

**Files:**
- Modify: `threatmodeller/threatmodeller.entitlements`
- Modify: `threatmodeller/project/RecentProjects.swift`
- Modify: `docs/RELEASING.md`
- Test: `threatmodellerTests/RecentProjectsTests.swift`

**Interfaces:**
- Produces: `RecentProjects` stores plain paths and no bookmark.

**Why.** A child process inherits its parent's container. Inside one, `~` is
redirected to `~/Library/Containers/uk.craigbass.threatmodeller/Data`, so `git`
reads an empty `.ssh`, and `$SSH_AUTH_SOCK` names a socket the container denies.
Without the sandbox a security-scoped bookmark buys nothing, so a recent project
is a path.

- [x] **Step 1: Read `RecentProjects.swift` and its tests**

Note every place it mints, resolves or starts access to a bookmark. Those are
the lines this task removes.

- [x] **Step 2: Write the failing test**

```swift
@Test func remembersAProjectByItsPath() {
    let defaults = aTestDefaults()
    let recents = RecentProjects(defaults: defaults)

    recents.remember("/work")

    #expect(RecentProjects(defaults: defaults).paths == ["/work"])
}

@Test func keepsTheMostRecentFirst() {
    let defaults = aTestDefaults()
    let recents = RecentProjects(defaults: defaults)

    recents.remember("/one")
    recents.remember("/two")
    recents.remember("/one")

    #expect(recents.paths == ["/one", "/two"])
}
```

Match the names `RecentProjects` already uses; change the test to its real API
rather than changing the API to the test.

- [x] **Step 3: Run the tests and watch them fail or pass**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/RecentProjectsTests`

If they pass already, the store is path-based and only the bookmark code goes.

- [x] **Step 4: Change the entitlements**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<!-- This application is not sandboxed. A child process inherits its
	     parent's container, and `git` inside one cannot read the user's
	     ~/.ssh or reach their ssh-agent, so a private library repository
	     could not be fetched. It ships with the Hardened Runtime, a
	     Developer ID signature and notarization. -->
	<key>com.apple.security.files.user-selected.read-write</key>
	<true/>
</dict>
</plist>
```

- [x] **Step 5: Remove the bookmark code**

Delete the bookmark minting, resolving and `startAccessingSecurityScopedResource`
calls from `RecentProjects` and anywhere else that calls them. Search:
`grep -rn "bookmark\|SecurityScoped" threatmodeller`.

- [x] **Step 6: Write the reason into `docs/RELEASING.md`**

Add a short section, "The sandbox", saying the application is not sandboxed,
why, and that the Hardened Runtime, the signature and the notarization do not
change.

- [x] **Step 7: Run both suites and open the application**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
Expected: PASS.

Then open the built application, open a project, close it and open it again from
Open Recent Project, and confirm it still opens.

- [x] **Step 8: Commit**

```bash
git add threatmodeller/threatmodeller.entitlements \
        threatmodeller/project/RecentProjects.swift \
        threatmodellerTests/RecentProjectsTests.swift \
        docs/RELEASING.md
git -c commit.gpgsign=false commit -m "feat: run without the app sandbox, so git reads the user's keys"
```

---

### Task 2: the library session

**Files:**
- Create: `threatmodeller/project/LibrarySession.swift`
- Modify: `threatmodeller/Dependencies.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`
- Modify: `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`
- Test: `threatmodellerTests/LibrarySessionTests.swift`

**Interfaces:**
- Consumes: `ListLibraries`, `AddLibrary`, `UpdateLibraries`, `RemoveLibrary`,
  `ListOutdatedLibraries` from Milestone 11B.
- Produces:
  `struct LibraryRow: Equatable, Sendable { let label: String; let name: String; let repository: String; let tag: String; let matchesLock: Bool; var newestTag: String? }` in `LibrarySession.swift`, because a row joins what `ListLibraries` says with what `ListOutdatedLibraries` says, and neither use case holds both,
  `@MainActor @Observable final class LibrarySession { init(useCases: UseCaseFactory, root: String, onChange: @escaping () -> Void); private(set) var libraries: [LibraryRow]; private(set) var errorMessage: String?; private(set) var isWorking: Bool; private(set) var removalInUse: [String]?; func reload(); func add(repository: String, tag: String) async; func update(label: String) async; func remove(label: String, isForced: Bool); func checkForUpdates() async }`
- `UseCaseFactory` gains `addLibrary()`, `updateLibraries()`, `removeLibrary()`,
  `listLibraries()`, `listOutdatedLibraries()`.

- [x] **Step 1: Write the failing tests**

```swift
import Testing
import TestSupport
import ThreatModelKit
@testable import threatmodeller

@MainActor
struct LibrarySessionTests {
    private func aSession(usingTheLibrary: Bool = false) -> (LibrarySession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(
            usingTheLibrary
                ? "system \"Payments\" { component \"i\" { technology = \"acme-thing\" } }"
                : "system \"Payments\" { }",
            at: "/work/threatmodel/payments.arch"
        )
        useCases.libraryFetcher.put(
            ["acme.lib": "library \"acme\" { name = \"Acme Platform\" }\n"],
            repository: "github.com/acme/threat-elements",
            tag: "v2.1.0"
        )
        return (LibrarySession(useCases: useCases, root: "/work", onChange: {}), useCases)
    }

    @Test func listsNothingForAProjectWithNoLibrary() {
        let (session, _) = aSession()

        session.reload()

        #expect(session.libraries.isEmpty)
        #expect(session.errorMessage == nil)
    }

    @Test func addsALibraryAndListsIt() async {
        let (session, _) = aSession()

        await session.add(repository: "github.com/acme/threat-elements", tag: "v2.1.0")

        #expect(session.libraries.map(\.label) == ["acme"])
        #expect(session.libraries.first?.name == "Acme Platform")
        #expect(session.libraries.first?.tag == "v2.1.0")
        #expect(session.libraries.first?.matchesLock == true)
        #expect(session.errorMessage == nil)
    }

    @Test func tellsTheProjectToReloadAfterAnAdd() async {
        let useCases = TestDependencies()
        useCases.project.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")
        useCases.libraryFetcher.put(
            ["acme.lib": "library \"acme\" { }\n"],
            repository: "r",
            tag: "v1"
        )
        var reloads = 0
        let session = LibrarySession(useCases: useCases, root: "/work", onChange: { reloads += 1 })

        await session.add(repository: "r", tag: "v1")

        #expect(reloads == 1)
    }

    @Test func saysWhatTheFetchSaid() async {
        let (session, _) = aSession()

        await session.add(repository: "github.com/acme/threat-elements", tag: "v9")

        #expect(session.libraries.isEmpty)
        #expect(session.errorMessage?.isEmpty == false)
    }

    @Test func asksAgainBeforeRemovingALibraryASystemNames() async {
        let (session, _) = aSession(usingTheLibrary: true)
        await session.add(repository: "github.com/acme/threat-elements", tag: "v2.1.0")

        session.remove(label: "acme", isForced: false)

        #expect(session.removalInUse == ["payments"])
        #expect(session.libraries.map(\.label) == ["acme"])
    }

    @Test func removesItWhenTheUserSaysSoAgain() async {
        let (session, _) = aSession(usingTheLibrary: true)
        await session.add(repository: "github.com/acme/threat-elements", tag: "v2.1.0")
        session.remove(label: "acme", isForced: false)

        session.remove(label: "acme", isForced: true)

        #expect(session.libraries.isEmpty)
        #expect(session.removalInUse == nil)
    }

    @Test func saysWhichLibraryHasANewerTag() async {
        let (session, useCases) = aSession()
        await session.add(repository: "github.com/acme/threat-elements", tag: "v2.1.0")
        useCases.libraryFetcher.put(
            ["acme.lib": "library \"acme\" { }\n"],
            repository: "github.com/acme/threat-elements",
            tag: "v2.2.0"
        )

        await session.checkForUpdates()

        #expect(session.libraries.first?.newestTag == "v2.2.0")
    }
}
```

`TestDependencies` gains a `libraryFetcher: FakeLibraryFetcher` the test fills.

- [x] **Step 2: Run the tests and watch them fail**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/LibrarySessionTests`
Expected: FAIL, `cannot find 'LibrarySession' in scope`.

- [x] **Step 3: Write `LibrarySession.swift`**

It owns no rule. Every answer comes from a use case, exactly as
`ProjectSession` does. `add`, `update` and `checkForUpdates` are `async` and run
their use case off the main actor with `Task.detached`, then write the result
back on the main actor, so a slow `git` does not stop the window. `isWorking` is
true while one runs. `onChange` is what the project window calls to reload the
project after a change, so the palette shows the new group.

- [x] **Step 4: Run the tests and watch them pass**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add threatmodeller/project/LibrarySession.swift \
        threatmodeller/Dependencies.swift \
        ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift \
        ThreatModelKit/Sources/TestSupport/TestDependencies.swift \
        threatmodellerTests/LibrarySessionTests.swift
git -c commit.gpgsign=false commit -m "feat: hold what the Libraries sheet shows"
```

---

### Task 3: the sheet

**Files:**
- Create: `threatmodeller/project/LibrariesSheet.swift`
- Modify: `threatmodeller/project/ProjectWindow.swift`
- Test: `threatmodellerTests/ViewRenderTests.swift`

**Interfaces:**
- Produces: `struct LibrariesSheet: View { let session: LibrarySession; let dismiss: () -> Void }`
- `ProjectWindow` gains a toolbar button with the accessibility identifier
  `libraries` that opens the sheet.

- [x] **Step 1: Write the failing render test**

Follow the shape the other tests in `ViewRenderTests.swift` use: render the view
with `ImageRenderer` and assert the pixels are not all one colour, and that the
view builds for an empty project and for one holding two libraries.

```swift
@Test func drawsTheLibrariesSheet() throws {
    let useCases = TestDependencies()
    useCases.project.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")
    let session = LibrarySession(useCases: useCases, root: "/work", onChange: {})
    session.reload()

    let image = try #require(render(LibrariesSheet(session: session, dismiss: {})))

    #expect(image.width > 0)
}
```

Use the helper `ViewRenderTests` already holds rather than a new one.

- [x] **Step 2: Run the test and watch it fail**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ViewRenderTests`
Expected: FAIL, `cannot find 'LibrariesSheet' in scope`.

- [x] **Step 3: Write the sheet**

A `Table` or a `List` of the rows, each showing the name, the label, the
repository, the tag, and the status: `matches`, `does not match the lock file`,
or `<newest> is newer`. Below it: `Add…`, `Update`, `Remove`,
`Check for updates`, and `Done`. `Add…` opens a small form asking for a
repository and a tag. While `session.isWorking`, the buttons are disabled and a
`ProgressView` shows. `session.errorMessage` shows under the list, and it holds
`git`'s own message.

Give each control an accessibility identifier: `library-add`,
`library-update`, `library-remove`, `library-check-for-updates`,
`libraries-done`.

`ProjectWindow` gains:

```swift
            ToolbarItem {
                Button("Libraries") { isShowingLibraries = true }
                    .disabled(session.root == nil)
                    .accessibilityIdentifier("libraries")
            }
```

and a `.sheet(isPresented: $isShowingLibraries)` holding `LibrariesSheet`, built
with `LibrarySession(useCases:root:onChange:)` where `onChange` calls
`session.reloadFromDisk()`.

- [x] **Step 4: Run the tests and watch them pass**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add threatmodeller/project/LibrariesSheet.swift \
        threatmodeller/project/ProjectWindow.swift \
        threatmodellerTests/ViewRenderTests.swift
git -c commit.gpgsign=false commit -m "feat: manage a library from the project window"
```

---

### Task 4: the documents, and one run of the real thing

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/specs/MILESTONE-11-CARRY-FORWARD.md` (create it)

- [x] **Step 1: Write the sheet into `README.md`**

Add the Libraries button to "The application", saying what the sheet lists, that
`Add…` and `Check for updates` are the two controls that reach a server, and
that a private repository works because the application runs the user's own
`git`.

- [x] **Step 2: Run the real application against a real repository**

Build and open the application. Open a project. Open Libraries. Add a public
repository holding a `.lib` file at its root, at a real tag. Confirm the palette
shows the new group, `threatmodel/library/` holds the file and the lock file,
and `threatmodeller library verify` exits 0.

Record what happened in the carry-forward note, including anything that did not
work.

- [x] **Step 3: Write the carry-forward note**

`docs/superpowers/specs/MILESTONE-11-CARRY-FORWARD.md`, in the shape the other
carry-forward notes use: what Milestone 11 closed, and what still stands. Carry
forward at least: a library cannot define a category; there is no index, so no
browsing and no search; `ListOutdatedLibraries` compares tags as text rather
than as versions; and the About window does not list the libraries.

- [x] **Step 4: Run both suites**

Run: `cd ThreatModelKit && swift test`
Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add README.md docs/superpowers/specs/MILESTONE-11-CARRY-FORWARD.md
git -c commit.gpgsign=false commit -m "docs: say what Milestone 11 closed and what stands"
```
