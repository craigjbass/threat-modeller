# The project follows its files, the workflow shows its buttons, and the application opens on a welcome window

Date: 2026-09-09

## 1. Purpose

Three changes to the macOS application.

1. The project window redraws when the source files change on disk.
2. The project workflow gets large buttons in the window, not menu items only.
3. The application opens on a welcome window, not on the file open panel.

## 2. Change 1 — the project window follows its files

### 2.1 What the user sees

The user opens a project, then edits `payments.arch` in a text editor and saves
it. The diagram redraws on its own.

When the user has changes on screen that no file holds yet — a component moved,
a control answered, a compensating control written — the window does not
discard them. It shows a notice strip:

```
The files changed on disk. Your unsaved changes are still on screen.
                                          [ Reload ]  [ Keep Mine ]
```

`Reload` reads the files again and draws them. `Keep Mine` hides the strip and
changes nothing. The strip returns on the next change on disk.

### 2.2 What happens inside

`ProjectSession` owns a watcher. The watcher reports one thing: a file under
the project directory changed. `ProjectSession` then reads a fingerprint of the
project source files and compares it with the fingerprint it holds.

- The fingerprints match: the change came from this application's own save, or
  from an editor that wrote the same bytes. Nothing happens.
- The fingerprints differ and nothing on screen is unsaved: `ProjectSession`
  reloads at once.
- The fingerprints differ and something on screen is unsaved: `ProjectSession`
  sets `hasFilesChangedOnDisk`, and the window shows the strip.

`ProjectSession` reads a new fingerprint after every open, every reload and
every save, so its stored fingerprint always names the bytes it last read or
wrote.

A reload keeps the chosen system when the project still holds it, and picks the
first system when it does not.

### 2.3 The watcher

`ProjectWatching` is a protocol in the application layer:

```swift
@MainActor
protocol ProjectWatching {
    func watch(directory: String, onChange: @escaping () -> Void)
    func stop()
}
```

`FSEventsProjectWatcher` implements it with `FSEventStreamCreate` over the
project directory, with `kFSEventStreamCreateFlagFileEvents` and a latency of
0.3 seconds. `FSEvents` reports a write into a file that already exists, which
a `DispatchSource` on the directory does not.

Watching holds no business rule, so it stays out of `ThreatModelKit`. Tests
inject a fake watcher and call its `onChange`.

### 2.4 The fingerprint

`ReadProjectFingerprint` is a new use case in
`ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/`. It reads every
`.arch` and `.controls` path the layout names, and answers a dictionary from
path to a hash of the file text.

```swift
public enum ReadProjectFingerprintResponse: Equatable, Sendable {
    case read(fingerprint: [String: Int])
    case notAProject(reason: String)
}
```

The hash is `String.hashValue`. Swift seeds that hash once per process, so two
reads in one run of the application answer the same number for the same text.
Nothing writes the fingerprint to a file, so the per-process seed costs
nothing.

A `.controls` file that does not exist yet contributes no entry, and a file
that appears later changes the fingerprint.

### 2.5 The unsaved flag

`ThreatModelSession.refresh()` runs once when the session is built, and once
after every change to the model. It gains a counter:

```swift
/// How many times this session has read the model back. It starts at 1, and
/// every change raises it. `ProjectSession` compares it with the number it
/// recorded to answer whether anything on screen is unsaved.
private(set) var revision = 0

private func refresh() {
    revision += 1
    ...
}
```

`ProjectSession` records `model.revision` at the end of `choose(_:)` and after
each save. `hasUnsavedChanges` answers true when the current revision is higher
than the recorded one.

A use case that failed still calls `refresh()`, so a failed change raises the
revision without changing the model. The cost is one notice strip the user did
not need, and that same failure already shows an error message.

## 3. Change 2 — the workflow action bar

### 3.1 What the user sees

A bar sits across the top of the project window, under the toolbar and above
the three columns.

```
+- Threat Modeller Project -----------------------------+
| [System: payments v]                                  |
+-------------------------------------------------------+
|  [ Save System ]   [ Compile Report ]                 |
|  Report: threatmodel/payments.report.md               |
+---------+----------------------------+----------------+
| Palette |  Canvas                    | Threats        |
+---------+----------------------------+----------------+
```

- `Save System` writes the architecture and the answers. Its icon is
  `square.and.arrow.down`. Its shortcut stays Command-Option-S.
- `Compile Report` writes the Markdown report. Its icon is `doc.text`. Its
  shortcut stays Command-Option-R.
- Both buttons use `.controlSize(.large)` and carry an icon and a label.
- Both buttons are disabled while `chosenSystem` is nil.

The line under the buttons states the result of the last action:

- After a save: `Saved. <n> threats have no answer.`, or `Saved.` when every
  threat has one.
- After a compile: `Report: <path>`.
- Before either: nothing.

### 3.2 What happens inside

`WorkflowBar` is a new view in `threatmodeller/project/`. It takes the
`ProjectSession` and calls `save()` and `compileReport()`. It holds no rule.

`ProjectSession` gains `lastActionMessage: String?`, which `save()` and
`compileReport()` set, and which `choose(_:)` clears.

`ProjectWindow` draws the bar in its `safeAreaInset(edge: .top)`, above the
existing diagnostics strip. The system picker stays in the toolbar. The menu
commands stay as they are.

## 4. Change 3 — the welcome window

### 4.1 What the user sees

The application opens on this window.

```
+- Threat Modeller -----------------------+
|          Threat Modeller                |
|          catalogue v1.4.2               |
|                                         |
|  +------------+  +------------+         |
|  | [folder]   |  | [doc]      |         |
|  | Open       |  | Open Model |         |
|  | Project... |  | File...    |         |
|  | A folder   |  | One .tm    |         |
|  | of .arch   |  | document   |         |
|  +------------+  +------------+         |
|           New Model File                |
|  Recent                                 |
|   [folder] ~/work/payments              |
|   [doc]    ~/Desktop/api.threatmodel    |
+-----------------------------------------+
```

- `Open Project...` runs the same open panel the File menu runs, opens the
  project window, and closes the welcome window.
- `Open Model File...` calls `NSDocumentController.shared.openDocument(nil)`.
- `New Model File` calls `NSDocumentController.shared.newDocument(nil)`.
- A recent project row opens that project without a panel.
- A recent model file row opens that document.
- The window shows the catalogue version, so a user can read it without the
  About window.
- The window is not resizable and carries no toolbar.

When the catalogue could not be loaded, the window says so in place of the two
cards, and offers no route.

### 4.2 Scene order

`Window("Threat Modeller", id: "welcome")` is declared first in the `App` body,
before `DocumentGroup`. The first scene is what macOS opens at launch.

RISK: this alone may not stop macOS presenting the open panel for the document
type at launch. The implementation checks it by running the built application.
If the panel still appears, an `NSApplicationDelegate` is added with
`applicationShouldOpenUntitledFile` answering false, and
`ProjectLaunchArgument` keeps its current behaviour.

### 4.3 Recent projects

The application is sandboxed. A path alone cannot be reopened after a
relaunch, so each recent project is stored as an app-scoped bookmark.
`threatmodeller.entitlements` already grants
`com.apple.security.files.bookmarks.app-scope`.

`RecentProjects` is a new type in `threatmodeller/project/`.

```swift
@MainActor
final class RecentProjects {
    func record(url: URL)
    func list() -> [RecentProject]      // newest first, at most 10
    func resolve(_ entry: RecentProject) -> URL?
}
```

- `record` creates the bookmark with `.withSecurityScope`, and writes the
  array of bookmarks to `UserDefaults` under `recentProjects`.
- `resolve` resolves the bookmark, and drops the entry when the bookmark is
  stale or the directory is gone.
- The caller calls `startAccessingSecurityScopedResource()` before it opens the
  root, and `stopAccessingSecurityScopedResource()` when the project closes.

Recent model files come from `NSDocumentController.shared.recentDocumentURLs`.
`DocumentGroup` already fills that list, so nothing new records it.

### 4.4 Reopening the welcome window

- A new menu item `Window > Welcome` opens it.
- Clicking the Dock icon with no window open opens it, through
  `applicationShouldHandleReopen`.

## 5. Files

New:

- `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/ReadProjectFingerprint.swift`
- `threatmodeller/project/ProjectWatching.swift` (protocol and FSEvents implementation)
- `threatmodeller/project/WorkflowBar.swift`
- `threatmodeller/project/RecentProjects.swift`
- `threatmodeller/WelcomeWindow.swift`
- `ThreatModelKit/Tests/UnitTests/ReadProjectFingerprintTests.swift`
- `threatmodellerTests/RecentProjectsTests.swift`

Changed:

- `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift` — the new factory method
- `threatmodeller/Dependencies.swift` — the new factory method
- `ThreatModelKit/Sources/TestSupport/TestDependencies.swift` — the new factory method
- `threatmodeller/ThreatModelSession.swift` — `changeCount` and `apply()`
- `threatmodeller/project/ProjectSession.swift` — watcher, fingerprint, unsaved flag, last action message
- `threatmodeller/project/ProjectWindow.swift` — the action bar and the changed-on-disk strip
- `threatmodeller/threatmodellerApp.swift` — the welcome scene and the application delegate
- `threatmodellerTests/ProjectSessionTests.swift` — the new session tests
- `threatmodellerTests/ViewRenderTests.swift` — the new views

## 6. Testing

`ReadProjectFingerprintTests` runs the use case over `InMemoryProject`:

- two systems answer two `.arch` entries
- a `.controls` file that exists answers a third entry
- the same text twice answers the same fingerprint
- changed text answers a different fingerprint
- a root that is not a project answers `notAProject`

`ProjectSessionTests` runs `ProjectSession` with a fake watcher:

- the watcher fires and the text is the same: the model is the same object
- the watcher fires, the text changed, nothing is unsaved: the canvas redraws
  and `hasFilesChangedOnDisk` stays false
- the watcher fires, the text changed, a component was moved:
  `hasFilesChangedOnDisk` is true and the canvas does not redraw
- `reloadFromDisk()` then redraws and clears the flag
- `keepMine()` clears the flag and does not redraw
- a save is followed by a watcher event, and nothing redraws
- a reload keeps the chosen system when the project still holds it
- a reload picks the first system when the chosen one is gone
- `save()` sets `lastActionMessage`, and `choose(_:)` clears it

`RecentProjectsTests` runs over a `UserDefaults` suite made for the test:

- `record` then `list` answers the recorded root
- recording the same root twice answers one entry, newest first
- the list holds at most 10

`ViewRenderTests` draws `WelcomeWindow` and the project window with the action
bar, and reads the pixels back, as the existing render tests do.

## 7. Out of scope

- Watching a document window's `.threatmodel` file. This change covers the
  project route only.
- Merging a change on disk with a change on screen. The user picks one.
- Any change to the report format, the catalogue or the DSL.

## 8. What the build showed

Run on 2026-09-09, against the built application.

**The launch window.** The application opened one window, 620 by 552 points,
which is the welcome window plus its title bar. No open panel appeared and no
document window appeared. Both parts were needed: the `Window` scene declared
first in the `App` body, and `AppDelegate.applicationShouldOpenUntitledFile`
answering false.

The check read the window list with `CGWindowListCopyWindowInfo`. Window titles
need the screen recording permission, which this machine does not grant to the
runner, so the check read the size and the count rather than the title.
`osascript` and `screencapture` both failed for the same reason:
`osascript is not allowed assistive access` and `could not create image from
display`.

**FSEvents.** A separate check ran the same stream flags and the same 0.3
second latency over a temporary directory, then wrote into a file that already
existed, in place. The stream reported three events. That is what a text editor
that saves in place produces, and it is what a `DispatchSource` on the directory
would not report.

**A stale build.** Adding a source file to `ThreatModelKit` while an Xcode build
of the application already existed made `TestSupport` fail to compile with
`Cannot find type 'ReadProjectFingerprintUseCase' in scope`, although
`swift test` in the package passed. `xcodebuild clean` cleared it. Run the clean
after adding a file to the package, before running the application tests.
