# Milestone 11B: managing a library from the command line — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A person runs `threatmodeller library add git@github.com:acme/threat-elements v2.1.0`
and the project holds the library, a lock file that pins it, and a `verify` that
a continuous integration job can run offline.

**Architecture:** One `LibraryFetching` port with `git` behind it. Five use
cases over that port and the project gateway. Six verbs over the use cases. The
lock file is JSON beside the `.lib` files.

**Tech Stack:** Swift 6.3, SwiftPM, Swift Testing, Foundation only in the
package. `git` is a child process, found on `PATH`.

**Spec:** `docs/superpowers/specs/2026-09-09-shared-element-library-design.md`

**Depends on:** Milestone 11A.

## Global Constraints

- Swift 6.3, `swift-tools-version: 6.2`, `platforms: [.macOS(.v26)]`.
- **No package target may import AppKit, CoreGraphics, SwiftUI, CoreText or
  PDFKit.** Foundation only.
- No third-party dependency.
- **No test reaches the network.** The fetcher's contract builds a real
  repository with `git init` in a temporary directory and clones it by path.
- A gateway gets a shared contract in `TestSupport`, run against the fake and
  the real implementation.
- Every task ends with `cd ThreatModelKit && swift test` green and one commit.
- Commits are unsigned: `git -c commit.gpgsign=false commit`.
- Prose in code comments, commits and documents follows ASD-STE100.

---

### Task 1: the fetching port, its fake and its contract

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/gateway/LibraryFetching.swift`
- Create: `ThreatModelKit/Sources/TestSupport/FakeLibraryFetcher.swift`
- Create: `ThreatModelKit/Sources/TestSupport/LibraryFetchingContract.swift`
- Test: `ThreatModelKit/Tests/GatewayContractTests/FakeLibraryFetcherTests.swift`

**Interfaces:**
- Produces:
  `enum LibraryFetchFault: Error, Equatable { case gitIsNotInstalled, cannotRead(reason: String), noLibraryFile, badRepository(String), timedOut }`,
  `protocol LibraryFetching: Sendable { func fetch(repository: String, tag: String) throws -> [String: String]; func tags(repository: String) throws -> [String] }`,
  `final class FakeLibraryFetcher: LibraryFetching`,
  `func assertLibraryFetching(_ fetcher: LibraryFetching, repository: String, tag: String)`

- [ ] **Step 1: Write the failing contract and its test**

```swift
// TestSupport/LibraryFetchingContract.swift
import Testing
import ThreatModelKit

/// The one contract every library fetcher meets. `repository` must hold one
/// file, `acme.lib`, at `tag`, and must hold the tag `v1.0.0`.
public func assertLibraryFetching(_ fetcher: LibraryFetching, repository: String, tag: String) {
    let files = (try? fetcher.fetch(repository: repository, tag: tag)) ?? [:]
    #expect(files.keys.sorted() == ["acme.lib"])
    #expect(files["acme.lib"]?.hasPrefix("library \"acme\"") == true)

    let tags = (try? fetcher.tags(repository: repository)) ?? []
    #expect(tags.contains(tag))

    #expect(throws: (any Error).self) {
        try fetcher.fetch(repository: repository, tag: "no-such-tag")
    }
    #expect(throws: (any Error).self) {
        try fetcher.fetch(repository: "-oops", tag: tag)
    }
}
```

```swift
// TestSupport/FakeLibraryFetcher.swift
import Foundation
import ThreatModelKit

/// A fetcher a test fills by hand, so no test runs `git` or reaches a network.
public final class FakeLibraryFetcher: LibraryFetching, @unchecked Sendable {
    private let lock = NSLock()
    private var filesByTag: [String: [String: String]] = [:]
    private var tagsByRepository: [String: [String]] = [:]
    public private(set) var fetched: [(repository: String, tag: String)] = []

    public init() {}

    /// What `fetch` answers for one repository and tag.
    public func put(_ files: [String: String], repository: String, tag: String) {
        lock.lock()
        defer { lock.unlock() }
        filesByTag["\(repository)@\(tag)"] = files
        tagsByRepository[repository, default: []].append(tag)
    }

    public func fetch(repository: String, tag: String) throws -> [String: String] {
        if repository.hasPrefix("-") { throw LibraryFetchFault.badRepository(repository) }
        lock.lock()
        defer { lock.unlock() }
        fetched.append((repository, tag))
        guard let files = filesByTag["\(repository)@\(tag)"] else {
            throw LibraryFetchFault.cannotRead(reason: "no such tag \"\(tag)\"")
        }
        guard files.isEmpty == false else { throw LibraryFetchFault.noLibraryFile }
        return files
    }

    public func tags(repository: String) throws -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return tagsByRepository[repository] ?? []
    }
}
```

```swift
// Tests/GatewayContractTests/FakeLibraryFetcherTests.swift
import Testing
import TestSupport

@Suite("The fake library fetcher")
struct FakeLibraryFetcherTests {
    @Test func meetsTheContract() {
        let fetcher = FakeLibraryFetcher()
        fetcher.put(
            ["acme.lib": "library \"acme\" { }\n"],
            repository: "github.com/acme/threat-elements",
            tag: "v1.0.0"
        )

        assertLibraryFetching(
            fetcher,
            repository: "github.com/acme/threat-elements",
            tag: "v1.0.0"
        )
    }
}
```

- [ ] **Step 2: Run the test and watch it fail**

Run: `cd ThreatModelKit && swift test --filter FakeLibraryFetcherTests`
Expected: FAIL, `cannot find 'LibraryFetching' in scope`.

- [ ] **Step 3: Write the port**

```swift
/// What a fetch can fail with. Each one carries what a person needs to fix it.
public enum LibraryFetchFault: Error, Equatable, Sendable {
    case gitIsNotInstalled
    /// `git`'s own message, which is what tells a user their key is not loaded.
    case cannotRead(reason: String)
    case noLibraryFile
    case badRepository(String)
    case timedOut

    public var message: String {
        switch self {
        case .gitIsNotInstalled: "git is not installed, so a library cannot be fetched"
        case .cannotRead(let reason): reason
        case .noLibraryFile: "that repository holds no .lib file at its root"
        case .badRepository(let repository): "\"\(repository)\" is not a repository this application reads"
        case .timedOut: "the fetch did not answer in 60 seconds"
        }
    }
}

/// Reads a library repository.
///
/// One port, so the window and the executable fetch the same way, and every
/// test answers it with a fake.
public protocol LibraryFetching: Sendable {
    /// The `.lib` files at the repository's root, by file name.
    func fetch(repository: String, tag: String) throws -> [String: String]
    /// Every tag the repository holds.
    func tags(repository: String) throws -> [String]
}
```

- [ ] **Step 4: Run the test and watch it pass**

Run: `cd ThreatModelKit && swift test --filter FakeLibraryFetcherTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/architecture/gateway/LibraryFetching.swift \
        ThreatModelKit/Sources/TestSupport/FakeLibraryFetcher.swift \
        ThreatModelKit/Sources/TestSupport/LibraryFetchingContract.swift \
        ThreatModelKit/Tests/GatewayContractTests/FakeLibraryFetcherTests.swift
git -c commit.gpgsign=false commit -m "feat: state what a library fetcher does"
```

---

### Task 2: the git fetcher

**Files:**
- Create: `ThreatModelKit/Sources/FileGateways/GitLibraryFetcher.swift`
- Test: `ThreatModelKit/Tests/GatewayIntegrationTests/GitLibraryFetcherTests.swift`

**Interfaces:**
- Produces: `struct GitLibraryFetcher: LibraryFetching { init(timeout: TimeInterval = 60) }`

**Why the test needs no network.** The test builds a real repository in a
temporary directory with `git init`, commits `acme.lib`, tags it, and then
clones it by path. That runs the real `git` and proves the real gateway.

- [ ] **Step 1: Write the failing test**

```swift
import Foundation
import FileGateways
import Testing
import TestSupport

@Suite("The git library fetcher")
struct GitLibraryFetcherTests {
    /// Builds a repository holding one library at `v1.0.0`, and returns its path.
    private func aRepository() throws -> String {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("library-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try "library \"acme\" { }\n".write(
            to: directory.appendingPathComponent("acme.lib"),
            atomically: true,
            encoding: .utf8
        )
        try "not a library\n".write(
            to: directory.appendingPathComponent("README.md"),
            atomically: true,
            encoding: .utf8
        )

        for arguments in [
            ["init", "--initial-branch=main"],
            ["-c", "user.email=a@b.c", "-c", "user.name=A", "add", "."],
            ["-c", "user.email=a@b.c", "-c", "user.name=A", "commit", "-m", "one"],
            ["tag", "v1.0.0"]
        ] {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            process.arguments = ["git"] + arguments
            process.currentDirectoryURL = directory
            process.standardOutput = Pipe()
            process.standardError = Pipe()
            try process.run()
            process.waitUntilExit()
            #expect(process.terminationStatus == 0)
        }
        return directory.path
    }

    @Test func meetsTheContract() throws {
        let repository = try aRepository()
        defer { try? FileManager.default.removeItem(atPath: repository) }

        assertLibraryFetching(GitLibraryFetcher(), repository: repository, tag: "v1.0.0")
    }

    @Test func readsOnlyTheLibraryFiles() throws {
        let repository = try aRepository()
        defer { try? FileManager.default.removeItem(atPath: repository) }

        let files = try GitLibraryFetcher().fetch(repository: repository, tag: "v1.0.0")

        #expect(files.keys.sorted() == ["acme.lib"])
    }

    @Test func refusesARepositoryThatStartsWithAFlag() {
        #expect(throws: LibraryFetchFault.badRepository("--upload-pack=x")) {
            try GitLibraryFetcher().fetch(repository: "--upload-pack=x", tag: "v1.0.0")
        }
    }
}
```

- [ ] **Step 2: Run the test and watch it fail**

Run: `cd ThreatModelKit && swift test --filter GitLibraryFetcherTests`
Expected: FAIL, `cannot find 'GitLibraryFetcher' in scope`.

- [ ] **Step 3: Write `GitLibraryFetcher.swift`**

```swift
import Foundation
import ThreatModelKit

/// Reads a library repository by running `git`.
///
/// A team's access to its own repositories already lives in `ssh-agent`,
/// `~/.ssh/config`, a credential helper and `~/.gitconfig`. Running `git`
/// inherits every one of them, so this application re-implements none of it.
public struct GitLibraryFetcher: LibraryFetching {
    private let timeout: TimeInterval

    public init(timeout: TimeInterval = 60) {
        self.timeout = timeout
    }

    public func fetch(repository: String, tag: String) throws -> [String: String] {
        try refuseAFlag(repository)

        let clone = FileManager.default.temporaryDirectory
            .appendingPathComponent("threatmodeller-library-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: clone) }

        _ = try run([
            "clone", "--depth", "1", "--no-tags", "--recurse-submodules=no",
            "--branch", tag, "--", repository, clone.path
        ])

        let names = try FileManager.default.contentsOfDirectory(atPath: clone.path)
            .filter { $0.hasSuffix(".\(ProjectConvention.libraryExtension)") }
        guard names.isEmpty == false else { throw LibraryFetchFault.noLibraryFile }

        var files: [String: String] = [:]
        for name in names {
            files[name] = try String(
                contentsOf: clone.appendingPathComponent(name),
                encoding: .utf8
            )
        }
        return files
    }

    public func tags(repository: String) throws -> [String] {
        try refuseAFlag(repository)

        // Each line reads `<sha>\trefs/tags/<tag>`, and an annotated tag adds a
        // second line ending `^{}`, which names the same tag.
        return try run(["ls-remote", "--tags", "--", repository])
            .split(separator: "\n")
            .compactMap { line in
                guard let ref = line.split(separator: "\t").last else { return nil }
                guard ref.hasPrefix("refs/tags/") else { return nil }
                let tag = ref.dropFirst("refs/tags/".count)
                return tag.hasSuffix("^{}") ? nil : String(tag)
            }
    }

    /// A repository is user input, so a value that reads as a flag is refused
    /// rather than passed to `git`.
    private func refuseAFlag(_ repository: String) throws {
        if repository.hasPrefix("-") { throw LibraryFetchFault.badRepository(repository) }
    }

    private func run(_ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["git"] + arguments

        var environment = ProcessInfo.processInfo.environment
        // A repository the user cannot read fails and says so, rather than
        // waiting for a password nobody can type.
        environment["GIT_TERMINAL_PROMPT"] = "0"
        process.environment = environment

        let output = Pipe()
        let errors = Pipe()
        process.standardOutput = output
        process.standardError = errors

        do {
            try process.run()
        } catch {
            throw LibraryFetchFault.gitIsNotInstalled
        }

        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        if process.isRunning {
            process.terminate()
            throw LibraryFetchFault.timedOut
        }

        let text = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        let failure = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        guard process.terminationStatus == 0 else {
            throw LibraryFetchFault.cannotRead(
                reason: failure.trimmingCharacters(in: .whitespacesAndNewlines)
            )
        }
        return text
    }
}
```

- [ ] **Step 4: Run the test and watch it pass**

Run: `cd ThreatModelKit && swift test --filter GitLibraryFetcherTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/FileGateways/GitLibraryFetcher.swift \
        ThreatModelKit/Tests/GatewayIntegrationTests/GitLibraryFetcherTests.swift
git -c commit.gpgsign=false commit -m "feat: fetch a library by running git"
```

---

### Task 3: the lock file

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/LibraryLock.swift`
- Test: `ThreatModelKit/Tests/UnitTests/LibraryLockTests.swift`

**Interfaces:**
- Produces:
  `struct LockedLibrary: Equatable, Sendable { let label: String; let repository: String; let tag: String; let files: [String: String] }`,
  `struct LibraryLock: Equatable, Sendable { var libraries: [LockedLibrary]; static func read(_ text: String) -> LibraryLock; func written() -> String; static func checksum(_ text: String) -> String }`

The checksum is `sha256` of the file's bytes, written as lower-case hexadecimal.
Foundation on Linux has no `CryptoKit`, so write the digest by hand in
`ThreatModelKit`; it is 40 lines and it has no dependency.

- [ ] **Step 1: Write the failing test**

```swift
import Testing
@testable import ThreatModelKit

@Suite("The library lock file")
struct LibraryLockTests {
    private let text = """
    {
      "libraries" : {
        "acme" : {
          "files" : {
            "acme.lib" : "ab12"
          },
          "repository" : "github.com/acme/threat-elements",
          "tag" : "v2.1.0"
        }
      }
    }
    """

    @Test func readsWhatItWrites() {
        let lock = LibraryLock(libraries: [
            LockedLibrary(
                label: "acme",
                repository: "github.com/acme/threat-elements",
                tag: "v2.1.0",
                files: ["acme.lib": "ab12"]
            )
        ])

        #expect(LibraryLock.read(lock.written()) == lock)
    }

    @Test func readsALockFileAPersonWrote() {
        #expect(LibraryLock.read(text).libraries.first?.tag == "v2.1.0")
    }

    @Test func readsNothingFromTextThatIsNotALockFile() {
        #expect(LibraryLock.read("not json").libraries.isEmpty)
    }

    @Test func checksumsTheSameTextTheSameWay() {
        #expect(LibraryLock.checksum("abc") == LibraryLock.checksum("abc"))
        #expect(LibraryLock.checksum("abc") != LibraryLock.checksum("abd"))
        #expect(LibraryLock.checksum("abc").count == 64)
    }

    @Test func checksumsWhatSha256Says() {
        // The published SHA-256 of "abc".
        #expect(
            LibraryLock.checksum("abc")
                == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
    }
}
```

- [ ] **Step 2: Run the test and watch it fail**

Run: `cd ThreatModelKit && swift test --filter LibraryLockTests`
Expected: FAIL, `cannot find 'LibraryLock' in scope`.

- [ ] **Step 3: Write `LibraryLock.swift`**

Use `Codable` over a private `[String: Entry]` shape with
`JSONEncoder.outputFormatting = [.prettyPrinted, .sortedKeys]`, so two writes of
one lock file are the same text. Write `sha256` by hand: the eight initial
values, the sixty-four round constants, the message schedule and the
compression loop. Keep it in one file with a comment saying it is FIPS 180-4.

- [ ] **Step 4: Run the test and watch it pass**

Run: `cd ThreatModelKit && swift test --filter LibraryLockTests`
Expected: PASS, including `checksumsWhatSha256Says`.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/architecture/domain/LibraryLock.swift \
        ThreatModelKit/Tests/UnitTests/LibraryLockTests.swift
git -c commit.gpgsign=false commit -m "feat: read and write the library lock file"
```

---

### Task 4: adding and updating a library

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/AddLibrary.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/UpdateLibraries.swift`
- Test: `ThreatModelKit/Tests/UnitTests/AddLibraryTests.swift`

**Interfaces:**
- Produces:
  `struct AddLibraryRequest { let root: String; let repository: String; let tag: String }`,
  `enum AddLibraryResponse { case added(label: String, files: [String]); case refused(reason: String); case cannotWrite(reason: String) }`,
  `struct AddLibrary: AddLibraryUseCase { init(projects: ProjectSourceGateway, fetcher: LibraryFetching, sources: LibrarySourceGateway) }`,
  `struct UpdateLibrariesRequest { let root: String; let label: String? }`,
  `enum UpdateLibrariesResponse { case updated(labels: [String]); case refused(reason: String) }`

`AddLibrary` fetches, reads each file's label with the source gateway, refuses a
file that does not parse, writes the files under
`<directory>/library/`, and writes the lock entry keyed by the label. Adding a
repository the project already holds replaces its entry.

- [ ] **Step 1: Write the failing tests**

```swift
@Suite("Adding a library")
struct AddLibraryTests {
    private func aProject() -> (ProjectSourceGateway, FakeLibraryFetcher, AddLibraryUseCase) {
        let projects = InMemoryProject()
        projects.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")
        let fetcher = FakeLibraryFetcher()
        fetcher.put(
            ["acme.lib": "library \"acme\" { }\n"],
            repository: "github.com/acme/threat-elements",
            tag: "v2.1.0"
        )
        return (
            projects,
            fetcher,
            AddLibrary(projects: projects, fetcher: fetcher, sources: HclLibrarySource())
        )
    }

    @Test func writesTheFilesAndTheLockEntry() throws {
        let (projects, _, add) = aProject()

        let response = add.execute(
            AddLibraryRequest(
                root: "/work",
                repository: "github.com/acme/threat-elements",
                tag: "v2.1.0"
            )
        )

        #expect(response == .added(label: "acme", files: ["acme.lib"]))
        #expect(try projects.read(path: "/work/threatmodel/library/acme.lib")
            == "library \"acme\" { }\n")
        let lock = LibraryLock.read(try projects.read(path: "/work/threatmodel/library/library.lock.json"))
        #expect(lock.libraries.first?.label == "acme")
        #expect(lock.libraries.first?.tag == "v2.1.0")
        #expect(lock.libraries.first?.files["acme.lib"]
            == LibraryLock.checksum("library \"acme\" { }\n"))
    }

    @Test func replacesTheEntryWhenTheProjectAlreadyHoldsThatRepository() throws {
        let (projects, fetcher, add) = aProject()
        fetcher.put(
            ["acme.lib": "library \"acme\" { name = \"Acme\" }\n"],
            repository: "github.com/acme/threat-elements",
            tag: "v2.2.0"
        )
        _ = add.execute(AddLibraryRequest(root: "/work", repository: "github.com/acme/threat-elements", tag: "v2.1.0"))

        _ = add.execute(AddLibraryRequest(root: "/work", repository: "github.com/acme/threat-elements", tag: "v2.2.0"))

        let lock = LibraryLock.read(try projects.read(path: "/work/threatmodel/library/library.lock.json"))
        #expect(lock.libraries.count == 1)
        #expect(lock.libraries.first?.tag == "v2.2.0")
    }

    @Test func refusesAFileThatDoesNotParse() {
        let projects = InMemoryProject()
        projects.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")
        let fetcher = FakeLibraryFetcher()
        fetcher.put(["acme.lib": "library \"acme\" { technology }"], repository: "r", tag: "v1")
        let add = AddLibrary(projects: projects, fetcher: fetcher, sources: HclLibrarySource())

        let response = add.execute(AddLibraryRequest(root: "/work", repository: "r", tag: "v1"))

        guard case .refused(let reason) = response else {
            Issue.record("a library that does not parse was added")
            return
        }
        #expect(reason.contains("acme.lib"))
        #expect(projects.text(at: "/work/threatmodel/library/acme.lib") == nil)
    }

    @Test func saysWhatTheFetchSaid() {
        let (_, _, add) = aProject()

        let response = add.execute(AddLibraryRequest(root: "/work", repository: "github.com/acme/threat-elements", tag: "v9"))

        guard case .refused(let reason) = response else {
            Issue.record("an unknown tag was added")
            return
        }
        #expect(reason.contains("v9"))
    }
}
```

Write the matching tests for `UpdateLibraries` in the same file: updating every
library at its recorded tag, updating one named library, and refusing when the
project holds no lock file.

- [ ] **Step 2: Run the tests and watch them fail**

Run: `cd ThreatModelKit && swift test --filter AddLibraryTests`
Expected: FAIL, `cannot find 'AddLibrary' in scope`.

- [ ] **Step 3: Write the two use cases**

`AddLibrary.execute` in order: discover the layout; fetch; read every file with
`sources.read` and refuse the first that has errors, naming the file; refuse when
two fetched files carry the same label; write each file to
`ProjectConvention.path(libraryDirectory, name)`; read the lock file when it is
there; replace or append the entry keyed by the label, recording the repository,
the tag and the checksum of each file; write the lock file.

`UpdateLibraries.execute` reads the lock file, then for each entry (or the one
named) calls `AddLibrary` with the recorded repository and tag.

- [ ] **Step 4: Run the tests and watch them pass**

Run: `cd ThreatModelKit && swift test --filter Library`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/AddLibrary.swift \
        ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/UpdateLibraries.swift \
        ThreatModelKit/Tests/UnitTests/AddLibraryTests.swift
git -c commit.gpgsign=false commit -m "feat: add and update a library"
```

---

### Task 5: removing, verifying and listing

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/RemoveLibrary.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/VerifyLibraries.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/ListLibraries.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/ListOutdatedLibraries.swift`
- Test: `ThreatModelKit/Tests/UnitTests/RemoveLibraryTests.swift`
- Test: `ThreatModelKit/Tests/UnitTests/VerifyLibrariesTests.swift`

**Interfaces:**
- Produces:
  `enum RemoveLibraryResponse { case removed(files: [String]); case inUse(systems: [String]); case noSuchLibrary; case cannotWrite(reason: String) }`,
  `struct RemoveLibraryRequest { let root: String; let label: String; let isForced: Bool }`,
  `struct VerifyLibrariesRequest { let root: String }`,
  `enum VerifyLibrariesResponse { case verified(matched: [String], differed: [String]); case notAProject(reason: String) }`,
  `struct ListedLibrary: Equatable, Sendable { let label: String; let name: String; let repository: String; let tag: String; let matchesLock: Bool }`,
  `struct OutdatedLibrary: Equatable, Sendable { let label: String; let tag: String; let newestTag: String?; let reason: String? }`

**The in-use rule.** `RemoveLibrary` reads every `.arch` file in the project
with the architecture gateway and looks for a component whose `technology`
starts with `<label>-`. It returns `.inUse` naming those systems unless
`isForced`.

- [ ] **Step 1: Write the failing tests**

```swift
@Suite("Removing a library")
struct RemoveLibraryTests {
    private func aProject(usingTheLibrary: Bool) -> (InMemoryProject, RemoveLibraryUseCase) {
        let projects = InMemoryProject()
        projects.put(
            usingTheLibrary
                ? "system \"Payments\" { component \"i\" { technology = \"acme-cribl-stream\" } }"
                : "system \"Payments\" { component \"i\" { technology = \"aws-ec2\" } }",
            at: "/work/threatmodel/payments.arch"
        )
        projects.put("library \"acme\" { }\n", at: "/work/threatmodel/library/acme.lib")
        projects.put(
            LibraryLock(libraries: [
                LockedLibrary(label: "acme", repository: "r", tag: "v1", files: ["acme.lib": "x"])
            ]).written(),
            at: "/work/threatmodel/library/library.lock.json"
        )
        return (
            projects,
            RemoveLibrary(projects: projects, architectureSources: HclArchitectureSource())
        )
    }

    @Test func deletesTheFilesAndTheLockEntry() throws {
        let (projects, remove) = aProject(usingTheLibrary: false)

        let response = remove.execute(
            RemoveLibraryRequest(root: "/work", label: "acme", isForced: false)
        )

        #expect(response == .removed(files: ["acme.lib"]))
        #expect(projects.text(at: "/work/threatmodel/library/acme.lib") == nil)
        #expect(LibraryLock.read(try projects.read(path: "/work/threatmodel/library/library.lock.json"))
            .libraries.isEmpty)
    }

    @Test func refusesWhileASystemNamesIt() {
        let (_, remove) = aProject(usingTheLibrary: true)

        #expect(
            remove.execute(RemoveLibraryRequest(root: "/work", label: "acme", isForced: false))
                == .inUse(systems: ["payments"])
        )
    }

    @Test func removesItAnywayWhenForced() {
        let (projects, remove) = aProject(usingTheLibrary: true)

        _ = remove.execute(RemoveLibraryRequest(root: "/work", label: "acme", isForced: true))

        #expect(projects.text(at: "/work/threatmodel/library/acme.lib") == nil)
    }

    @Test func saysSoWhenTheProjectHoldsNoSuchLibrary() {
        let (_, remove) = aProject(usingTheLibrary: false)

        #expect(
            remove.execute(RemoveLibraryRequest(root: "/work", label: "beta", isForced: false))
                == .noSuchLibrary
        )
    }
}
```

```swift
@Suite("Verifying the libraries")
struct VerifyLibrariesTests {
    private let library = "library \"acme\" { }\n"

    /// A project holding one library, its lock entry, and whatever the caller
    /// wants the file on disk to say.
    private func aProject(fileSays: String?) -> VerifyLibrariesUseCase {
        let projects = InMemoryProject()
        projects.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")
        if let fileSays {
            projects.put(fileSays, at: "/work/threatmodel/library/acme.lib")
        }
        projects.put(
            LibraryLock(libraries: [
                LockedLibrary(
                    label: "acme",
                    repository: "r",
                    tag: "v1",
                    files: ["acme.lib": LibraryLock.checksum(library)]
                )
            ]).written(),
            at: "/work/threatmodel/library/library.lock.json"
        )
        return VerifyLibraries(projects: projects)
    }

    @Test func saysTheFilesMatchTheLockFile() {
        let response = aProject(fileSays: library).execute(
            VerifyLibrariesRequest(root: "/work")
        )

        #expect(response == .verified(matched: ["acme.lib"], differed: []))
    }

    @Test func saysWhichFileDiffers() {
        let response = aProject(fileSays: "library \"acme\" { name = \"Changed\" }\n")
            .execute(VerifyLibrariesRequest(root: "/work"))

        #expect(response == .verified(matched: [], differed: ["acme.lib"]))
    }

    @Test func saysWhichFileIsMissing() {
        let response = aProject(fileSays: nil).execute(
            VerifyLibrariesRequest(root: "/work")
        )

        #expect(response == .verified(matched: [], differed: ["acme.lib"]))
    }

    @Test func saysNothingWhenTheProjectHoldsNoLockFile() {
        let projects = InMemoryProject()
        projects.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")

        let response = VerifyLibraries(projects: projects).execute(
            VerifyLibrariesRequest(root: "/work")
        )

        #expect(response == .verified(matched: [], differed: []))
    }
}
```

- [ ] **Step 2: Run the tests and watch them fail**

Run: `cd ThreatModelKit && swift test --filter RemoveLibraryTests`
Expected: FAIL.

- [ ] **Step 3: Write the four use cases**

`ListLibraries` joins the lock file with `LoadLibraries`'s labels and display
names, and calls `VerifyLibraries` for the match column.
`ListOutdatedLibraries` reads each entry's tags through `LibraryFetching.tags`,
takes the last tag that sorts after the recorded one, and records a reason when
the tags cannot be read.

- [ ] **Step 4: Run the tests and watch them pass**

Run: `cd ThreatModelKit && swift test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/RemoveLibrary.swift \
        ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/VerifyLibraries.swift \
        ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/ListLibraries.swift \
        ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/ListOutdatedLibraries.swift \
        ThreatModelKit/Tests/UnitTests/RemoveLibraryTests.swift \
        ThreatModelKit/Tests/UnitTests/VerifyLibrariesTests.swift
git -c commit.gpgsign=false commit -m "feat: remove, verify and list a project's libraries"
```

---

### Task 6: the `library` verbs

**Files:**
- Modify: `ThreatModelKit/Sources/CommandLineApplication/CommandLineApplication.swift`
- Modify: `ThreatModelKit/Sources/CommandLineApplication/CommandLineDependencies.swift`
- Test: `ThreatModelKit/Tests/UnitTests/CommandLineApplicationTests.swift`

**Interfaces:**
- Produces: `CommandLineApplication.ExitCode.fetchFailed = 4`, and the verb
  `library` with the six operations.
- `CommandLineApplication.init` gains `fetcher: LibraryFetching = GitLibraryFetcher()`.

- [ ] **Step 1: Write the failing tests**

```swift
@Suite("The library verbs")
struct LibraryVerbTests {
    private func anApplication() -> (InMemoryProject, FakeLibraryFetcher, CommandLineApplication) {
        let projects = InMemoryProject()
        projects.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")
        let fetcher = FakeLibraryFetcher()
        fetcher.put(
            ["acme.lib": "library \"acme\" { }\n"],
            repository: "github.com/acme/threat-elements",
            tag: "v2.1.0"
        )
        return (
            projects,
            fetcher,
            CommandLineApplication(
                projects: projects,
                fetcher: fetcher,
                catalogue: { FakeTechnologyCatalogue() }
            )
        )
    }

    @Test func addsALibrary() throws {
        let (projects, _, application) = anApplication()
        var printed: [String] = []

        let code = application.run(
            arguments: ["threatmodeller", "library", "add", "github.com/acme/threat-elements", "v2.1.0", "/work"],
            output: { printed.append($0) }
        )

        #expect(code == 0)
        #expect(projects.text(at: "/work/threatmodel/library/acme.lib") != nil)
        #expect(printed.contains { $0.contains("acme") })
    }

    @Test func exitsFourWhenTheFetchFails() {
        let (_, _, application) = anApplication()
        var printed: [String] = []

        let code = application.run(
            arguments: ["threatmodeller", "library", "add", "github.com/acme/threat-elements", "v9", "/work"],
            output: { printed.append($0) }
        )

        #expect(code == 4)
    }

    @Test func verifiesWhatItAdded() {
        let (_, _, application) = anApplication()
        _ = application.run(
            arguments: ["threatmodeller", "library", "add", "github.com/acme/threat-elements", "v2.1.0", "/work"],
            output: { _ in }
        )
        var printed: [String] = []

        let code = application.run(
            arguments: ["threatmodeller", "library", "verify", "/work"],
            output: { printed.append($0) }
        )

        #expect(code == 0)
    }

    @Test func exitsOneWhenAFileDoesNotMatchTheLockFile() {
        let (projects, _, application) = anApplication()
        _ = application.run(
            arguments: ["threatmodeller", "library", "add", "github.com/acme/threat-elements", "v2.1.0", "/work"],
            output: { _ in }
        )
        projects.put("library \"acme\" { name = \"Changed\" }\n", at: "/work/threatmodel/library/acme.lib")
        var printed: [String] = []

        let code = application.run(
            arguments: ["threatmodeller", "library", "verify", "/work"],
            output: { printed.append($0) }
        )

        #expect(code == 1)
        #expect(printed.contains { $0.contains("acme.lib") })
    }

    @Test func refusesToRemoveALibraryASystemNames() {
        let (projects, _, application) = anApplication()
        _ = application.run(
            arguments: ["threatmodeller", "library", "add", "github.com/acme/threat-elements", "v2.1.0", "/work"],
            output: { _ in }
        )
        projects.put(
            "system \"Payments\" { component \"i\" { technology = \"acme-thing\" } }",
            at: "/work/threatmodel/payments.arch"
        )
        var printed: [String] = []

        let code = application.run(
            arguments: ["threatmodeller", "library", "remove", "acme", "/work"],
            output: { printed.append($0) }
        )

        #expect(code == 1)
        #expect(printed.contains { $0.contains("payments") })
    }

    @Test func namesTheVerbsInTheUsageText() {
        let (_, _, application) = anApplication()
        var printed: [String] = []

        _ = application.run(arguments: ["threatmodeller", "help"], output: { printed.append($0) })

        let usage = printed.joined(separator: "\n")
        #expect(usage.contains("library add"))
        #expect(usage.contains("library verify"))
    }
}
```

- [ ] **Step 2: Run the tests and watch them fail**

Run: `cd ThreatModelKit && swift test --filter LibraryVerbTests`
Expected: FAIL, `extra argument 'fetcher' in call`.

- [ ] **Step 3: Write the verb**

Add `case fetchFailed = 4` to `ExitCode`. Add `library` to the verb switch, which
reads the operation from the next flagless word and calls the matching use case.
Add the six lines and the option to `Self.usage`. Keep the printed text one line
per library, in the shape `<label>  <tag>  <repository>  <matches | differs>`.

- [ ] **Step 4: Run the tests and watch them pass**

Run: `cd ThreatModelKit && swift test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/CommandLineApplication \
        ThreatModelKit/Tests/UnitTests/CommandLineApplicationTests.swift
git -c commit.gpgsign=false commit -m "feat: manage a library from the command line"
```

---

### Task 7: the documents

**Files:**
- Modify: `README.md`
- Modify: `docs/LANGUAGE.md`

- [ ] **Step 1: Write the verbs into `README.md`**

Add a "Sharing a library" section under the executable: what a library
repository holds, the six verbs with a one-line description each, the lock file,
exit code 4, and the sentence that this application holds no credential and runs
the user's own `git`.

- [ ] **Step 2: Write the vendoring rules into `docs/LANGUAGE.md`**

Add to the library language section: where a `.lib` file lives, that
`library.lock.json` pins it, and that the label is the key.

- [ ] **Step 3: Run both suites**

Run: `cd ThreatModelKit && swift test`
Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/LANGUAGE.md
git -c commit.gpgsign=false commit -m "docs: document the library verbs"
```
