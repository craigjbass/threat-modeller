# Milestone 10A: the architecture language — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A user opens a project directory and sees the diagram and the threats
that the committed `.arch` file describes.

**Architecture:** A new package target `ArchitectureDSL` holds the lexer, the
parser and the writer. It produces plain value trees defined in the core, which
new use cases turn into a `ThreatModel`. A `ProjectSourceGateway` finds the files
by convention. The application gains a project window; the executable gains
`format`.

**Tech Stack:** Swift 6.3, SwiftPM, Swift Testing, SwiftUI (application target
only), Foundation only in the package.

**Spec:** `docs/superpowers/specs/2026-09-08-code-first-dsl-design.md`

## Global Constraints

- Swift 6.3, `swift-tools-version: 6.2`, `platforms: [.macOS(.v26)]`.
- **No package target may import AppKit, CoreGraphics, SwiftUI, CoreText or
  PDFKit.** Foundation only.
- No third-party dependency. The repository has none beyond the vendored
  catalogue.
- Swift Testing (`@Test`, `#expect`, `#require`) in the package; XCTest in the
  application targets.
- Domain objects never cross the use case boundary. A use case takes a request
  value and returns a response value.
- A gateway gets a shared contract in `TestSupport`, run against the fake and the
  real implementation.
- Every task ends with the package suite green and one commit.
- Commits are unsigned: `git -c commit.gpgsign=false commit`.
- Prose in code comments, commits and documents follows ASD-STE100.

---

### Task 1: the `ArchitectureDSL` target and its lexer

**Files:**
- Modify: `ThreatModelKit/Package.swift`
- Create: `ThreatModelKit/Sources/ArchitectureDSL/Lexer.swift`
- Create: `ThreatModelKit/Sources/ArchitectureDSL/Token.swift`
- Test: `ThreatModelKit/Tests/UnitTests/LexerTests.swift`

**Interfaces:**
- Produces: `struct Token { let kind: TokenKind; let text: String; let line: Int; let column: Int }`,
  `enum TokenKind { case identifier, string, number, boolean, leftBrace, rightBrace,
  leftBracket, rightBracket, equals, arrow, comma, comment, endOfFile }`,
  `struct Lexer { init(_ text: String); func scan() -> [Token] }`

- [ ] **Step 1: Write the failing test**

```swift
@Test func readsABlockHeaderAsTokens() {
    let tokens = Lexer("system \"Payments\" {").scan()

    #expect(tokens.map(\.kind) == [.identifier, .string, .leftBrace, .endOfFile])
    #expect(tokens[1].text == "Payments")
    #expect(tokens[2].column == 20)
}
```

Cases to cover: an attribute (`kind = "private"`), a number, `true`/`false`, a
list (`["a", "b"]`), a comment to end of line, an arrow (`a -> b`), a string with
an escaped quote, a newline advancing the line number, and an unterminated
string producing a token of kind `endOfFile` after the fault is recorded.

- [ ] **Step 2: Run and see it fail.** `cd ThreatModelKit && swift test --filter LexerTests`
- [ ] **Step 3: Add the target to `Package.swift`** with
      `.target(name: "ArchitectureDSL", dependencies: ["ThreatModelKit"])`, add it
      to the `UnitTests` dependencies, and write `Token.swift` and `Lexer.swift`.
      The lexer never throws: an unterminated string is a fault the parser reads
      from `Lexer.faults`.
- [ ] **Step 4: Run the suite.** `swift test`
- [ ] **Step 5: Commit.** `feat: read the architecture language as tokens`

---

### Task 2: the source value trees and the ports

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ArchitectureSource.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/Diagnostic.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/gateway/ArchitectureSourceGateway.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ArchitectureSourceTests.swift`

**Interfaces:**
- Produces:

```swift
public struct ArchitectureSource: Equatable, Sendable {
    public let systemName: String
    public let catalogueTag: String?
    public let technologies: [SourceTechnology]
    public let zones: [SourceZone]
    /// Components declared outside every zone.
    public let components: [SourceComponent]
    public let flows: [SourceFlow]
}

public struct SourceTechnology: Equatable, Sendable {
    public let id: String, name: String, category: String, description: String
    public let threatIds: [String], encrypts: Bool
}

public struct SourceZone: Equatable, Sendable {
    public let id: String, kind: String, network: String
    public let name: String?
    public let reducesRisk: Bool, reducesRiskBy: Int?
    public let components: [SourceComponent]
}

public struct SourceComponent: Equatable, Sendable {
    public let id: String, technologyId: String
    public let name: String?, data: String, raisesThreats: Bool
}

public struct SourceFlow: Equatable, Sendable {
    public let sourceId: String, targetId: String
}

public struct Diagnostic: Equatable, Sendable {
    public enum Severity: String, Equatable, Sendable { case error, warning }
    public let severity: Severity
    public let line: Int, column: Int
    public let message: String
    /// `file:line:column: severity: message`
    public func described(in fileName: String) -> String
}

public struct ArchitectureRead: Equatable, Sendable {
    public let source: ArchitectureSource?
    public let diagnostics: [Diagnostic]
    public var hasErrors: Bool { diagnostics.contains { $0.severity == .error } }
}

public protocol ArchitectureSourceGateway: Sendable {
    func read(_ text: String) -> ArchitectureRead
    func write(_ source: ArchitectureSource) -> String
}
```

- [ ] **Step 1: Write the failing test** for `described(in:)` and `hasErrors`.

```swift
@Test func namesTheFileTheLineAndTheColumn() {
    let diagnostic = Diagnostic(severity: .error, line: 12, column: 5, message: "no such thing")

    #expect(diagnostic.described(in: "payments.arch")
        == "payments.arch:12:5: error: no such thing")
}
```

- [ ] **Step 2: Run and see it fail.**
- [ ] **Step 3: Write the value types and the port.**
- [ ] **Step 4: Run the suite.**
- [ ] **Step 5: Commit.** `feat: state what an architecture source is`

---

### Task 3: the parser

**Files:**
- Create: `ThreatModelKit/Sources/ArchitectureDSL/ArchitectureParser.swift`
- Create: `ThreatModelKit/Sources/ArchitectureDSL/HclArchitectureSource.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ArchitectureParserTests.swift`

**Interfaces:**
- Consumes: `Lexer`, `ArchitectureSource`, `Diagnostic`, `ArchitectureRead`.
- Produces: `public struct HclArchitectureSource: ArchitectureSourceGateway { public init() }`

- [ ] **Step 1: Write the failing tests.** One per rule of spec §3.2 and §3.4:

```swift
@Test func readsASystemWithOneZoneAndOneComponent() throws {
    let read = HclArchitectureSource().read("""
    system "Payments" {
      zone "app" {
        kind = "private"
        component "api" { technology = "aws-ec2" }
      }
      flow api -> api2
    }
    """)
    ...
}
```

Cover: defaults applied when an attribute is absent; `threats = false`;
`reduces_risk_by`; a top-level component; a technology block; a duplicate id;
a flow naming an unknown component; a self flow; a duplicate flow pair; a value
outside a vocabulary; a missing required attribute; an unknown attribute; and
that every fault carries the right line and column.

- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Write the parser.** Recursive descent over the token list. It
      never throws and never stops at the first fault: on an unexpected token it
      records a diagnostic and skips to the next block boundary.
- [ ] **Step 4: Run the suite.**
- [ ] **Step 5: Commit.** `feat: parse the architecture language`

---

### Task 4: the writer and the round trip

**Files:**
- Create: `ThreatModelKit/Sources/ArchitectureDSL/ArchitectureWriter.swift`
- Create: `ThreatModelKit/Tests/UnitTests/Golden/payments.arch`
- Test: `ThreatModelKit/Tests/UnitTests/ArchitectureWriterTests.swift`

**Interfaces:**
- Produces: `HclArchitectureSource.write(_:) -> String`.

- [ ] **Step 1: Write the failing tests.**

```swift
@Test func writesWhatItRead() throws {
    let gateway = HclArchitectureSource()
    let text = try goldenText()

    let once = try #require(gateway.read(text).source)
    let twice = try #require(gateway.read(gateway.write(once)).source)

    #expect(once == twice)
}

@Test func reproducesACanonicalFileByteForByte() throws {
    let gateway = HclArchitectureSource()
    let text = try goldenText()

    #expect(gateway.write(try #require(gateway.read(text).source)) == text)
}
```

The golden file is the canonical shape: two-space indentation, attributes
aligned on the equals sign inside a block, a blank line between blocks, blocks
in the order technologies, zones, components, flows.

- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Write the writer**, and write the golden file to match it.
- [ ] **Step 4: Run the suite.**
- [ ] **Step 5: Commit.** `feat: write the architecture language back`

---

### Task 5: the gateway contract

**Files:**
- Create: `ThreatModelKit/Sources/TestSupport/ArchitectureSourceGatewayContract.swift`
- Create: `ThreatModelKit/Sources/TestSupport/FakeArchitectureSource.swift`
- Test: `ThreatModelKit/Tests/GatewayContractTests/ArchitectureSourceGatewayContractTests.swift`
- Modify: `ThreatModelKit/Package.swift` (TestSupport and the contract tests depend on `ArchitectureDSL`)

**Interfaces:**
- Produces: `public func verifyArchitectureSourceGatewayContract(_ make: () -> ArchitectureSourceGateway)`,
  `public struct FakeArchitectureSource: ArchitectureSourceGateway`.

The contract states: a valid source reads without error; writing then reading
gives the same value tree; an empty text reads as one error; a fault carries a
line greater than zero and a column greater than zero.

- [ ] **Step 1: Write the contract and the two tests that run it.**
- [ ] **Step 2: Run and see the fake fail.**
- [ ] **Step 3: Write the fake** — it reads a tiny two-line format, enough to
      honour the contract without a parser.
- [ ] **Step 4: Run the suite.**
- [ ] **Step 5: Commit.** `test: state what an architecture source gateway owes`

---

### Task 6: `LayOutModel`

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/LayOutModel.swift`
- Test: `ThreatModelKit/Tests/UnitTests/LayOutModelTests.swift`

**Interfaces:**
- Produces:

```swift
public struct LaidOutComponent: Equatable, Sendable { public let id: String, x: Double, y: Double }
public struct LaidOutZone: Equatable, Sendable {
    public let id: String, x: Double, y: Double, width: Double, height: Double
}
public struct LayOutModelResponse: Equatable, Sendable {
    public let components: [LaidOutComponent], zones: [LaidOutZone]
}
public struct LayOutModel: LayOutModelUseCase {
    public init()
    public func execute(_ request: LayOutModelRequest) -> LayOutModelResponse
}
```

`LayOutModelRequest` carries the `ArchitectureSource`.

- [ ] **Step 1: Write the failing tests** asserting coordinates for: one
      component outside a zone; four components in one zone as a two-by-two
      grid; two zones side by side; a zone with no components; and a row that
      wraps past 2400 points. Constants from spec §7: node 160 × 72, gaps 60 and
      48, zone padding 40, zone header 40.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Write the use case.**
- [ ] **Step 4: Run the suite.**
- [ ] **Step 5: Commit.** `feat: lay a diagram out from declaration order`

---

### Task 7: `ImportArchitecture`

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/ImportArchitecture.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`
- Modify: `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`
- Modify: `threatmodeller/Dependencies.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ImportArchitectureTests.swift`

**Interfaces:**
- Consumes: `ArchitectureSourceGateway`, `LayOutModel`, `ThreatModelGateway`, `TechnologyCatalogue`.
- Produces:

```swift
public enum ImportArchitectureResponse: Equatable, Sendable {
    case imported(name: String, warnings: [Diagnostic])
    case refused(diagnostics: [Diagnostic])
}
```

Rules: every `technology` block becomes a custom technology; every component
becomes a `Component` with the id the file gave it; every zone becomes a `Zone`
at the laid-out rectangle; every flow becomes a `Connection` with id
`"<source>-><target>"`; a technology neither the catalogue nor the file holds is
a **warning**, and the component is still placed. The whole import is one change
on the gateway, so one undo takes it back.

- [ ] **Step 1: Write the failing tests.** Cover the mapping, the one-undo rule,
      the warning case, and that a file with an error changes nothing.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Write the use case and vend it from all three roots.**
- [ ] **Step 4: Run the suite.**
- [ ] **Step 5: Commit.** `feat: draw what an architecture file describes`

---

### Task 8: `ExportArchitecture`

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/ExportArchitecture.swift`
- Modify: the three composition roots
- Test: `ThreatModelKit/Tests/UnitTests/ExportArchitectureTests.swift`
- Test: `ThreatModelKit/Tests/AcceptanceTests/ModellingFromSourceTests.swift`

**Interfaces:**
- Produces: `ExportArchitectureResponse { public let text: String; public let fileName: String }`

Rules: structure only, no coordinates; a component's zone is decided by the
containment rule, not by anything stored; a custom technology is written as a
`technology` block; the catalogue tag is written from the model's stamp.

- [ ] **Step 1: Write the failing tests**, including the acceptance test: import
      text, export it, and read the two value trees as equal.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Write the use case.**
- [ ] **Step 4: Run the suite.**
- [ ] **Step 5: Commit.** `feat: write a model back as an architecture file`

---

### Task 9: the project convention

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ProjectLayout.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/gateway/ProjectSourceGateway.swift`
- Create: `ThreatModelKit/Sources/FileGateways/FileSystemProject.swift`
- Create: `ThreatModelKit/Sources/TestSupport/InMemoryProject.swift`
- Create: `ThreatModelKit/Sources/TestSupport/ProjectSourceGatewayContract.swift`
- Test: `ThreatModelKit/Tests/GatewayContractTests/ProjectSourceGatewayContractTests.swift`

**Interfaces:**
- Produces:

```swift
public struct ProjectSystem: Equatable, Sendable {
    public let name: String              // the file stem
    public let architecturePath: String
    public let controlsPath: String      // may not exist yet
    public let reportPath: String
}

public struct ProjectLayout: Equatable, Sendable {
    public let root: String
    public let directory: String         // "<root>/threatmodel" or "<root>"
    public let systems: [ProjectSystem]  // by name, sorted
}

public enum ProjectError: Error, Equatable, Sendable {
    case notADirectory(path: String)
    case cannotRead(path: String, reason: String)
    case cannotWrite(path: String, reason: String)
}

public protocol ProjectSourceGateway: Sendable {
    func discover(root: String) throws -> ProjectLayout
    func read(path: String) throws -> String
    func write(_ text: String, to path: String) throws
    func exists(path: String) -> Bool
}
```

The contract states: `threatmodel/` wins over the root; systems pair by stem;
sorted by name; a root with nothing gives an empty `systems`; a write then a read
gives the same text; a read of a missing file throws `cannotRead`.

- [ ] **Step 1: Write the contract and the two tests that run it** (the fake, and
      the real one over a temporary directory).
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Write `InMemoryProject` and `FileSystemProject`.**
- [ ] **Step 4: Run the suite.**
- [ ] **Step 5: Commit.** `feat: find a project's files by convention`

---

### Task 10: the project use cases

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/OpenProject.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/OpenSystem.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/SaveSystem.swift`
- Modify: the three composition roots
- Test: `ThreatModelKit/Tests/UnitTests/ProjectUseCaseTests.swift`
- Test: `ThreatModelKit/Tests/AcceptanceTests/KeepingAProjectInGitTests.swift`

**Interfaces:**
- Produces:

```swift
public enum OpenProjectResponse: Equatable, Sendable {
    case opened(systems: [String], directory: String)
    case notAProject(reason: String)
}
public enum OpenSystemResponse: Equatable, Sendable {
    case opened(name: String, warnings: [Diagnostic])
    case refused(diagnostics: [Diagnostic])
    case noSuchSystem
}
public enum SaveSystemResponse: Equatable, Sendable {
    case saved(architecturePath: String)
    case noSuchSystem
    case cannotWrite(reason: String)
}
```

`OpenProject` holds the layout in the gateway-backed session state by returning
it; `OpenSystem` reads the architecture file and calls `ImportArchitecture`;
`SaveSystem` calls `ExportArchitecture` and writes the text back.

- [ ] **Step 1: Write the failing tests**, including the acceptance test: a
      project in memory, opened, a component added, saved, and the text on disk
      read again showing the new component.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Write the three use cases and vend them.**
- [ ] **Step 4: Run the suite.**
- [ ] **Step 5: Commit.** `feat: open and save a system in a project`

---

### Task 11: the executable and `format`

**Files:**
- Create: `ThreatModelKit/Sources/CommandLineApplication/Verbs.swift`
- Create: `ThreatModelKit/Sources/CommandLineApplication/CommandLineApplication.swift`
- Create: `ThreatModelKit/Sources/threatmodeller-cli/main.swift`
- Modify: `ThreatModelKit/Package.swift`
- Create: `ThreatModelKit/Sources/CatalogueGateways/CatalogueLocation.swift`
- Modify: `ThreatModelKit/Sources/CatalogueGateways/LibraryResources.swift`
- Test: `ThreatModelKit/Tests/UnitTests/CommandLineApplicationTests.swift`

**Interfaces:**
- Produces:

```swift
public struct CommandLineApplication {
    public init(project: ProjectSourceGateway, architecture: ArchitectureSourceGateway)
    /// Returns the exit code. Everything it prints goes to `output`.
    public func run(arguments: [String], output: (String) -> Void) -> Int32
}
```

Exit codes from spec §9: `0`, `1`, `2`, `3`. `format` reads every `.arch` in the
project and writes it back canonically. `--catalogue <dir>` and
`THREATMODELLER_CATALOGUE` name a catalogue directory; `LibraryResources` reads
that directory when it is set and `Bundle.module` when it is not.

- [ ] **Step 1: Write the failing tests.** `format` rewrites a badly formatted
      file; `format` on a file with an error returns 2 and prints the diagnostic
      in `file:line:column: error: message` shape; an unknown verb returns 2 and
      prints the usage; no argument means the working directory.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Write the library target, the executable target and the catalogue
      location.** `main.swift` is `exit(CommandLineApplication(...).run(arguments:
      CommandLine.arguments, output: { print($0) }))`.
- [ ] **Step 4: Run the suite, then `swift run threatmodeller format` over a
      scratch project.**
- [ ] **Step 5: Commit.** `feat: add the threatmodeller executable and format`

---

### Task 12: Linux

**Files:**
- Create: `.github/workflows/linux.yml`
- Create: `scripts/build-linux.sh`
- Modify: `ThreatModelKit/Package.swift` if a target needs to be excluded

**Interfaces:** none.

The workflow runs on `ubuntu-latest` with the Swift 6.3 image: `swift build`,
`swift test`, then `swift run threatmodeller check` — which does not exist until
Milestone 10B, so 10A runs `format` over the sample project and asserts exit 0.
`scripts/build-linux.sh` installs the static Linux SDK and builds both
architectures.

- [ ] **Step 1: Write the workflow and the script.**
- [ ] **Step 2: Run `swift build 2>&1 | grep -c 'import AppKit'` over the package
      sources as a local proxy**, and read `Package.swift` to confirm no package
      target depends on an application target.
- [ ] **Step 3: Commit.** `ci: build and test the package on Linux`

---

### Task 13: the project window

**Files:**
- Create: `threatmodeller/project/ProjectSession.swift`
- Create: `threatmodeller/project/ProjectWindow.swift`
- Create: `threatmodeller/project/DiagnosticsSheet.swift`
- Modify: `threatmodeller/threatmodellerApp.swift`
- Modify: `threatmodeller/ThreatModelCommands.swift`
- Modify: `threatmodeller/Dependencies.swift`
- Modify: `threatmodeller/Info.plist` (the two exported type declarations)
- Modify: the target's entitlements (`com.apple.security.files.bookmarks.app-scope`)
- Test: `threatmodellerTests/ProjectSessionTests.swift`

**Interfaces:**
- Consumes: `OpenProject`, `OpenSystem`, `SaveSystem`, `ImportArchitecture`.
- Produces: `@MainActor @Observable final class ProjectSession` with
  `systems: [String]`, `chosenSystem: String?`, `diagnostics: [Diagnostic]`,
  `open(root:)`, `choose(_:)`, `save()`.

The window reuses the three columns. *File ▸ Open Project…* runs an open panel
with `canChooseDirectories = true`. A `-project <path>` launch argument opens a
project at launch, which is how the interface journey drives it.

- [ ] **Step 1: Write the failing tests** over `ProjectSession` with an
      `InMemoryProject`: opening lists the systems; choosing one draws it;
      saving writes the text back; a file with an error fills `diagnostics` and
      draws nothing.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Write the session, the window, the sheet, the menu command, the
      launch argument, the type declarations and the entitlement.**
- [ ] **Step 4: Run the application test target.**
- [ ] **Step 5: Commit.** `feat: open a project directory in the application`

---

### Task 14: the journey

**Files:**
- Modify: `threatmodellerUITests/threatmodellerUITests.swift`
- Create: `docs/superpowers/specs/MILESTONE-10B-CARRY-FORWARD.md`

**Interfaces:** none.

- [ ] **Step 1: Write the journey.** The test writes a project into a temporary
      directory, launches with `-project <path>`, waits for the systems picker,
      and asserts a node and a threat the file describes.
- [ ] **Step 2: Run the whole test plan.** `xcodebuild test … -destination 'platform=macOS'`
- [ ] **Step 3: Write the carry-forward.**
- [ ] **Step 4: Commit and push.** `test: walk a project directory in the interface`

---

## Self-review

- **Spec coverage.** §3 Tasks 1, 3, 4. §4 is Milestone 10B. §5 is 10B. §6.1–6.3
  Tasks 2, 3, 5. §6.4 Tasks 6, 7, 8, 10. §6.5 is 10B, except that nothing in 10A
  changes `ThreatModel`. §7 Task 6. §8 Tasks 9, 10, 13. §9 Task 11. §10 Task 12.
  §11 Tasks 5, 9, and the acceptance tests in 8 and 10, and Task 14.
- **Placeholders.** None: every task names its files, its types and its rules.
- **Type consistency.** `ArchitectureSource` and its members are defined once in
  Task 2 and used unchanged in Tasks 3, 4, 6, 7 and 8. `ProjectLayout` and
  `ProjectSystem` are defined in Task 9 and used in Tasks 10, 11 and 13.
  `Diagnostic` is defined in Task 2 and used in Tasks 3, 7, 10, 11 and 13.
