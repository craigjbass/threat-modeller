# Milestone 11A: the library language and the merge — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A user opens a project that holds `threatmodel/library/acme.lib` and
sees the library's technologies in the palette and its threats in the sidebar.

**Architecture:** A third language in `ArchitectureDSL` reads a `.lib` file into
a `LibrarySource` value tree. `LoadLibraries` turns those trees into `Library`
values, prefixing every id with the library's label. `MergedCatalogue`
implements the existing `TechnologyCatalogue` port over the bundled catalogue
and a `LibraryStore`, so nothing downstream changes.

**Tech Stack:** Swift 6.3, SwiftPM, Swift Testing, SwiftUI (application target
only), Foundation only in the package.

**Spec:** `docs/superpowers/specs/2026-09-09-shared-element-library-design.md`

## Global Constraints

- Swift 6.3, `swift-tools-version: 6.2`, `platforms: [.macOS(.v26)]`.
- **No package target may import AppKit, CoreGraphics, SwiftUI, CoreText or
  PDFKit.** Foundation only.
- No third-party dependency.
- Swift Testing (`@Test`, `#expect`, `#require`) in the package; Swift Testing
  in the application test target as well.
- Domain objects never cross the use case boundary. A use case takes a request
  value and returns a response value.
- A gateway gets a shared contract in `TestSupport`, run against the fake and
  the real implementation.
- Every task ends with `cd ThreatModelKit && swift test` green and one commit.
- Commits are unsigned: `git -c commit.gpgsign=false commit`.
- Prose in code comments, commits and documents follows ASD-STE100.
- The vocabularies `severity`, `stride` and `category` are taxonomy data, so the
  parser accepts any string and `LoadLibraries` reports a value the taxonomy
  does not hold.

---

### Task 1: the library value tree and the parser's `library` block

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/LibrarySource.swift`
- Create: `ThreatModelKit/Sources/ArchitectureDSL/LibraryParser.swift`
- Test: `ThreatModelKit/Tests/UnitTests/LibraryParserTests.swift`

**Interfaces:**
- Consumes: `Lexer`, `Token`, `TokenKind`, `Diagnostic`, `SourceTechnology`
  (already in `ArchitectureSource.swift`).
- Produces:
  `struct LibrarySource { let label: String; let displayName: String?; let catalogueTag: String?; let technologies: [SourceTechnology]; let threats: [SourceLibraryThreat] }`,
  `struct SourceLibraryThreat { let id: String; let name: String; let description: String; let severityLabel: String; let strideIds: [String]; let isConnectionThreat: Bool; let isZoneThreat: Bool; let zoneContext: String?; let mitre: [SourceMitreTechnique]; let controlDescriptions: [String] }`,
  `struct SourceMitreTechnique { let id: String; let name: String; let tactic: String }`,
  `struct LibraryRead { let source: LibrarySource?; let diagnostics: [Diagnostic]; var hasErrors: Bool; var warnings: [Diagnostic] }`,
  `struct LibraryParser { init(tokens: [Token], faults: [Diagnostic]); mutating func parse() -> LibraryRead }`

- [x] **Step 1: Write the failing test**

```swift
import Testing
import ThreatModelKit
@testable import ArchitectureDSL

@Suite("Parsing the library language")
struct LibraryParserTests {
    private func read(_ text: String) -> LibraryRead {
        let scanned = Lexer(text).scan()
        var parser = LibraryParser(tokens: scanned.tokens, faults: scanned.faults)
        return parser.parse()
    }

    @Test func readsALibraryWithOneTechnology() throws {
        let read = read("""
        library "acme" {
          name      = "Acme Platform"
          catalogue = "v1.0.1"

          technology "cribl-stream" {
            name        = "Cribl Stream"
            category    = "monitoring"
            description = "Observability pipeline"
            threats     = ["pipeline-tamper", "credential-theft"]
            encrypts    = true
          }
        }
        """)

        let source = try #require(read.source)
        #expect(read.diagnostics.isEmpty)
        #expect(source.label == "acme")
        #expect(source.displayName == "Acme Platform")
        #expect(source.catalogueTag == "v1.0.1")
        #expect(source.technologies.count == 1)
        let technology = try #require(source.technologies.first)
        #expect(technology.id == "cribl-stream")
        #expect(technology.name == "Cribl Stream")
        #expect(technology.category == "monitoring")
        #expect(technology.threatIds == ["pipeline-tamper", "credential-theft"])
        #expect(technology.encrypts)
    }

    @Test func refusesAFileThatDoesNotStartWithLibrary() {
        let read = read("system \"Payments\" { }")

        #expect(read.source == nil)
        #expect(read.diagnostics.first?.message.contains("library") == true)
    }
}
```

- [x] **Step 2: Run the test and watch it fail**

Run: `cd ThreatModelKit && swift test --filter LibraryParserTests`
Expected: FAIL, `cannot find 'LibraryParser' in scope`.

- [x] **Step 3: Write `LibrarySource.swift`**

```swift
/// One library, as the text says it. Ids here are unprefixed: `LoadLibraries`
/// mints the prefixed ones.
public struct LibrarySource: Equatable, Sendable {
    /// The label of the `library` block, which is the provider id.
    public let label: String
    /// What the palette calls the group. Nil means the label.
    public let displayName: String?
    public let catalogueTag: String?
    public let technologies: [SourceTechnology]
    public let threats: [SourceLibraryThreat]

    public init(
        label: String,
        displayName: String? = nil,
        catalogueTag: String? = nil,
        technologies: [SourceTechnology] = [],
        threats: [SourceLibraryThreat] = []
    ) {
        self.label = label
        self.displayName = displayName
        self.catalogueTag = catalogueTag
        self.technologies = technologies
        self.threats = threats
    }
}

/// A threat a library defines.
public struct SourceLibraryThreat: Equatable, Sendable {
    public let id: String
    public let name: String
    public let description: String
    /// A severity id. The taxonomy says which ids exist, so the load checks it.
    public let severityLabel: String
    public let strideIds: [String]
    public let isConnectionThreat: Bool
    public let isZoneThreat: Bool
    public let zoneContext: String?
    public let mitre: [SourceMitreTechnique]
    /// A control is its description, which is what a controls file keys on.
    public let controlDescriptions: [String]

    public init(
        id: String,
        name: String,
        description: String = "",
        severityLabel: String,
        strideIds: [String] = [],
        isConnectionThreat: Bool = false,
        isZoneThreat: Bool = false,
        zoneContext: String? = nil,
        mitre: [SourceMitreTechnique] = [],
        controlDescriptions: [String] = []
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.severityLabel = severityLabel
        self.strideIds = strideIds
        self.isConnectionThreat = isConnectionThreat
        self.isZoneThreat = isZoneThreat
        self.zoneContext = zoneContext
        self.mitre = mitre
        self.controlDescriptions = controlDescriptions
    }
}

public struct SourceMitreTechnique: Equatable, Sendable {
    public let id: String
    public let name: String
    public let tactic: String

    public init(id: String, name: String, tactic: String) {
        self.id = id
        self.name = name
        self.tactic = tactic
    }
}

public struct LibraryRead: Equatable, Sendable {
    public let source: LibrarySource?
    public let diagnostics: [Diagnostic]

    public init(source: LibrarySource?, diagnostics: [Diagnostic]) {
        self.source = source
        self.diagnostics = diagnostics
    }

    public var hasErrors: Bool { diagnostics.contains { $0.severity == .error } }
    public var warnings: [Diagnostic] { diagnostics.filter { $0.severity == .warning } }
}
```

- [x] **Step 4: Write `LibraryParser.swift`, the `library` block and its technologies**

Copy the shape of `ArchitectureParser`: the same `current`, `advance`,
`expect`, `record`, `skipToNextBlock` and `skipAttribute` helpers, and the same
`parseTextAttribute`, `parseBooleanAttribute` and `parseListAttribute`. Reuse
its `parseTechnology()` body verbatim for the `technology` block, so both
languages read the same block the same way.

```swift
import ThreatModelKit

/// Turns tokens into a `LibrarySource`.
///
/// Like the other two parsers it never throws and never stops at the first
/// fault.
struct LibraryParser {
    private let tokens: [Token]
    private var index = 0
    private var diagnostics: [Diagnostic]

    init(tokens: [Token], faults: [Diagnostic]) {
        self.tokens = tokens
        diagnostics = faults
    }

    mutating func parse() -> LibraryRead {
        guard let source = parseLibrary() else {
            return LibraryRead(source: nil, diagnostics: diagnostics)
        }
        check(source)
        return LibraryRead(
            source: diagnostics.contains { $0.severity == .error } ? nil : source,
            diagnostics: diagnostics
        )
    }

    private mutating func parseLibrary() -> LibrarySource? {
        guard expectKeyword("library") else { return nil }
        guard let label = expect(.string, "the library's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var displayName: String?
        var catalogueTag: String?
        var technologies: [SourceTechnology] = []
        var threats: [SourceLibraryThreat] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "name": displayName = parseTextAttribute()
            case "catalogue": catalogueTag = parseTextAttribute()
            case "technology":
                if let technology = parseTechnology() { technologies.append(technology) }
            case "threat":
                if let threat = parseThreat() { threats.append(threat) }
            default:
                record("a library holds name, catalogue, technology and threat, not \"\(current.text)\"")
                skipToNextBlock()
            }
        }
        _ = expect(.rightBrace, "}")

        return LibrarySource(
            label: label.text,
            displayName: displayName,
            catalogueTag: catalogueTag,
            technologies: technologies,
            threats: threats
        )
    }
}
```

`parseThreat()` returns nil for now and records nothing; Task 2 writes it.
`check(_:)` is empty for now; Task 3 writes it.

- [x] **Step 5: Run the test and watch it pass**

Run: `cd ThreatModelKit && swift test --filter LibraryParserTests`
Expected: PASS.

- [x] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/architecture/domain/LibrarySource.swift \
        ThreatModelKit/Sources/ArchitectureDSL/LibraryParser.swift \
        ThreatModelKit/Tests/UnitTests/LibraryParserTests.swift
git -c commit.gpgsign=false commit -m "feat: read a library block and its technologies"
```

---

### Task 2: the `threat` block

**Files:**
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/LibraryParser.swift`
- Test: `ThreatModelKit/Tests/UnitTests/LibraryParserTests.swift`

**Interfaces:**
- Produces: `LibraryParser.parseThreat()`, filling `SourceLibraryThreat`.

- [x] **Step 1: Write the failing test**

```swift
@Test func readsAThreatWithItsControls() throws {
    let read = read("""
    library "acme" {
      threat "pipeline-tamper" {
        name         = "Pipeline tampering"
        description  = "An attacker changes a pipeline."
        severity     = "high"
        stride       = ["tampering"]
        zone         = true
        zone_context = "Reachable only from the VPC."

        mitre "T1565" {
          name   = "Data Manipulation"
          tactic = "impact"
        }

        control "Sign pipeline configurations"
        control "Review every pipeline change"
      }
    }
    """)

    let source = try #require(read.source)
    let threat = try #require(source.threats.first)
    #expect(threat.id == "pipeline-tamper")
    #expect(threat.name == "Pipeline tampering")
    #expect(threat.severityLabel == "high")
    #expect(threat.strideIds == ["tampering"])
    #expect(threat.isZoneThreat)
    #expect(threat.isConnectionThreat == false)
    #expect(threat.zoneContext == "Reachable only from the VPC.")
    #expect(threat.mitre == [SourceMitreTechnique(id: "T1565", name: "Data Manipulation", tactic: "impact")])
    #expect(threat.controlDescriptions == [
        "Sign pipeline configurations",
        "Review every pipeline change"
    ])
}
```

- [x] **Step 2: Run the test and watch it fail**

Run: `cd ThreatModelKit && swift test --filter readsAThreatWithItsControls`
Expected: FAIL, the threat list is empty.

- [x] **Step 3: Write `parseThreat`, `parseMitre` and `parseControl`**

```swift
    private mutating func parseThreat() -> SourceLibraryThreat? {
        advance()
        guard let id = expect(.string, "the threat's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var name: String?
        var description = ""
        var severityLabel: String?
        var strideIds: [String] = []
        var isConnectionThreat = false
        var isZoneThreat = false
        var zoneContext: String?
        var mitre: [SourceMitreTechnique] = []
        var controls: [String] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "name": name = parseTextAttribute()
            case "description": description = parseTextAttribute() ?? ""
            case "severity": severityLabel = parseTextAttribute()
            case "stride": strideIds = parseListAttribute()
            case "connection": isConnectionThreat = parseBooleanAttribute() ?? false
            case "zone": isZoneThreat = parseBooleanAttribute() ?? false
            case "zone_context": zoneContext = parseTextAttribute()
            case "mitre":
                if let technique = parseMitre() { mitre.append(technique) }
            case "control":
                if let control = parseControl() { controls.append(control) }
            default:
                record(
                    "a threat holds name, description, severity, stride, connection, "
                        + "zone, zone_context, mitre and control, not \"\(current.text)\""
                )
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard let name else {
            record("the threat \"\(id.text)\" has no name", at: id)
            return nil
        }
        guard let severityLabel else {
            record("the threat \"\(id.text)\" has no severity", at: id)
            return nil
        }
        return SourceLibraryThreat(
            id: id.text,
            name: name,
            description: description,
            severityLabel: severityLabel,
            strideIds: strideIds,
            isConnectionThreat: isConnectionThreat,
            isZoneThreat: isZoneThreat,
            zoneContext: zoneContext,
            mitre: mitre,
            controlDescriptions: controls
        )
    }

    private mutating func parseMitre() -> SourceMitreTechnique? {
        advance()
        guard let id = expect(.string, "the technique's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var name: String?
        var tactic: String?
        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "name": name = parseTextAttribute()
            case "tactic": tactic = parseTextAttribute()
            default:
                record("a mitre technique holds name and tactic, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard let name else {
            record("the technique \"\(id.text)\" has no name", at: id)
            return nil
        }
        guard let tactic else {
            record("the technique \"\(id.text)\" has no tactic", at: id)
            return nil
        }
        return SourceMitreTechnique(id: id.text, name: name, tactic: tactic)
    }

    /// A control is a statement, not a block: a library says what a control is
    /// and a controls file says its status.
    private mutating func parseControl() -> String? {
        advance()
        return expect(.string, "the control's description")?.text
    }
```

- [x] **Step 4: Run the test and watch it pass**

Run: `cd ThreatModelKit && swift test --filter LibraryParserTests`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ArchitectureDSL/LibraryParser.swift \
        ThreatModelKit/Tests/UnitTests/LibraryParserTests.swift
git -c commit.gpgsign=false commit -m "feat: read a threat block in a library"
```

---

### Task 3: what a library file must hold

**Files:**
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/LibraryParser.swift`
- Test: `ThreatModelKit/Tests/UnitTests/LibraryParserTests.swift`

**Interfaces:**
- Produces: `LibraryParser.check(_:)`, the static checks of spec section 3.5.

- [x] **Step 1: Write the failing tests**

```swift
@Test func refusesADuplicateTechnologyIdentifier() {
    let read = read("""
    library "acme" {
      technology "one" { name = "One" category = "monitoring" }
      technology "one" { name = "Two" category = "monitoring" }
    }
    """)

    #expect(read.source == nil)
    #expect(read.diagnostics.contains { $0.message == "the technology \"one\" is declared twice" })
}

@Test func refusesADuplicateThreatIdentifier() {
    let read = read("""
    library "acme" {
      threat "t" { name = "One" severity = "high" }
      threat "t" { name = "Two" severity = "high" }
    }
    """)

    #expect(read.source == nil)
    #expect(read.diagnostics.contains { $0.message == "the threat \"t\" is declared twice" })
}

@Test func warnsAboutAThreatNothingCanRaise() throws {
    let read = read("""
    library "acme" {
      threat "orphan" { name = "Orphan" severity = "low" }
    }
    """)

    #expect(read.source != nil)
    let warning = try #require(read.diagnostics.first)
    #expect(warning.severity == .warning)
    #expect(warning.message == "no technology in this library names \"orphan\", so nothing raises it")
}

@Test func doesNotWarnAboutAZoneThreat() {
    let read = read("""
    library "acme" {
      threat "everywhere" { name = "Everywhere" severity = "low" zone = true }
    }
    """)

    #expect(read.diagnostics.isEmpty)
}

@Test func reportsEveryFaultRatherThanTheFirst() {
    let read = read("""
    library "acme" {
      technology "one" { category = "monitoring" }
      threat "t" { name = "T" }
    }
    """)

    #expect(read.diagnostics.count == 2)
}
```

- [x] **Step 2: Run the tests and watch them fail**

Run: `cd ThreatModelKit && swift test --filter LibraryParserTests`
Expected: FAIL on the duplicate and the warning tests.

- [x] **Step 3: Write `check`**

```swift
    /// What the file must hold once it parses. Each fault names the first line,
    /// because it is a fault of the file rather than of one token.
    private mutating func check(_ source: LibrarySource) {
        var technologyIds: Set<String> = []
        for technology in source.technologies
        where technologyIds.insert(technology.id).inserted == false {
            record("the technology \"\(technology.id)\" is declared twice", at: tokens[0])
        }

        var threatIds: Set<String> = []
        for threat in source.threats where threatIds.insert(threat.id).inserted == false {
            record("the threat \"\(threat.id)\" is declared twice", at: tokens[0])
        }

        let named = Set(source.technologies.flatMap(\.threatIds))
        for threat in source.threats
        where named.contains(threat.id) == false
            && threat.isZoneThreat == false
            && threat.isConnectionThreat == false {
            record(
                "no technology in this library names \"\(threat.id)\", so nothing raises it",
                at: tokens[0],
                severity: .warning
            )
        }
    }
```

- [x] **Step 4: Run the tests and watch them pass**

Run: `cd ThreatModelKit && swift test --filter LibraryParserTests`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ArchitectureDSL/LibraryParser.swift \
        ThreatModelKit/Tests/UnitTests/LibraryParserTests.swift
git -c commit.gpgsign=false commit -m "feat: check what a library file must hold"
```

---

### Task 4: the library writer

**Files:**
- Create: `ThreatModelKit/Sources/ArchitectureDSL/LibraryWriter.swift`
- Test: `ThreatModelKit/Tests/UnitTests/LibraryWriterTests.swift`

**Interfaces:**
- Produces: `struct LibraryWriter { func write(_ source: LibrarySource) -> String }`

The rules are the ones `ArchitectureWriter` holds: two spaces of indentation,
the equals signs of one run of attributes lined up, a blank line between blocks,
one newline at the end, and an attribute holding its default not written. The
order is `name`, `catalogue`, the technologies in declaration order, then the
threats in declaration order.

- [x] **Step 1: Write the failing test**

```swift
import Testing
import ThreatModelKit
@testable import ArchitectureDSL

@Suite("Writing the library language")
struct LibraryWriterTests {
    private let text = """
    library "acme" {
      name      = "Acme Platform"
      catalogue = "v1.0.1"

      technology "cribl-stream" {
        name     = "Cribl Stream"
        category = "monitoring"
        threats  = ["pipeline-tamper"]
        encrypts = true
      }

      threat "pipeline-tamper" {
        name     = "Pipeline tampering"
        severity = "high"
        stride   = ["tampering"]

        mitre "T1565" {
          name   = "Data Manipulation"
          tactic = "impact"
        }

        control "Sign pipeline configurations"
      }
    }

    """

    private func read(_ text: String) -> LibraryRead {
        let scanned = Lexer(text).scan()
        var parser = LibraryParser(tokens: scanned.tokens, faults: scanned.faults)
        return parser.parse()
    }

    @Test func writesACanonicalFileItCanReadBack() throws {
        let source = try #require(read(text).source)

        #expect(LibraryWriter().write(source) == text)
    }

    @Test func parseWriteParseGivesTheSameTree() throws {
        let once = try #require(read(text).source)
        let twice = try #require(read(LibraryWriter().write(once)).source)

        #expect(once == twice)
    }
}
```

- [x] **Step 2: Run the test and watch it fail**

Run: `cd ThreatModelKit && swift test --filter LibraryWriterTests`
Expected: FAIL, `cannot find 'LibraryWriter' in scope`.

- [x] **Step 3: Write `LibraryWriter.swift`**

Copy `ArchitectureWriter`'s `aligned`, `indent` and `quoted` helpers verbatim,
then:

```swift
import ThreatModelKit

/// Writes a library source in the canonical shape.
///
/// The rules are the architecture writer's: two-space indentation, the equals
/// signs of one block lined up, a blank line between blocks. A rewrite of an
/// unchanged source produces no diff.
struct LibraryWriter {
    func write(_ source: LibrarySource) -> String {
        var lines = ["library \(quoted(source.label)) {"]
        var body: [String] = []

        var header: [(String, String)] = []
        if let displayName = source.displayName {
            header.append(("name", quoted(displayName)))
        }
        if let catalogueTag = source.catalogueTag {
            header.append(("catalogue", quoted(catalogueTag)))
        }
        if header.isEmpty == false {
            body += aligned(header)
            body.append("")
        }

        for technology in source.technologies {
            body.append("technology \(quoted(technology.id)) {")
            var attributes: [(String, String)] = [
                ("name", quoted(technology.name)),
                ("category", quoted(technology.category))
            ]
            if technology.description.isEmpty == false {
                attributes.append(("description", quoted(technology.description)))
            }
            if technology.threatIds.isEmpty == false {
                attributes.append(
                    ("threats", "[" + technology.threatIds.map(quoted).joined(separator: ", ") + "]")
                )
            }
            if technology.encrypts { attributes.append(("encrypts", "true")) }
            body += indent(aligned(attributes))
            body.append("}")
            body.append("")
        }

        for threat in source.threats {
            body += threatBlock(threat)
            body.append("")
        }

        while body.last == "" { body.removeLast() }
        lines += indent(body)
        lines.append("}")
        return lines.joined(separator: "\n") + "\n"
    }

    private func threatBlock(_ threat: SourceLibraryThreat) -> [String] {
        var lines = ["threat \(quoted(threat.id)) {"]
        var body: [String] = []

        var attributes: [(String, String)] = [("name", quoted(threat.name))]
        if threat.description.isEmpty == false {
            attributes.append(("description", quoted(threat.description)))
        }
        attributes.append(("severity", quoted(threat.severityLabel)))
        if threat.strideIds.isEmpty == false {
            attributes.append(
                ("stride", "[" + threat.strideIds.map(quoted).joined(separator: ", ") + "]")
            )
        }
        if threat.isConnectionThreat { attributes.append(("connection", "true")) }
        if threat.isZoneThreat { attributes.append(("zone", "true")) }
        if let zoneContext = threat.zoneContext {
            attributes.append(("zone_context", quoted(zoneContext)))
        }
        body += aligned(attributes)

        for technique in threat.mitre {
            body.append("")
            body.append("mitre \(quoted(technique.id)) {")
            body += indent(
                aligned([("name", quoted(technique.name)), ("tactic", quoted(technique.tactic))])
            )
            body.append("}")
        }

        if threat.controlDescriptions.isEmpty == false {
            body.append("")
            for description in threat.controlDescriptions {
                body.append("control \(quoted(description))")
            }
        }

        lines += indent(body)
        lines.append("}")
        return lines
    }
}
```

- [x] **Step 4: Run the test and watch it pass**

Run: `cd ThreatModelKit && swift test --filter LibraryWriterTests`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ArchitectureDSL/LibraryWriter.swift \
        ThreatModelKit/Tests/UnitTests/LibraryWriterTests.swift
git -c commit.gpgsign=false commit -m "feat: write a library file in a canonical shape"
```

---

### Task 5: the library source gateway

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/gateway/LibrarySourceGateway.swift`
- Create: `ThreatModelKit/Sources/ArchitectureDSL/HclLibrarySource.swift`
- Create: `ThreatModelKit/Sources/TestSupport/LibrarySourceGatewayContract.swift`
- Test: `ThreatModelKit/Tests/GatewayIntegrationTests/HclLibrarySourceTests.swift`

**Interfaces:**
- Produces:
  `protocol LibrarySourceGateway: Sendable { func read(_ text: String) -> LibraryRead; func write(_ source: LibrarySource) -> String }`,
  `struct HclLibrarySource: LibrarySourceGateway`,
  `func assertLibrarySourceGateway(_ gateway: LibrarySourceGateway)`

- [x] **Step 1: Write the failing contract and its test**

```swift
// TestSupport/LibrarySourceGatewayContract.swift
import Testing
import ThreatModelKit

/// The one contract every library source gateway meets.
public func assertLibrarySourceGateway(_ gateway: LibrarySourceGateway) {
    let text = """
    library "acme" {
      technology "cribl-stream" {
        name     = "Cribl Stream"
        category = "monitoring"
        threats  = ["pipeline-tamper"]
      }

      threat "pipeline-tamper" {
        name     = "Pipeline tampering"
        severity = "high"
      }
    }

    """

    let read = gateway.read(text)
    #expect(read.source?.label == "acme")
    #expect(read.hasErrors == false)

    guard let source = read.source else { return }
    #expect(gateway.write(source) == text)

    let refused = gateway.read("system \"Payments\" { }")
    #expect(refused.source == nil)
    #expect(refused.hasErrors)
}
```

```swift
// Tests/GatewayIntegrationTests/HclLibrarySourceTests.swift
import ArchitectureDSL
import Testing
import TestSupport

@Suite("The HCL library source")
struct HclLibrarySourceTests {
    @Test func meetsTheContract() {
        assertLibrarySourceGateway(HclLibrarySource())
    }
}
```

- [x] **Step 2: Run the test and watch it fail**

Run: `cd ThreatModelKit && swift test --filter HclLibrarySourceTests`
Expected: FAIL, `cannot find 'HclLibrarySource' in scope`.

- [x] **Step 3: Write the port and the implementation**

```swift
// ThreatModelKit/architecture/gateway/LibrarySourceGateway.swift
/// Reads and writes the library language.
public protocol LibrarySourceGateway: Sendable {
    func read(_ text: String) -> LibraryRead
    func write(_ source: LibrarySource) -> String
}
```

```swift
// ArchitectureDSL/HclLibrarySource.swift
import ThreatModelKit

/// The library language over the lexer, the parser and the writer.
public struct HclLibrarySource: LibrarySourceGateway {
    public init() {}

    public func read(_ text: String) -> LibraryRead {
        let scanned = Lexer(text).scan()
        var parser = LibraryParser(tokens: scanned.tokens, faults: scanned.faults)
        return parser.parse()
    }

    public func write(_ source: LibrarySource) -> String {
        LibraryWriter().write(source)
    }
}
```

- [x] **Step 4: Run the test and watch it pass**

Run: `cd ThreatModelKit && swift test --filter HclLibrarySourceTests`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/architecture/gateway/LibrarySourceGateway.swift \
        ThreatModelKit/Sources/ArchitectureDSL/HclLibrarySource.swift \
        ThreatModelKit/Sources/TestSupport/LibrarySourceGatewayContract.swift \
        ThreatModelKit/Tests/GatewayIntegrationTests/HclLibrarySourceTests.swift
git -c commit.gpgsign=false commit -m "feat: read and write a library through a gateway"
```

---

### Task 6: a library as catalogue values

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/Library.swift`
- Test: `ThreatModelKit/Tests/UnitTests/LibraryTests.swift`

**Interfaces:**
- Produces:
  `struct Library { let label: String; let provider: Provider; let technologies: [Technology]; let threats: [Threat] }`,
  `enum LibraryBuildFault { case unknownSeverity(technologyOrThreatId: String, value: String), unknownCategory(technologyId: String, value: String), unknownStride(threatId: String, value: String) }`,
  `static func Library.build(from: LibrarySource, taxonomy: Taxonomy) -> (library: Library?, faults: [LibraryBuildFault])`

**The prefix rule:** every id the source declares is minted `<label>-<id>`. A
`threats` entry is prefixed when the library declares that threat, and left bare
when it does not, because a bare id belongs to the vendored catalogue.

- [x] **Step 1: Write the failing test**

```swift
import Testing
@testable import ThreatModelKit

@Suite("Building a library")
struct LibraryTests {
    private let taxonomy = Taxonomy(
        stride: [StrideCategory(id: StrideId("tampering"), label: "Tampering")],
        severities: [
            ThreatSeverity(id: "low", label: "Low", rank: 1),
            ThreatSeverity(id: "high", label: "High", rank: 3)
        ],
        categories: [
            ServiceCategory(id: CategoryId("monitoring"), label: "Monitoring", presetThreatIds: [])
        ]
    )

    private let source = LibrarySource(
        label: "acme",
        displayName: "Acme Platform",
        technologies: [
            SourceTechnology(
                id: "cribl-stream",
                name: "Cribl Stream",
                category: "monitoring",
                description: "Observability pipeline",
                threatIds: ["pipeline-tamper", "credential-theft"],
                encrypts: true
            )
        ],
        threats: [
            SourceLibraryThreat(
                id: "pipeline-tamper",
                name: "Pipeline tampering",
                severityLabel: "high",
                strideIds: ["tampering"],
                controlDescriptions: ["Sign pipeline configurations"]
            )
        ]
    )

    @Test func prefixesEveryIdentifierItDeclares() throws {
        let (library, faults) = Library.build(from: source, taxonomy: taxonomy)

        let built = try #require(library)
        #expect(faults.isEmpty)
        #expect(built.provider == Provider(id: ProviderId("acme"), displayName: "Acme Platform"))
        #expect(built.technologies.map(\.id.value) == ["acme-cribl-stream"])
        #expect(built.threats.map(\.id.value) == ["acme-pipeline-tamper"])
    }

    @Test func leavesACatalogueThreatIdentifierBare() throws {
        let (library, _) = Library.build(from: source, taxonomy: taxonomy)

        let technology = try #require(library?.technologies.first)
        #expect(technology.threatIds.map(\.value) == ["acme-pipeline-tamper", "credential-theft"])
    }

    @Test func namesTheLabelWhenTheLibraryHasNoDisplayName() throws {
        let plain = LibrarySource(label: "acme")

        let (library, _) = Library.build(from: plain, taxonomy: taxonomy)

        #expect(library?.provider.displayName == "acme")
    }

    @Test func reportsAValueTheTaxonomyDoesNotHold() {
        let wrong = LibrarySource(
            label: "acme",
            technologies: [
                SourceTechnology(id: "t", name: "T", category: "observability", threatIds: [])
            ],
            threats: [
                SourceLibraryThreat(id: "x", name: "X", severityLabel: "severe", strideIds: ["fibbing"])
            ]
        )

        let (library, faults) = Library.build(from: wrong, taxonomy: taxonomy)

        #expect(library == nil)
        #expect(faults.count == 3)
    }
}
```

- [x] **Step 2: Run the test and watch it fail**

Run: `cd ThreatModelKit && swift test --filter LibraryTests`
Expected: FAIL, `type 'Library' has no member 'build'`.

- [x] **Step 3: Write `Library.swift`**

```swift
/// One library, said the way the rest of the application says it.
///
/// Every id it holds is already prefixed by its label, so nothing downstream
/// has to know a library from the vendored catalogue.
public struct Library: Equatable, Sendable {
    public let label: String
    public let provider: Provider
    public let technologies: [Technology]
    public let threats: [Threat]

    public init(label: String, provider: Provider, technologies: [Technology], threats: [Threat]) {
        self.label = label
        self.provider = provider
        self.technologies = technologies
        self.threats = threats
    }
}

/// A value a library states that the taxonomy does not hold.
public enum LibraryBuildFault: Equatable, Sendable {
    case unknownCategory(technologyId: String, value: String)
    case unknownSeverity(threatId: String, value: String)
    case unknownStride(threatId: String, value: String)

    public var message: String {
        switch self {
        case .unknownCategory(let technologyId, let value):
            "the technology \"\(technologyId)\" is in the category \"\(value)\", which the taxonomy does not hold"
        case .unknownSeverity(let threatId, let value):
            "the threat \"\(threatId)\" has the severity \"\(value)\", which the taxonomy does not hold"
        case .unknownStride(let threatId, let value):
            "the threat \"\(threatId)\" names the stride category \"\(value)\", which the taxonomy does not hold"
        }
    }
}

public extension Library {
    /// Mints the prefixed ids and checks every value against the taxonomy.
    /// It returns no library when it finds a fault, because half a library is
    /// worse than none.
    static func build(from source: LibrarySource, taxonomy: Taxonomy) -> (library: Library?, faults: [LibraryBuildFault]) {
        var faults: [LibraryBuildFault] = []
        let declared = Set(source.threats.map(\.id))

        func prefixed(_ id: String) -> String { "\(source.label)-\(id)" }

        let technologies = source.technologies.map { technology -> Technology in
            if taxonomy.category(id: CategoryId(technology.category)) == nil {
                faults.append(.unknownCategory(technologyId: technology.id, value: technology.category))
            }
            return Technology(
                id: TechnologyId(prefixed(technology.id)),
                name: technology.name,
                provider: ProviderId(source.label),
                category: CategoryId(technology.category),
                description: technology.description,
                threatIds: technology.threatIds.map {
                    ThreatId(declared.contains($0) ? prefixed($0) : $0)
                },
                enforcesEncryption: technology.encrypts
            )
        }

        let threats = source.threats.map { threat -> Threat in
            let severity = taxonomy.severity(id: threat.severityLabel)
            if severity == nil {
                faults.append(.unknownSeverity(threatId: threat.id, value: threat.severityLabel))
            }
            for stride in threat.strideIds where taxonomy.strideCategory(id: StrideId(stride)) == nil {
                faults.append(.unknownStride(threatId: threat.id, value: stride))
            }
            return Threat(
                id: ThreatId(prefixed(threat.id)),
                name: threat.name,
                description: threat.description,
                severity: severity ?? ThreatSeverity(id: threat.severityLabel, label: threat.severityLabel, rank: 1),
                stride: threat.strideIds.map(StrideId.init),
                mitreTechniques: threat.mitre.map {
                    MitreTechnique(id: $0.id, name: $0.name, tactic: $0.tactic)
                },
                controls: threat.controlDescriptions.enumerated().map {
                    Control(id: "\(prefixed(threat.id))-\($0.offset)", description: $0.element)
                },
                isConnectionThreat: threat.isConnectionThreat,
                isZoneThreat: threat.isZoneThreat,
                zoneContext: threat.zoneContext
            )
        }

        guard faults.isEmpty else { return (nil, faults) }
        return (
            Library(
                label: source.label,
                provider: Provider(
                    id: ProviderId(source.label),
                    displayName: source.displayName ?? source.label
                ),
                technologies: technologies,
                threats: threats
            ),
            []
        )
    }
}
```

Add `Equatable` to `Provider` if it is not already `Equatable`; it is.

- [x] **Step 4: Run the test and watch it pass**

Run: `cd ThreatModelKit && swift test --filter LibraryTests`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/Library.swift \
        ThreatModelKit/Tests/UnitTests/LibraryTests.swift
git -c commit.gpgsign=false commit -m "feat: build a library as catalogue values"
```

---

### Task 7: the merged catalogue

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/LibraryStore.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/MergedCatalogue.swift`
- Test: `ThreatModelKit/Tests/UnitTests/MergedCatalogueTests.swift`

**Interfaces:**
- Produces:
  `final class LibraryStore: @unchecked Sendable { init(_ libraries: [Library] = []); func set(_ libraries: [Library]); func all() -> [Library] }`,
  `struct MergedCatalogue: TechnologyCatalogue { init(base: TechnologyCatalogue, store: LibraryStore) }`

A store rather than a stored array, because a composition root builds its
catalogue once and a project's libraries arrive later, when the user opens the
project.

- [x] **Step 1: Write the failing test**

```swift
import Testing
import TestSupport
@testable import ThreatModelKit

@Suite("The merged catalogue")
struct MergedCatalogueTests {
    private func aLibrary() -> Library {
        Library(
            label: "acme",
            provider: Provider(id: ProviderId("acme"), displayName: "Acme Platform"),
            technologies: [
                Technology(
                    id: TechnologyId("acme-cribl-stream"),
                    name: "Cribl Stream",
                    provider: ProviderId("acme"),
                    category: CategoryId("monitoring"),
                    description: "",
                    threatIds: [ThreatId("acme-pipeline-tamper")]
                )
            ],
            threats: [
                Threat(
                    id: ThreatId("acme-pipeline-tamper"),
                    name: "Pipeline tampering",
                    description: "",
                    severity: ThreatSeverity(id: "high", label: "High", rank: 3)
                )
            ]
        )
    }

    @Test func readsExactlyTheBaseWhenItHoldsNoLibrary() {
        let base = FakeTechnologyCatalogue()
        let merged = MergedCatalogue(base: base, store: LibraryStore())

        #expect(merged.all() == base.all())
        #expect(merged.providers() == base.providers())
        #expect(merged.version() == base.version())
        #expect(merged.taxonomy() == base.taxonomy())
    }

    @Test func findsALibraryTechnology() throws {
        let merged = MergedCatalogue(base: FakeTechnologyCatalogue(), store: LibraryStore([aLibrary()]))

        let found = try #require(merged.findById(TechnologyId("acme-cribl-stream")))
        #expect(found.name == "Cribl Stream")
    }

    @Test func readsALibraryTechnologysThreats() {
        let merged = MergedCatalogue(base: FakeTechnologyCatalogue(), store: LibraryStore([aLibrary()]))

        #expect(
            merged.threatsFor(technologyId: TechnologyId("acme-cribl-stream")).map(\.id.value)
                == ["acme-pipeline-tamper"]
        )
    }

    @Test func addsOneProviderForEachLibrary() {
        let base = FakeTechnologyCatalogue()
        let merged = MergedCatalogue(base: base, store: LibraryStore([aLibrary()]))

        #expect(merged.providers().count == base.providers().count + 1)
        #expect(merged.providers().last?.id == ProviderId("acme"))
    }

    @Test func readsTheStoreEveryTimeRatherThanOnce() {
        let store = LibraryStore()
        let merged = MergedCatalogue(base: FakeTechnologyCatalogue(), store: store)
        #expect(merged.findById(TechnologyId("acme-cribl-stream")) == nil)

        store.set([aLibrary()])

        #expect(merged.findById(TechnologyId("acme-cribl-stream")) != nil)
    }
}
```

`FakeTechnologyCatalogue` already exists in `TestSupport`. Check its name before
writing the test and use whatever the package already calls its fake catalogue.

- [x] **Step 2: Run the test and watch it fail**

Run: `cd ThreatModelKit && swift test --filter MergedCatalogueTests`
Expected: FAIL, `cannot find 'MergedCatalogue' in scope`.

- [x] **Step 3: Write `LibraryStore.swift` and `MergedCatalogue.swift`**

```swift
import Foundation

/// The libraries the open project holds.
///
/// A composition root builds its catalogue once, and a project's libraries
/// arrive when a user opens the project, so the catalogue reads them through
/// this rather than holding a copy.
public final class LibraryStore: @unchecked Sendable {
    private let lock = NSLock()
    private var libraries: [Library]

    public init(_ libraries: [Library] = []) {
        self.libraries = libraries
    }

    public func set(_ libraries: [Library]) {
        lock.lock()
        defer { lock.unlock() }
        self.libraries = libraries
    }

    public func all() -> [Library] {
        lock.lock()
        defer { lock.unlock() }
        return libraries
    }
}
```

```swift
/// The vendored catalogue and the project's libraries, read as one.
///
/// Nothing downstream can tell a library entry from a vendored one, which is
/// what keeps the resolver, the palette and the report unchanged.
public struct MergedCatalogue: TechnologyCatalogue {
    private let base: TechnologyCatalogue
    private let store: LibraryStore

    public init(base: TechnologyCatalogue, store: LibraryStore) {
        self.base = base
        self.store = store
    }

    public func all() -> [Technology] {
        base.all() + store.all().flatMap(\.technologies)
    }

    public func findById(_ id: TechnologyId) -> Technology? {
        if let found = base.findById(id) { return found }
        for library in store.all() {
            if let found = library.technologies.first(where: { $0.id == id }) { return found }
        }
        return nil
    }

    public func threatsFor(technologyId: TechnologyId) -> [Threat] {
        if base.findById(technologyId) != nil {
            return base.threatsFor(technologyId: technologyId)
        }
        guard let technology = findById(technologyId) else { return [] }
        return technology.threatIds.compactMap { threat(id: $0) }
    }

    public func connectionThreats() -> [Threat] {
        base.connectionThreats() + store.all().flatMap { $0.threats.filter(\.isConnectionThreat) }
    }

    public func zoneThreats() -> [Threat] {
        base.zoneThreats() + store.all().flatMap { $0.threats.filter(\.isZoneThreat) }
    }

    public func pathwayMitigations() -> [PathwayMitigationDefinition] {
        base.pathwayMitigations()
    }

    public func version() -> CatalogueVersion { base.version() }

    public func taxonomy() -> Taxonomy { base.taxonomy() }

    public func providers() -> [Provider] {
        base.providers() + store.all().map(\.provider)
    }

    /// A threat a library declares, else the same id in the base catalogue.
    private func threat(id: ThreatId) -> Threat? {
        for library in store.all() {
            if let found = library.threats.first(where: { $0.id == id }) { return found }
        }
        return base.all()
            .flatMap { base.threatsFor(technologyId: $0.id) }
            .first { $0.id == id }
            ?? base.connectionThreats().first { $0.id == id }
            ?? base.zoneThreats().first { $0.id == id }
    }
}
```

- [x] **Step 4: Run the test and watch it pass**

Run: `cd ThreatModelKit && swift test --filter MergedCatalogueTests`
Expected: PASS.

- [x] **Step 5: Run the whole suite**

Run: `cd ThreatModelKit && swift test`
Expected: PASS.

- [x] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/LibraryStore.swift \
        ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/MergedCatalogue.swift \
        ThreatModelKit/Tests/UnitTests/MergedCatalogueTests.swift
git -c commit.gpgsign=false commit -m "feat: read the catalogue and the project's libraries as one"
```

---

### Task 8: the project finds its libraries

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ProjectConvention.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ProjectLayout.swift`
- Modify: `ThreatModelKit/Sources/FileGateways/FileSystemProject.swift`
- Modify: `ThreatModelKit/Sources/TestSupport/InMemoryProject.swift`
- Modify: `ThreatModelKit/Sources/TestSupport/ProjectSourceGatewayContract.swift`
- Test: the contract runs in `Tests/GatewayContractTests` and
  `Tests/GatewayIntegrationTests` already.

**Interfaces:**
- Produces: `ProjectConvention.libraryDirectory = "library"`,
  `ProjectConvention.libraryExtension = "lib"`,
  `ProjectConvention.libraries(in:fileNames:) -> [String]`,
  `ProjectLayout.libraryPaths: [String]`

- [x] **Step 1: Write the failing contract addition**

Add to `assertProjectSourceGateway`:

```swift
    // A project's libraries sit in a `library` directory beside its systems,
    // and the layout lists them sorted.
    try gateway.write("library \"acme\" { }\n", to: inside + "/library/acme.lib")
    try gateway.write("library \"beta\" { }\n", to: inside + "/library/beta.lib")
    try gateway.write("not a library\n", to: inside + "/library/README.md")

    let withLibraries = try gateway.discover(root: root)
    #expect(withLibraries.libraryPaths == [
        inside + "/library/acme.lib",
        inside + "/library/beta.lib"
    ])
```

- [x] **Step 2: Run the contract and watch it fail**

Run: `cd ThreatModelKit && swift test --filter ProjectSourceGateway`
Expected: FAIL, `value of type 'ProjectLayout' has no member 'libraryPaths'`.

- [x] **Step 3: Add the convention, the layout field and both gateways**

```swift
// ProjectConvention.swift
    public static let libraryDirectory = "library"
    public static let libraryExtension = "lib"

    /// The library files a directory holds, sorted, so two reads list the same.
    public static func libraries(in directory: String, fileNames: [String]) -> [String] {
        fileNames
            .filter { $0.hasSuffix(".\(libraryExtension)") }
            .sorted()
            .map { path(directory, $0) }
    }
```

```swift
// ProjectLayout.swift — add the stored property, the initialiser parameter with
// a default of [], and keep Equatable.
    /// The `.lib` files under `<directory>/library`, by name, sorted.
    public let libraryPaths: [String]
```

`FileSystemProject.discover` lists `<directory>/library` and passes its file
names through `ProjectConvention.libraries(in:fileNames:)`. A directory that is
absent gives an empty list rather than an error. `InMemoryProject.discover` does
the same over its dictionary of paths.

- [x] **Step 4: Run the contract and watch it pass**

Run: `cd ThreatModelKit && swift test --filter ProjectSourceGateway`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ProjectConvention.swift \
        ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ProjectLayout.swift \
        ThreatModelKit/Sources/FileGateways/FileSystemProject.swift \
        ThreatModelKit/Sources/TestSupport/InMemoryProject.swift \
        ThreatModelKit/Sources/TestSupport/ProjectSourceGatewayContract.swift
git -c commit.gpgsign=false commit -m "feat: find a project's library files by convention"
```

---

### Task 9: loading a project's libraries

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/LoadLibraries.swift`
- Test: `ThreatModelKit/Tests/UnitTests/LoadLibrariesTests.swift`

**Interfaces:**
- Produces:
  `protocol LoadLibrariesUseCase { func execute(_ request: LoadLibrariesRequest) -> LoadLibrariesResponse }`,
  `struct LoadLibrariesRequest { let root: String }`,
  `enum LoadLibrariesResponse { case loaded(libraries: [Library], warnings: [Diagnostic]); case refused(fileName: String, diagnostics: [Diagnostic]); case notAProject(reason: String) }`,
  `struct LoadLibraries: LoadLibrariesUseCase { init(projects: ProjectSourceGateway, sources: LibrarySourceGateway, catalogue: TechnologyCatalogue) }`

- [x] **Step 1: Write the failing test**

```swift
import Testing
import TestSupport
@testable import ThreatModelKit

@Suite("Loading a project's libraries")
struct LoadLibrariesTests {
    private let acme = """
    library "acme" {
      technology "cribl-stream" {
        name     = "Cribl Stream"
        category = "monitoring"
        threats  = ["pipeline-tamper"]
      }

      threat "pipeline-tamper" {
        name     = "Pipeline tampering"
        severity = "high"
      }
    }

    """

    private func aProject(_ files: [String: String]) -> LoadLibrariesUseCase {
        let projects = InMemoryProject()
        for (path, text) in files { projects.put(text, at: path) }
        return LoadLibraries(
            projects: projects,
            sources: FakeLibrarySource(),
            catalogue: FakeTechnologyCatalogue()
        )
    }

    @Test func readsEveryLibraryBesideTheSystems() throws {
        let load = aProject([
            "/work/threatmodel/payments.arch": "system \"P\" { }",
            "/work/threatmodel/library/acme.lib": acme
        ])

        guard case .loaded(let libraries, let warnings) = load.execute(
            LoadLibrariesRequest(root: "/work")
        ) else {
            Issue.record("the libraries did not load")
            return
        }

        #expect(warnings.isEmpty)
        #expect(libraries.map(\.label) == ["acme"])
        #expect(libraries.first?.technologies.map(\.id.value) == ["acme-cribl-stream"])
    }

    @Test func refusesAFileThatDoesNotParse() {
        let load = aProject([
            "/work/threatmodel/payments.arch": "system \"P\" { }",
            "/work/threatmodel/library/broken.lib": "library \"acme\" { technology }"
        ])

        guard case .refused(let fileName, let diagnostics) = load.execute(
            LoadLibrariesRequest(root: "/work")
        ) else {
            Issue.record("a broken library did not refuse")
            return
        }

        #expect(fileName == "broken.lib")
        #expect(diagnostics.isEmpty == false)
    }

    @Test func refusesTwoLibrariesWithTheSameLabel() {
        let load = aProject([
            "/work/threatmodel/payments.arch": "system \"P\" { }",
            "/work/threatmodel/library/one.lib": "library \"acme\" { }",
            "/work/threatmodel/library/two.lib": "library \"acme\" { }"
        ])

        guard case .refused(_, let diagnostics) = load.execute(
            LoadLibrariesRequest(root: "/work")
        ) else {
            Issue.record("two libraries with one label did not refuse")
            return
        }

        #expect(diagnostics.first?.message.contains("acme") == true)
    }

    @Test func refusesAValueTheTaxonomyDoesNotHold() {
        let load = aProject([
            "/work/threatmodel/payments.arch": "system \"P\" { }",
            "/work/threatmodel/library/acme.lib": """
            library "acme" {
              technology "t" { name = "T" category = "observability" }
            }
            """
        ])

        guard case .refused(_, let diagnostics) = load.execute(
            LoadLibrariesRequest(root: "/work")
        ) else {
            Issue.record("an unknown category did not refuse")
            return
        }

        #expect(diagnostics.first?.message.contains("observability") == true)
    }

    @Test func loadsNothingWhenTheProjectHoldsNoLibrary() {
        let load = aProject(["/work/threatmodel/payments.arch": "system \"P\" { }"])

        guard case .loaded(let libraries, _) = load.execute(
            LoadLibrariesRequest(root: "/work")
        ) else {
            Issue.record("a project with no library did not load")
            return
        }

        #expect(libraries.isEmpty)
    }
}
```

`FakeLibrarySource` is a new fake in `TestSupport` that wraps nothing: the
library language has no fake, so use `HclLibrarySource` here by importing
`ArchitectureDSL` in the test, exactly as the other use case tests do for the
architecture language. Check how `CompileControlsTests` gets its gateway and
follow it.

- [x] **Step 2: Run the test and watch it fail**

Run: `cd ThreatModelKit && swift test --filter LoadLibrariesTests`
Expected: FAIL, `cannot find 'LoadLibraries' in scope`.

- [x] **Step 3: Write `LoadLibraries.swift`**

```swift
public protocol LoadLibrariesUseCase {
    func execute(_ request: LoadLibrariesRequest) -> LoadLibrariesResponse
}

public struct LoadLibrariesRequest: Equatable, Sendable {
    public let root: String

    public init(root: String) {
        self.root = root
    }
}

public enum LoadLibrariesResponse: Equatable, Sendable {
    case loaded(libraries: [Library], warnings: [Diagnostic])
    /// A library that does not load stops the project, because half a
    /// catalogue draws a diagram nobody can trust.
    case refused(fileName: String, diagnostics: [Diagnostic])
    case notAProject(reason: String)
}

/// Reads every `.lib` file a project holds.
public struct LoadLibraries: LoadLibrariesUseCase {
    private let projects: ProjectSourceGateway
    private let sources: LibrarySourceGateway
    private let catalogue: TechnologyCatalogue

    public init(
        projects: ProjectSourceGateway,
        sources: LibrarySourceGateway,
        catalogue: TechnologyCatalogue
    ) {
        self.projects = projects
        self.sources = sources
        self.catalogue = catalogue
    }

    public func execute(_ request: LoadLibrariesRequest) -> LoadLibrariesResponse {
        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: request.root)
        } catch {
            return .notAProject(reason: String(describing: error))
        }

        var libraries: [Library] = []
        var warnings: [Diagnostic] = []
        var labels: Set<String> = []
        let taxonomy = catalogue.taxonomy()

        for path in layout.libraryPaths {
            let fileName = String(path.split(separator: "/").last ?? "")
            let text: String
            do {
                text = try projects.read(path: path)
            } catch {
                return .refused(
                    fileName: fileName,
                    diagnostics: [Diagnostic(severity: .error, line: 1, column: 1, message: String(describing: error))]
                )
            }

            let read = sources.read(text)
            guard let source = read.source else {
                return .refused(fileName: fileName, diagnostics: read.diagnostics)
            }
            warnings += read.warnings

            guard labels.insert(source.label).inserted else {
                return .refused(
                    fileName: fileName,
                    diagnostics: [
                        Diagnostic(
                            severity: .error,
                            line: 1,
                            column: 1,
                            message: "this project already holds a library called \"\(source.label)\""
                        )
                    ]
                )
            }

            let built = Library.build(from: source, taxonomy: taxonomy)
            guard let library = built.library else {
                return .refused(
                    fileName: fileName,
                    diagnostics: built.faults.map {
                        Diagnostic(severity: .error, line: 1, column: 1, message: $0.message)
                    }
                )
            }
            libraries.append(library)
        }

        return .loaded(libraries: libraries, warnings: warnings)
    }
}
```

- [x] **Step 4: Run the test and watch it pass**

Run: `cd ThreatModelKit && swift test --filter LoadLibrariesTests`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/LoadLibraries.swift \
        ThreatModelKit/Tests/UnitTests/LoadLibrariesTests.swift
git -c commit.gpgsign=false commit -m "feat: load every library a project holds"
```

---

### Task 10: the executable reads a project's libraries

**Files:**
- Modify: `ThreatModelKit/Sources/CommandLineApplication/CommandLineApplication.swift`
- Modify: `ThreatModelKit/Sources/CommandLineApplication/CommandLineDependencies.swift`
- Test: `ThreatModelKit/Tests/UnitTests/CommandLineApplicationTests.swift`

**Interfaces:**
- Consumes: `LoadLibraries`, `MergedCatalogue`, `LibraryStore`.
- Produces: `forEachSystem` builds `MergedCatalogue(base:store:)` with the
  project's libraries in the store, and refuses with exit code 2 when a `.lib`
  file does not load.

- [x] **Step 1: Write the failing test**

```swift
@Test func compilesAThreatALibraryDefines() throws {
    let projects = InMemoryProject()
    projects.put("""
    system "Payments" {
      component "ingest" { technology = "acme-cribl-stream" }
    }
    """, at: "/work/threatmodel/payments.arch")
    projects.put("""
    library "acme" {
      technology "cribl-stream" {
        name     = "Cribl Stream"
        category = "monitoring"
        threats  = ["pipeline-tamper"]
      }

      threat "pipeline-tamper" {
        name     = "Pipeline tampering"
        severity = "high"

        control "Sign pipeline configurations"
      }
    }
    """, at: "/work/threatmodel/library/acme.lib")

    var printed: [String] = []
    let code = CommandLineApplication(projects: projects, catalogue: { FakeTechnologyCatalogue() })
        .run(arguments: ["threatmodeller", "compile", "/work"], output: { printed.append($0) })

    #expect(code == 0)
    let written = try #require(projects.text(at: "/work/threatmodel/payments.controls"))
    #expect(written.contains("threat \"acme-pipeline-tamper\" on component \"ingest\""))
    #expect(written.contains("control \"Sign pipeline configurations\""))
}

@Test func refusesWhenALibraryDoesNotParse() {
    let projects = InMemoryProject()
    projects.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")
    projects.put("library \"acme\" { technology }", at: "/work/threatmodel/library/acme.lib")

    var printed: [String] = []
    let code = CommandLineApplication(projects: projects, catalogue: { FakeTechnologyCatalogue() })
        .run(arguments: ["threatmodeller", "check", "/work"], output: { printed.append($0) })

    #expect(code == 2)
    #expect(printed.contains { $0.contains("acme.lib") })
}
```

- [x] **Step 2: Run the test and watch it fail**

Run: `cd ThreatModelKit && swift test --filter CommandLineApplicationTests`
Expected: FAIL, the compiled file names no library threat.

- [x] **Step 3: Merge the libraries in `forEachSystem`**

In `CommandLineApplication`, after the catalogue is built and before the loop:

```swift
        let store = LibraryStore()
        let merged = MergedCatalogue(base: catalogue, store: store)

        switch LoadLibraries(
            projects: projects,
            sources: HclLibrarySource(),
            catalogue: catalogue
        ).execute(LoadLibrariesRequest(root: root)) {
        case .loaded(let libraries, let warnings):
            store.set(libraries)
            for warning in warnings { output("threatmodeller: \(warning.message)") }
        case .refused(let fileName, let diagnostics):
            for diagnostic in diagnostics {
                output(diagnostic.described(in: ProjectConvention.path(
                    ProjectConvention.path(layout.directory, ProjectConvention.libraryDirectory),
                    fileName
                )))
            }
            return ExitCode.didNotParse.rawValue
        case .notAProject(let reason):
            output("threatmodeller: \(reason)")
            return ExitCode.fileFault.rawValue
        }
```

and pass `merged` into each `CommandLineDependencies`. Add
`import ArchitectureDSL` if the file does not already hold it; it does.

- [x] **Step 4: Run the test and watch it pass**

Run: `cd ThreatModelKit && swift test`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/CommandLineApplication \
        ThreatModelKit/Tests/UnitTests/CommandLineApplicationTests.swift
git -c commit.gpgsign=false commit -m "feat: read a project's libraries in the executable"
```

---

### Task 11: the application reads a project's libraries

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`
- Modify: `threatmodeller/Dependencies.swift`
- Modify: `ThreatModelKit/Sources/TestSupport/TestDependencies.swift`
- Modify: `threatmodeller/project/ProjectSession.swift`
- Test: `threatmodellerTests/ProjectSessionTests.swift`

**Interfaces:**
- Produces: `UseCaseFactory.loadLibraries() -> LoadLibrariesUseCase` and
  `UseCaseFactory.useLibraries(_ libraries: [Library])`.
- `ProjectSession.open(root:preferring:)` loads the libraries before it chooses
  a system, and refuses the project when one does not load.

- [x] **Step 1: Write the failing test**

```swift
@MainActor
struct ProjectLibraryTests {
    private let payments = """
    system "Payments" {
      component "ingest" { technology = "acme-cribl-stream" }
    }
    """

    private let acme = """
    library "acme" {
      technology "cribl-stream" {
        name     = "Cribl Stream"
        category = "monitoring"
        threats  = ["pipeline-tamper"]
      }

      threat "pipeline-tamper" {
        name     = "Pipeline tampering"
        severity = "high"

        control "Sign pipeline configurations"
      }
    }
    """

    private func aProject(_ files: [String: String]) -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        for (path, text) in files { useCases.project.put(text, at: path) }
        return (ProjectSession(useCases: useCases, defaults: aTestDefaults()), useCases)
    }

    @Test func drawsAComponentALibraryDefines() throws {
        let (session, _) = aProject([
            "/work/threatmodel/payments.arch": payments,
            "/work/threatmodel/library/acme.lib": acme
        ])

        session.open(root: "/work")

        #expect(session.errorMessage == nil)
        let threats = try #require(session.model?.threats)
        #expect(threats.contains { $0.threatId == "acme-pipeline-tamper" })
    }

    @Test func showsTheLibraryAsItsOwnPaletteGroup() {
        let (session, _) = aProject([
            "/work/threatmodel/payments.arch": payments,
            "/work/threatmodel/library/acme.lib": acme
        ])

        session.open(root: "/work")

        #expect(session.model?.palette.contains { $0.id == "acme" } == true)
    }

    @Test func saysSoWhenALibraryDoesNotParse() {
        let (session, _) = aProject([
            "/work/threatmodel/payments.arch": payments,
            "/work/threatmodel/library/acme.lib": "library \"acme\" { technology }"
        ])

        session.open(root: "/work")

        #expect(session.model == nil)
        #expect(session.diagnosticsFileName == "acme.lib")
        #expect(session.errorMessage?.contains("acme.lib") == true)
    }
}
```

Read `ThreatModelSession.palette`'s element type before writing the second test
and match its property names.

- [x] **Step 2: Run the test and watch it fail**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS' -only-testing:threatmodellerTests/ProjectLibraryTests`
Expected: FAIL.

- [x] **Step 3: Add the two factory methods and call them**

`UseCaseFactory` gains:

```swift
    func loadLibraries() -> LoadLibrariesUseCase
    /// What the open project's libraries are, for every use case built after
    /// this call.
    func useLibraries(_ libraries: [Library])
```

`Dependencies` holds `private let libraries = LibraryStore()` and builds
`catalogue = MergedCatalogue(base: try BundledTechnologyCatalogue(), store: libraries)`,
then:

```swift
    func loadLibraries() -> LoadLibrariesUseCase {
        LoadLibraries(projects: projects, sources: librarySources, catalogue: catalogue)
    }

    func useLibraries(_ libraries: [Library]) {
        self.libraries.set(libraries)
    }
```

with `private let librarySources: LibrarySourceGateway = HclLibrarySource()`.
`TestDependencies` gains the same two, over its own `LibraryStore`.

`ProjectSession.open(root:preferring:)`, after `case .opened` and before it
chooses a system:

```swift
            switch useCases.loadLibraries().execute(LoadLibrariesRequest(root: root)) {
            case .loaded(let libraries, let warnings):
                useCases.useLibraries(libraries)
                diagnostics = warnings
            case .refused(let fileName, let faults):
                useCases.useLibraries([])
                model = nil
                diagnostics = faults
                diagnosticsFileName = fileName
                errorMessage = "\(fileName) did not parse."
                return
            case .notAProject(let reason):
                errorMessage = "That is not a project: \(reason)"
                return
            }
```

- [x] **Step 4: Run the tests and watch them pass**

Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift \
        ThreatModelKit/Sources/TestSupport/TestDependencies.swift \
        threatmodeller/Dependencies.swift \
        threatmodeller/project/ProjectSession.swift \
        threatmodellerTests/ProjectSessionTests.swift
git -c commit.gpgsign=false commit -m "feat: read a project's libraries in the application"
```

---

### Task 12: an acceptance test, and the documents

**Files:**
- Create: `ThreatModelKit/Tests/AcceptanceTests/UsingASharedLibraryTests.swift`
- Modify: `docs/LANGUAGE.md`
- Modify: `README.md`

- [x] **Step 1: Write the failing acceptance test**

```swift
import ArchitectureDSL
import Testing
import TestSupport
@testable import ThreatModelKit

/// A team defines Cribl once and a project names it.
@Suite("Using a shared library")
struct UsingASharedLibraryTests {
    @Test func answersAThreatThatOnlyTheLibraryDefines() throws {
        let projects = InMemoryProject()
        projects.put("""
        system "Payments" {
          component "ingest" { technology = "acme-cribl-stream" }
        }
        """, at: "/work/threatmodel/payments.arch")
        projects.put("""
        library "acme" {
          technology "cribl-stream" {
            name     = "Cribl Stream"
            category = "monitoring"
            threats  = ["pipeline-tamper"]
          }

          threat "pipeline-tamper" {
            name     = "Pipeline tampering"
            severity = "high"

            control "Sign pipeline configurations"
          }
        }
        """, at: "/work/threatmodel/library/acme.lib")

        let base = FakeTechnologyCatalogue()
        let store = LibraryStore()
        let merged = MergedCatalogue(base: base, store: store)
        guard case .loaded(let libraries, _) = LoadLibraries(
            projects: projects,
            sources: HclLibrarySource(),
            catalogue: base
        ).execute(LoadLibrariesRequest(root: "/work")) else {
            Issue.record("the library did not load")
            return
        }
        store.set(libraries)

        let compiled = CompileControls(
            catalogue: merged,
            architectureSources: HclArchitectureSource(),
            controlsSources: HclControlsSource(),
            layout: LayOutModel()
        ).execute(
            CompileControlsRequest(
                architectureText: try projects.read(path: "/work/threatmodel/payments.arch"),
                controlsText: nil
            )
        )

        guard case .compiled(let text, _, _, _) = compiled else {
            Issue.record("the controls did not compile")
            return
        }
        #expect(text.contains("threat \"acme-pipeline-tamper\" on component \"ingest\""))
        #expect(text.contains("control \"Sign pipeline configurations\""))
    }
}
```

Check `CompileControls`'s initialiser and its response's associated values
before writing this, and match them.

- [x] **Step 2: Run it and watch it fail, then pass**

Run: `cd ThreatModelKit && swift test --filter UsingASharedLibraryTests`

- [x] **Step 3: Write the library language into `docs/LANGUAGE.md`**

Add a section 6, "The library language", between the controls language and the
diagnostics section, and renumber the sections after it and the contents list.
It holds the same parts the other two languages have: a shape, the EBNF, the
block and attribute table, the identity rule and the fault list. Add the
library rules to section 9, "The grammar in full".

- [x] **Step 4: Write the library into `README.md`**

Add a row to the file table for `<name>.lib`, a paragraph under "The project
layout" for `threatmodel/library/`, and a link to the new section of the
language guide.

- [x] **Step 5: Run both suites**

Run: `cd ThreatModelKit && swift test`
Run: `xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
Expected: PASS.

- [x] **Step 6: Commit**

```bash
git add ThreatModelKit/Tests/AcceptanceTests/UsingASharedLibraryTests.swift \
        docs/LANGUAGE.md README.md
git -c commit.gpgsign=false commit -m "docs: document the library language"
```
