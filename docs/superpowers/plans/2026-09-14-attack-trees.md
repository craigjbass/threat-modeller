# Attack Trees Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A person writes a `.attacktree` file that states a route through several components, and the goal of that route scores higher while every step of it stays open.

**Architecture:** A fourth source language, read by the shared lexer, parsed into a plain value tree, and bound to the resolved threats after `ThreatResolver.resolve()` runs. The binding produces one boost for the goal threat and a set of stanzas the compiler writes into the `.controls` file. Nothing inside the seven existing scoring stages changes.

**Tech Stack:** Swift 6, Swift Testing (`import Testing`, `@Suite`, `@Test`), Swift Package Manager. The package is `ThreatModelKit`.

**Spec:** `docs/superpowers/specs/2026-09-14-attack-trees-design.md`

## Global Constraints

- Swift 6. Every new type is `Sendable`, and every value type is `Equatable`.
- Tests use Swift Testing. Never `import XCTest`. A suite is `@Suite("…") struct …Tests`, a test is `@Test func …()`, and an assertion is `#expect(…)` or `try #require(…)`.
- Every diagnostic message is copied from the spec word for word. A test asserts the whole string, never a substring.
- Every doc comment and every message is written in ASD-STE100: short common words, active voice, present tense, one instruction per sentence, no ambiguous pronouns.
- The scale maximum is 16. Read it from `RiskScore`, never write the number in two places.
- `Lexer.swift` and `Token.swift` are shared by all four languages. Do not change them.
- A model that states no tree scores exactly what it scores today. Every sample in `ThreatModelKit/Sources/CatalogueGateways/Resources/Samples/` states no tree, and `AssessThreatModelTests` proves the scores did not move.
- Run the whole suite with `swift test --package-path ThreatModelKit`.
- Commit at the end of every task. Never leave a task half-committed.

## File Structure

| File | Responsibility |
| --- | --- |
| `Sources/ThreatModelKit/architecture/domain/AttackTreeSource.swift` | the plain value tree a `.attacktree` file parses into |
| `Sources/ThreatModelKit/architecture/gateway/AttackTreeSourceGateway.swift` | the read and write protocol |
| `Sources/ArchitectureDSL/AttackTreeParser.swift` | tokens to `AttackTreeSource` |
| `Sources/ArchitectureDSL/AttackTreeWriter.swift` | `AttackTreeSource` to canonical text |
| `Sources/ArchitectureDSL/HclAttackTreeSource.swift` | the gateway that joins the two |
| `Sources/ThreatModelKit/assessment/domain/AttackTree.swift` | the bound tree, its nodes and its steps |
| `Sources/ThreatModelKit/assessment/domain/AttackTreeBinding.swift` | binding, open and closed, and the node rules |
| `Sources/ThreatModelKit/assessment/domain/AttackTreeScoring.swift` | stage 8 |
| `Sources/ThreatModelKit/reporting/usecase/MarkdownAttackTrees.swift` | the report section |

Modified: `ProjectConvention`, `ControlsSource`, `ControlsParser`, `ControlsWriter`, `CompileControls`, `CheckControlAnswers`, `StaleAnswers`, `ThreatModel`, `AssessThreatModel`, `Report`, `BuildThreatModelReport`, `MarkdownExecutiveSummary`, `MarkdownThreatStanza`, `ExportModelAsMarkdown`, `CommandLineApplication`, `docs/LANGUAGE.md`.

---

### Task 1: The project pairs a `.attacktree` file with its `.arch` file

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ProjectConvention.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ProjectSystem.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ProjectConventionTests.swift`

**Interfaces:**
- Consumes: nothing.
- Produces: `ProjectConvention.attackTreeExtension: String`, and `ProjectSystem.attackTreePath: String`.

- [ ] **Step 1: Write the failing test**

Add to `ThreatModelKit/Tests/UnitTests/ProjectConventionTests.swift`. Create the file with this header when it does not exist.

```swift
import Testing
import ThreatModelKit

@Suite("The project file convention")
struct ProjectConventionTests {
    @Test func pairsAnAttackTreeFileWithItsArchitectureFile() throws {
        let systems = ProjectConvention.systems(
            in: "/p/threatmodel",
            fileNames: ["payments.arch", "payments.controls", "payments.attacktree"]
        )

        let system = try #require(systems.first)
        #expect(system.attackTreePath == "/p/threatmodel/payments.attacktree")
    }

    @Test func namesAnAttackTreePathForASystemThatHasNoSuchFile() throws {
        let systems = ProjectConvention.systems(in: "/p", fileNames: ["payments.arch"])

        let system = try #require(systems.first)
        #expect(system.attackTreePath == "/p/payments.attacktree")
    }

    @Test func opensAProjectFromAnAttackTreeFile() throws {
        let found = try #require(
            ProjectConvention.system(atPath: "/p/threatmodel/payments.attacktree")
        )

        #expect(found.root == "/p")
        #expect(found.systemName == "payments")
    }
}
```

- [ ] **Step 2: Run the test to see it fail**

Run: `swift test --package-path ThreatModelKit --filter ProjectConventionTests`
Expected: FAIL, because `ProjectSystem` has no member `attackTreePath`.

- [ ] **Step 3: Add the extension and the path**

In `ProjectConvention.swift`, beside `reportExtension`:

```swift
    public static let attackTreeExtension = "attacktree"
```

In the same file, inside `systems(in:fileNames:)`, add the path to the value it builds:

```swift
                return ProjectSystem(
                    name: name,
                    architecturePath: path(directory, "\(name).\(architectureExtension)"),
                    controlsPath: path(directory, "\(name).\(controlsExtension)"),
                    reportPath: path(directory, "\(name).\(reportExtension)"),
                    attackTreePath: path(directory, "\(name).\(attackTreeExtension)")
                )
```

In the same file, inside `system(atPath:)`, widen the guard:

```swift
        guard fileExtension == architectureExtension
            || fileExtension == controlsExtension
            || fileExtension == attackTreeExtension
        else {
            return nil
        }
```

In `ProjectSystem.swift`, add the stored property and the initialiser parameter. Give the parameter no default, so every call site states the path and none can forget it.

```swift
    /// The attack trees a person wrote for this system. The file may not
    /// exist: a system that states no tree holds no such file.
    public let attackTreePath: String
```

- [ ] **Step 4: Run the test to see it pass**

Run: `swift test --package-path ThreatModelKit --filter ProjectConventionTests`
Expected: PASS.

- [ ] **Step 5: Build the whole package and fix every call site**

Run: `swift build --package-path ThreatModelKit`
Every `ProjectSystem(...)` call site now fails to build. Each one already knows its directory and its stem, so each one adds `attackTreePath:` the same way `reportPath:` is built beside it.

- [ ] **Step 6: Run the whole suite**

Run: `swift test --package-path ThreatModelKit`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ProjectConvention.swift \
        ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ProjectSystem.swift \
        ThreatModelKit/Tests/UnitTests/ProjectConventionTests.swift
git commit -m "feat: a project pairs a .attacktree file with its .arch file"
```

---

### Task 2: The value tree a `.attacktree` file parses into

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/AttackTreeSource.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/architecture/gateway/AttackTreeSourceGateway.swift`
- Test: `ThreatModelKit/Tests/UnitTests/AttackTreeSourceTests.swift`

**Interfaces:**
- Consumes: `Diagnostic`, `ThreatKey`, `SourceThreatAnswer.resolverKind(_:)`.
- Produces: `AttackTreeSource`, `SourceAttackTree`, `SourceTreeNode`, `SourceTreeStep`, `SourceTreeTarget`, `AttackTreeRead`, `AttackTreeSourceGateway`.

- [ ] **Step 1: Write the failing test**

```swift
import Testing
import ThreatModelKit

@Suite("The attack tree value tree")
struct AttackTreeSourceTests {
    @Test func mintsTheThreatKeyAFlowStepNames() {
        let target = SourceTreeTarget(threatId: "connection-mitm", sourceKind: "flow", sourceId: "cdn->api")

        #expect(target.key == ThreatKey(threatId: "connection-mitm", sourceId: "connection:cdn->api"))
    }

    @Test func mintsTheThreatKeyAComponentStepNames() {
        let target = SourceTreeTarget(threatId: "ssrf-attack", sourceKind: "component", sourceId: "appserver")

        #expect(target.key == ThreatKey(threatId: "ssrf-attack", sourceId: "component:appserver"))
    }

    @Test func listsEveryStepInATree() {
        let tree = SourceAttackTree(
            id: "steal-the-credential",
            goal: SourceTreeTarget(threatId: "data-exfiltration", sourceKind: "component", sourceId: "db"),
            root: .all([
                .step(SourceTreeStep(target: SourceTreeTarget(
                    threatId: "ssrf-attack", sourceKind: "component", sourceId: "appserver"
                ))),
                .any([
                    .step(SourceTreeStep(target: SourceTreeTarget(
                        threatId: "credential-theft", sourceKind: "component", sourceId: "appserver"
                    ))),
                ]),
            ])
        )

        #expect(tree.steps.map(\.target.threatId) == ["ssrf-attack", "credential-theft"])
    }
}
```

- [ ] **Step 2: Run the test to see it fail**

Run: `swift test --package-path ThreatModelKit --filter AttackTreeSourceTests`
Expected: FAIL, because none of these types exists.

- [ ] **Step 3: Write the value tree**

`AttackTreeSource.swift`:

```swift
/// What an attack tree file says, as plain values.
public struct AttackTreeSource: Equatable, Sendable {
    public let systemName: String
    public let catalogueTag: String?
    public let trees: [SourceAttackTree]

    public init(systemName: String, catalogueTag: String? = nil, trees: [SourceAttackTree] = []) {
        self.systemName = systemName
        self.catalogueTag = catalogueTag
        self.trees = trees
    }
}

/// One route a person wrote down.
public struct SourceAttackTree: Equatable, Sendable {
    public let id: String
    public let name: String?
    public let description: String?
    /// The percentage this tree adds to its goal when every step is open.
    /// Zero is a tree that narrates and moves no score.
    public let raisesRiskBy: Int
    public let goal: SourceTreeTarget
    public let root: SourceTreeNode

    public init(
        id: String,
        name: String? = nil,
        description: String? = nil,
        raisesRiskBy: Int = 0,
        goal: SourceTreeTarget,
        root: SourceTreeNode
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.raisesRiskBy = raisesRiskBy
        self.goal = goal
        self.root = root
    }

    /// Every step in the tree, in the order the file declares them.
    public var steps: [SourceTreeStep] { root.steps }

    /// The name a report shows, which is the `name` when the file states one
    /// and the id when it does not.
    public var displayName: String { name ?? id }
}

/// A branch of a tree, or a step at the end of one.
public indirect enum SourceTreeNode: Equatable, Sendable {
    case step(SourceTreeStep)
    /// Open while every child is open.
    case all([SourceTreeNode])
    /// Open while any child is open.
    case any([SourceTreeNode])

    public var steps: [SourceTreeStep] {
        switch self {
        case .step(let step): [step]
        case .all(let children), .any(let children): children.flatMap(\.steps)
        }
    }
}

public struct SourceTreeStep: Equatable, Sendable {
    public let target: SourceTreeTarget
    public let note: String?

    public init(target: SourceTreeTarget, note: String? = nil) {
        self.target = target
        self.note = note
    }
}

/// A threat on the thing that raises it, which is the shape the controls
/// language already writes as `threat "<id>" on component "<id>"`.
public struct SourceTreeTarget: Equatable, Sendable {
    public let threatId: String
    /// `component`, `zone` or `flow`.
    public let sourceKind: String
    public let sourceId: String

    public init(threatId: String, sourceKind: String, sourceId: String) {
        self.threatId = threatId
        self.sourceKind = sourceKind
        self.sourceId = sourceId
    }

    /// The key the resolver mints for the same threat. The file says `flow`
    /// and the resolver says `connection`; `SourceThreatAnswer` holds the one
    /// rule that maps them.
    public var key: ThreatKey {
        ThreatKey(
            threatId: threatId,
            sourceId: "\(SourceThreatAnswer.resolverKind(sourceKind)):\(sourceId)"
        )
    }
}

public struct AttackTreeRead: Equatable, Sendable {
    public let source: AttackTreeSource?
    public let diagnostics: [Diagnostic]

    public init(source: AttackTreeSource?, diagnostics: [Diagnostic]) {
        self.source = source
        self.diagnostics = diagnostics
    }

    public var hasErrors: Bool {
        diagnostics.contains { $0.severity == .error }
    }
}
```

`AttackTreeSourceGateway.swift`:

```swift
/// Reads and writes the attack tree language.
public protocol AttackTreeSourceGateway: Sendable {
    func read(_ text: String) -> AttackTreeRead
    func write(_ source: AttackTreeSource) -> String
}
```

- [ ] **Step 4: Run the test to see it pass**

Run: `swift test --package-path ThreatModelKit --filter AttackTreeSourceTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/architecture/domain/AttackTreeSource.swift \
        ThreatModelKit/Sources/ThreatModelKit/architecture/gateway/AttackTreeSourceGateway.swift \
        ThreatModelKit/Tests/UnitTests/AttackTreeSourceTests.swift
git commit -m "feat: the value tree an attack tree file parses into"
```

---

### Task 3: The parser reads a file with one tree

**Files:**
- Create: `ThreatModelKit/Sources/ArchitectureDSL/AttackTreeParser.swift`
- Create: `ThreatModelKit/Sources/ArchitectureDSL/HclAttackTreeSource.swift`
- Test: `ThreatModelKit/Tests/UnitTests/AttackTreeParserTests.swift`

**Interfaces:**
- Consumes: `Lexer`, `Token`, `TokenKind`, `AttackTreeSource` and the types of Task 2.
- Produces: `HclAttackTreeSource: AttackTreeSourceGateway`, `AttackTreeParser`.

- [ ] **Step 1: Write the failing test**

```swift
import ArchitectureDSL
import Testing
import ThreatModelKit

@Suite("Parsing the attack tree language")
struct AttackTreeParserTests {
    private let gateway = HclAttackTreeSource()

    private func read(_ text: String) -> AttackTreeRead { gateway.read(text) }

    private func errors(_ text: String) -> [Diagnostic] {
        read(text).diagnostics.filter { $0.severity == .error }
    }

    @Test func readsAFileWithOneTree() throws {
        let read = read("""
        attack_trees for "Two-Tier Web Application" {
          catalogue = "v1.0.1"

          tree "read-every-customer-record" {
            name           = "Read every customer record"
            description    = "An unauthenticated caller reaches the customer table."
            raises_risk_by = 40

            goal "data-exfiltration" on component "db"

            all_of {
              step "ssrf-attack" on component "appserver" {
                note = "The avatar import fetches a URL the user gives it."
              }

              any_of {
                step "credential-theft" on component "appserver"

                all_of {
                  step "excessive-permissions" on component "secrets"
                  step "privilege-escalation" on component "secrets"
                }
              }
            }
          }
        }
        """)

        let source = try #require(read.source)
        #expect(read.diagnostics.isEmpty)
        #expect(source.systemName == "Two-Tier Web Application")
        #expect(source.catalogueTag == "v1.0.1")

        let tree = try #require(source.trees.first)
        #expect(tree.id == "read-every-customer-record")
        #expect(tree.name == "Read every customer record")
        #expect(tree.raisesRiskBy == 40)
        #expect(tree.goal == SourceTreeTarget(
            threatId: "data-exfiltration", sourceKind: "component", sourceId: "db"
        ))
        #expect(tree.steps.map(\.target.threatId) == [
            "ssrf-attack", "credential-theft", "excessive-permissions", "privilege-escalation",
        ])
        #expect(tree.steps.first?.note == "The avatar import fetches a URL the user gives it.")
    }

    @Test func readsAStepWithNoBodyAsAStepWithAnEmptyBody() throws {
        let read = read("""
        attack_trees for "P" {
          tree "t" {
            goal "data-exfiltration" on component "db"
            step "ssrf-attack" on component "appserver"
          }
        }
        """)

        let tree = try #require(read.source?.trees.first)
        #expect(tree.steps.count == 1)
        #expect(tree.steps[0].note == nil)
        #expect(tree.raisesRiskBy == 0)
    }

    @Test func readsAFlowStep() throws {
        let read = read("""
        attack_trees for "P" {
          tree "t" {
            goal "data-exfiltration" on component "db"
            step "connection-mitm" on flow "cdn->api"
          }
        }
        """)

        let tree = try #require(read.source?.trees.first)
        #expect(tree.steps[0].target.sourceKind == "flow")
        #expect(tree.steps[0].target.sourceId == "cdn->api")
    }
}
```

- [ ] **Step 2: Run the test to see it fail**

Run: `swift test --package-path ThreatModelKit --filter AttackTreeParserTests`
Expected: FAIL, because `HclAttackTreeSource` does not exist.

- [ ] **Step 3: Write the parser and the gateway**

`HclAttackTreeSource.swift`:

```swift
import ThreatModelKit

/// Reads and writes the attack tree language.
public struct HclAttackTreeSource: AttackTreeSourceGateway {
    public init() {}

    public func read(_ text: String) -> AttackTreeRead {
        let scanned = Lexer(text).scan()
        var parser = AttackTreeParser(tokens: scanned.tokens, faults: scanned.faults)
        return parser.parse()
    }

    public func write(_ source: AttackTreeSource) -> String {
        AttackTreeWriter().write(source)
    }
}
```

`AttackTreeParser.swift`. The token helpers are the ones `ControlsParser` already uses, and this parser copies them rather than sharing them, because the two parsers report different messages and a shared helper would have to take both.

```swift
import ThreatModelKit

/// Turns tokens into an `AttackTreeSource`.
///
/// Like the other three parsers it never throws and never stops at the first
/// fault.
struct AttackTreeParser {
    private let tokens: [Token]
    private var index = 0
    private var diagnostics: [Diagnostic]

    init(tokens: [Token], faults: [Diagnostic]) {
        self.tokens = tokens
        diagnostics = faults
    }

    private static let sourceKinds: Set<String> = ["component", "zone", "flow"]

    mutating func parse() -> AttackTreeRead {
        guard let source = parseDocument() else {
            return AttackTreeRead(source: nil, diagnostics: diagnostics)
        }
        return AttackTreeRead(
            source: diagnostics.contains { $0.severity == .error } ? nil : source,
            diagnostics: diagnostics
        )
    }

    private mutating func parseDocument() -> AttackTreeSource? {
        guard expectKeyword("attack_trees") else { return nil }
        guard expectKeyword("for") else { return nil }
        guard let name = expect(.string, "the system's name") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var catalogueTag: String?
        var trees: [SourceAttackTree] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "catalogue":
                catalogueTag = parseTextAttribute()
            case "tree":
                if let tree = parseTree() { trees.append(tree) }
            default:
                record("an attack tree file holds catalogue and tree, not \"\(current.text)\"")
                skipToNextBlock()
            }
        }
        _ = expect(.rightBrace, "}")

        var seen: Set<String> = []
        for tree in trees where seen.insert(tree.id).inserted == false {
            record("the tree \"\(tree.id)\" is declared twice", at: tokens[0])
        }

        return AttackTreeSource(systemName: name.text, catalogueTag: catalogueTag, trees: trees)
    }

    private mutating func parseTree() -> SourceAttackTree? {
        let treeToken = current
        guard expectKeyword("tree") else { return nil }
        guard let id = expect(.string, "the tree's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var name: String?
        var description: String?
        var raisesRiskBy = 0
        var goals: [SourceTreeTarget] = []
        var roots: [SourceTreeNode] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "name": name = parseTextAttribute()
            case "description": description = parseTextAttribute()
            case "raises_risk_by":
                let token = current
                if let value = parseNumberAttribute() {
                    if (0...100).contains(value) {
                        raisesRiskBy = value
                    } else {
                        record("raises_risk_by is \(value); it runs from 0 to 100", at: token)
                    }
                }
            case "goal":
                if let goal = parseGoal() { goals.append(goal) }
            case "all_of", "any_of":
                if let node = parseNode(treeId: id.text) { roots.append(node) }
            case "step":
                if let step = parseStep() { roots.append(.step(step)) }
            default:
                record(
                    "a tree holds name, description, raises_risk_by, goal, all_of, any_of and "
                        + "step, not \"\(current.text)\""
                )
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        if goals.isEmpty {
            record("the tree \"\(id.text)\" states no goal", at: treeToken)
            return nil
        }
        if goals.count > 1 {
            record("the tree \"\(id.text)\" states two goals; it states one", at: treeToken)
            return nil
        }
        if roots.isEmpty {
            record("the tree \"\(id.text)\" holds no steps", at: treeToken)
            return nil
        }
        if roots.count > 1 {
            record("the tree \"\(id.text)\" holds two roots; it holds one", at: treeToken)
            return nil
        }

        return SourceAttackTree(
            id: id.text,
            name: name,
            description: description,
            raisesRiskBy: raisesRiskBy,
            goal: goals[0],
            root: roots[0]
        )
    }

    private mutating func parseGoal() -> SourceTreeTarget? {
        advance()
        return parseTarget()
    }

    private mutating func parseStep() -> SourceTreeStep? {
        advance()
        guard let target = parseTarget() else { return nil }
        guard current.kind == .leftBrace else {
            return SourceTreeStep(target: target)
        }
        advance()

        var note: String?
        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "note": note = parseTextAttribute()
            default:
                record("a step holds note, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")
        return SourceTreeStep(target: target, note: note)
    }

    /// The `"<threat>" on component "<id>"` header, which the controls
    /// language writes the same way.
    private mutating func parseTarget() -> SourceTreeTarget? {
        guard let threatId = expect(.string, "the threat's identifier") else { return nil }

        guard current.kind == .identifier, current.text == "on" else {
            record("a step says what raises it: on component, on zone or on flow")
            return nil
        }
        advance()

        let kindToken = current
        guard let kind = expect(.identifier, "component, zone or flow") else { return nil }
        if Self.sourceKinds.contains(kind.text) == false {
            record(
                "a step is raised by a component, a zone or a flow, not \"\(kind.text)\"",
                at: kindToken
            )
        }
        guard let sourceId = expect(.string, "the identifier of what raises it") else { return nil }

        return SourceTreeTarget(
            threatId: threatId.text,
            sourceKind: kind.text,
            sourceId: sourceId.text
        )
    }

    private mutating func parseNode(treeId: String) -> SourceTreeNode? {
        let word = current.text
        let token = current
        advance()
        guard expect(.leftBrace, "{") != nil else { return nil }

        var children: [SourceTreeNode] = []
        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "step":
                if let step = parseStep() { children.append(.step(step)) }
            case "all_of", "any_of":
                if let child = parseNode(treeId: treeId) { children.append(child) }
            default:
                record("an \(word) holds step, all_of and any_of, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        if children.isEmpty {
            record("the \(word) in the tree \"\(treeId)\" holds nothing", at: token)
            return nil
        }
        return word == "all_of" ? .all(children) : .any(children)
    }

    // MARK: reading the token list

    private var current: Token { tokens[min(index, tokens.count - 1)] }

    private mutating func advance() {
        if index < tokens.count - 1 { index += 1 }
    }

    private mutating func expectKeyword(_ keyword: String) -> Bool {
        guard current.kind == .identifier, current.text == keyword else {
            record("expected \(keyword), not \"\(current.text)\"")
            return false
        }
        advance()
        return true
    }

    private mutating func expect(_ kind: TokenKind, _ what: String) -> Token? {
        guard current.kind == kind else {
            record("expected \(what)")
            return nil
        }
        let token = current
        advance()
        return token
    }

    private mutating func parseTextAttribute() -> String? {
        advance()
        guard expect(.equals, "=") != nil else { return nil }
        return expect(.string, "a text in quotation marks")?.text
    }

    private mutating func parseNumberAttribute() -> Int? {
        advance()
        guard expect(.equals, "=") != nil else { return nil }
        guard let token = expect(.number, "a whole number") else { return nil }
        return Int(token.text)
    }

    private mutating func record(
        _ message: String,
        at token: Token? = nil,
        severity: Diagnostic.Severity = .error
    ) {
        let where_ = token ?? current
        diagnostics.append(
            Diagnostic(severity: severity, line: where_.line, column: where_.column, message: message)
        )
    }

    private mutating func skipToNextBlock() {
        var depth = 0
        while current.kind != .endOfFile {
            if current.kind == .leftBrace { depth += 1 }
            if current.kind == .rightBrace {
                if depth == 0 { return }
                depth -= 1
                advance()
                if depth == 0 { return }
                continue
            }
            advance()
        }
    }

    private mutating func skipAttribute() {
        advance()
        if current.kind == .equals {
            advance()
            advance()
        } else if current.kind == .leftBrace {
            skipToNextBlock()
        }
    }
}
```

`AttackTreeWriter` does not exist yet, so `HclAttackTreeSource.write` does not build. Add this placeholder file now and finish it in Task 5:

`AttackTreeWriter.swift`:

```swift
import ThreatModelKit

/// Writes an attack tree source in the canonical shape.
struct AttackTreeWriter {
    func write(_ source: AttackTreeSource) -> String {
        "attack_trees for \"\(source.systemName)\" {\n}\n"
    }
}
```

- [ ] **Step 4: Run the test to see it pass**

Run: `swift test --package-path ThreatModelKit --filter AttackTreeParserTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ArchitectureDSL/AttackTreeParser.swift \
        ThreatModelKit/Sources/ArchitectureDSL/AttackTreeWriter.swift \
        ThreatModelKit/Sources/ArchitectureDSL/HclAttackTreeSource.swift \
        ThreatModelKit/Tests/UnitTests/AttackTreeParserTests.swift
git commit -m "feat: the attack tree parser reads a file with one tree"
```

---

### Task 4: The parser refuses every fault the spec names

**Files:**
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/AttackTreeParser.swift` (only if a test finds a gap)
- Test: `ThreatModelKit/Tests/UnitTests/AttackTreeParserTests.swift`

**Interfaces:**
- Consumes: `HclAttackTreeSource` from Task 3.
- Produces: nothing new.

- [ ] **Step 1: Write the failing test**

Add to `AttackTreeParserTests`. Each argument is one row of section 3.5 of the spec, and the test asserts the whole message.

```swift
    @Test(arguments: [
        (
            """
            trees for "P" { }
            """,
            "expected attack_trees, not \"trees\""
        ),
        (
            """
            attack_trees of "P" { }
            """,
            "expected for, not \"of\""
        ),
        (
            """
            attack_trees for "P" {
              tree "t" { goal "g" on component "c" step "s" on component "c" }
              tree "t" { goal "g" on component "c" step "s" on component "c" }
            }
            """,
            "the tree \"t\" is declared twice"
        ),
        (
            """
            attack_trees for "P" {
              tree "t" { step "s" on component "c" }
            }
            """,
            "the tree \"t\" states no goal"
        ),
        (
            """
            attack_trees for "P" {
              tree "t" {
                goal "g" on component "c"
                goal "h" on component "c"
                step "s" on component "c"
              }
            }
            """,
            "the tree \"t\" states two goals; it states one"
        ),
        (
            """
            attack_trees for "P" {
              tree "t" { goal "g" on component "c" }
            }
            """,
            "the tree \"t\" holds no steps"
        ),
        (
            """
            attack_trees for "P" {
              tree "t" {
                goal "g" on component "c"
                step "s" on component "c"
                step "u" on component "c"
              }
            }
            """,
            "the tree \"t\" holds two roots; it holds one"
        ),
        (
            """
            attack_trees for "P" {
              tree "t" {
                goal "g" on component "c"
                all_of { }
              }
            }
            """,
            "the all_of in the tree \"t\" holds nothing"
        ),
        (
            """
            attack_trees for "P" {
              tree "t" {
                goal "g" on component "c"
                step "s" on gateway "c"
              }
            }
            """,
            "a step is raised by a component, a zone or a flow, not \"gateway\""
        ),
        (
            """
            attack_trees for "P" {
              tree "t" {
                goal "g" on component "c"
                step "s" component "c"
              }
            }
            """,
            "a step says what raises it: on component, on zone or on flow"
        ),
        (
            """
            attack_trees for "P" {
              tree "t" {
                raises_risk_by = 140
                goal "g" on component "c"
                step "s" on component "c"
              }
            }
            """,
            "raises_risk_by is 140; it runs from 0 to 100"
        ),
        (
            """
            attack_trees for "P" {
              tree "t" {
                owner = "Platform team"
                goal "g" on component "c"
                step "s" on component "c"
              }
            }
            """,
            "a tree holds name, description, raises_risk_by, goal, all_of, any_of and step, not \"owner\""
        ),
    ])
    func refusesTheFault(text: String, message: String) {
        #expect(errors(text).map(\.message).contains(message))
    }

    @Test func producesNoSourceWhenAFileHoldsAnError() {
        #expect(read("""
        attack_trees for "P" {
          tree "t" { step "s" on component "c" }
        }
        """).source == nil)
    }
```

- [ ] **Step 2: Run the test to see which rows fail**

Run: `swift test --package-path ThreatModelKit --filter AttackTreeParserTests`
Expected: the rows that the Task 3 parser does not yet produce fail, and each failure names the message it wanted.

- [ ] **Step 3: Close every gap the run named**

Change `AttackTreeParser.swift` until every row passes. Change only the message or the check the failing row names. Do not change a message a passing row already asserts.

- [ ] **Step 4: Run the test to see it pass**

Run: `swift test --package-path ThreatModelKit --filter AttackTreeParserTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ArchitectureDSL/AttackTreeParser.swift \
        ThreatModelKit/Tests/UnitTests/AttackTreeParserTests.swift
git commit -m "feat: the attack tree parser refuses every fault the design names"
```

---

### Task 5: The writer writes the canonical shape

**Files:**
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/AttackTreeWriter.swift`
- Test: `ThreatModelKit/Tests/UnitTests/AttackTreeWriterTests.swift`

**Interfaces:**
- Consumes: `AttackTreeSource` and its types.
- Produces: `AttackTreeWriter.write(_:) -> String`.

- [ ] **Step 1: Write the failing test**

```swift
import ArchitectureDSL
import Testing
import ThreatModelKit

@Suite("Writing the attack tree language")
struct AttackTreeWriterTests {
    private let gateway = HclAttackTreeSource()

    private let canonical = """
    attack_trees for "Two-Tier Web Application" {
      catalogue = "v1.0.1"

      tree "read-every-customer-record" {
        name           = "Read every customer record"
        description    = "An unauthenticated caller reaches the customer table."
        raises_risk_by = 40

        goal "data-exfiltration" on component "db"

        all_of {
          step "ssrf-attack" on component "appserver" {
            note = "The avatar import fetches a URL the user gives it."
          }

          any_of {
            step "credential-theft" on component "appserver"

            all_of {
              step "excessive-permissions" on component "secrets"
              step "privilege-escalation" on component "secrets"
            }
          }
        }
      }
    }

    """

    @Test func writesAnUnchangedSourceWithNoDiff() throws {
        let read = try #require(gateway.read(canonical).source)

        #expect(gateway.write(read) == canonical)
    }

    @Test func writesNoAttributeHoldingItsDefault() throws {
        let source = AttackTreeSource(
            systemName: "P",
            trees: [
                SourceAttackTree(
                    id: "t",
                    goal: SourceTreeTarget(threatId: "g", sourceKind: "component", sourceId: "c"),
                    root: .step(SourceTreeStep(target: SourceTreeTarget(
                        threatId: "s", sourceKind: "component", sourceId: "c"
                    )))
                ),
            ]
        )

        #expect(gateway.write(source) == """
        attack_trees for "P" {
          tree "t" {
            goal "g" on component "c"

            step "s" on component "c"
          }
        }

        """)
    }
}
```

- [ ] **Step 2: Run the test to see it fail**

Run: `swift test --package-path ThreatModelKit --filter AttackTreeWriterTests`
Expected: FAIL, because the placeholder writer writes an empty block.

- [ ] **Step 3: Write the writer**

Replace `AttackTreeWriter.swift` whole:

```swift
import ThreatModelKit

/// Writes an attack tree source in the canonical shape.
///
/// The shape follows section 8 of the language guide: two spaces for each
/// level, the equals signs of one run of attributes lined up, a blank line
/// between blocks, none before a closing brace, and no attribute holding its
/// default value. A node writes its children in the order the source states
/// them, because that order is what a person reads.
struct AttackTreeWriter {
    func write(_ source: AttackTreeSource) -> String {
        var lines: [String] = []
        lines.append("attack_trees for \(quoted(source.systemName)) {")

        var body: [String] = []
        if let catalogueTag = source.catalogueTag {
            body.append("catalogue = \(quoted(catalogueTag))")
            body.append("")
        }

        for tree in source.trees {
            body += treeBlock(tree)
            body.append("")
        }

        while body.last == "" { body.removeLast() }
        lines += indent(body)
        lines.append("}")
        return lines.joined(separator: "\n") + "\n"
    }

    private func treeBlock(_ tree: SourceAttackTree) -> [String] {
        var lines: [String] = ["tree \(quoted(tree.id)) {"]
        var body: [String] = []

        var attributes: [(String, String)] = []
        if let name = tree.name { attributes.append(("name", quoted(name))) }
        if let description = tree.description {
            attributes.append(("description", quoted(description)))
        }
        if tree.raisesRiskBy != 0 {
            attributes.append(("raises_risk_by", String(tree.raisesRiskBy)))
        }
        if attributes.isEmpty == false {
            body += aligned(attributes)
            body.append("")
        }

        body.append("goal \(target(tree.goal))")
        body.append("")
        body += node(tree.root)

        lines += indent(body)
        lines.append("}")
        return lines
    }

    private func node(_ node: SourceTreeNode) -> [String] {
        switch node {
        case .step(let step):
            return stepBlock(step)
        case .all(let children):
            return group("all_of", children)
        case .any(let children):
            return group("any_of", children)
        }
    }

    private func group(_ word: String, _ children: [SourceTreeNode]) -> [String] {
        var body: [String] = []
        for child in children {
            body += self.node(child)
            body.append("")
        }
        while body.last == "" { body.removeLast() }
        return ["\(word) {"] + indent(body) + ["}"]
    }

    private func stepBlock(_ step: SourceTreeStep) -> [String] {
        let header = "step \(target(step.target))"
        guard let note = step.note else { return [header] }
        return [header + " {"] + indent(["note = \(quoted(note))"]) + ["}"]
    }

    private func target(_ target: SourceTreeTarget) -> String {
        "\(quoted(target.threatId)) on \(target.sourceKind) \(quoted(target.sourceId))"
    }

    private func aligned(_ attributes: [(String, String)]) -> [String] {
        let width = attributes.map(\.0.count).max() ?? 0
        return attributes.map { name, value in
            name.padding(toLength: width, withPad: " ", startingAt: 0) + " = " + value
        }
    }

    private func indent(_ lines: [String]) -> [String] {
        lines.map { $0.isEmpty ? "" : "  " + $0 }
    }

    private func quoted(_ text: String) -> String {
        "\"" + text
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "\t", with: "\\t")
            + "\""
    }
}
```

- [ ] **Step 4: Run the test to see it pass**

Run: `swift test --package-path ThreatModelKit --filter AttackTreeWriterTests`
Expected: PASS. When the blank lines differ, read the expected text in the test and change the writer, never the test: the test states the canonical shape.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ArchitectureDSL/AttackTreeWriter.swift \
        ThreatModelKit/Tests/UnitTests/AttackTreeWriterTests.swift
git commit -m "feat: the attack tree writer writes the canonical shape"
```

---

### Task 6: The bound tree, its steps and their states

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/AttackTree.swift`
- Test: `ThreatModelKit/Tests/UnitTests/AttackTreeTests.swift`

**Interfaces:**
- Consumes: `ThreatKey`.
- Produces: `BoundAttackTree`, `BoundStep`, `StepState`.

- [ ] **Step 1: Write the failing test**

```swift
import Testing
import ThreatModelKit

@Suite("The bound attack tree")
struct AttackTreeTests {
    private func step(_ id: String, _ state: StepState, _ factor: Double) -> BoundStep {
        BoundStep(
            key: ThreatKey(threatId: id, sourceId: "component:c"),
            threatName: id,
            sourceName: "c",
            state: state,
            closedBy: state == .closed ? "a control" : nil,
            factor: factor,
            note: nil
        )
    }

    @Test func aTreeIsStaleWhenAnyStepIsUnbound() {
        let tree = BoundAttackTree(
            id: "t",
            name: "T",
            description: nil,
            raisesRiskBy: 40,
            goal: ThreatKey(threatId: "g", sourceId: "component:db"),
            goalName: "G",
            goalSourceName: "db",
            steps: [step("a", .open, 1.0), step("b", .unbound, 1.0)],
            chainFactor: 0,
            isOpen: false,
            isStale: true,
            scoreBefore: 5,
            score: 5
        )

        #expect(tree.isStale)
        #expect(tree.score == tree.scoreBefore)
    }

    @Test func aTreeNamesItselfByIdWhenItStatesNoName() {
        #expect(SourceAttackTree(
            id: "t",
            goal: SourceTreeTarget(threatId: "g", sourceKind: "component", sourceId: "db"),
            root: .step(SourceTreeStep(target: SourceTreeTarget(
                threatId: "s", sourceKind: "component", sourceId: "c"
            )))
        ).displayName == "t")
    }
}
```

- [ ] **Step 2: Run the test to see it fail**

Run: `swift test --package-path ThreatModelKit --filter AttackTreeTests`
Expected: FAIL, because `BoundAttackTree` does not exist.

- [ ] **Step 3: Write the bound tree**

```swift
/// What one step of a tree is doing today.
public enum StepState: String, Equatable, Sendable {
    /// The model raises this threat, and nothing closes it.
    case open
    /// An implemented control or a compensating control closes it.
    case closed
    /// The model no longer raises this threat on this source.
    case unbound
}

/// One step of a tree, matched against the resolved model.
public struct BoundStep: Equatable, Sendable {
    public let key: ThreatKey
    public let threatName: String
    public let sourceName: String
    public let state: StepState
    /// The control that closed this step, or nil when nothing closed it.
    public let closedBy: String?
    /// The likelihood factor this step carries, from 0.0 to 1.0.
    public let factor: Double
    public let note: String?

    public init(
        key: ThreatKey,
        threatName: String,
        sourceName: String,
        state: StepState,
        closedBy: String? = nil,
        factor: Double,
        note: String? = nil
    ) {
        self.key = key
        self.threatName = threatName
        self.sourceName = sourceName
        self.state = state
        self.closedBy = closedBy
        self.factor = factor
        self.note = note
    }
}

/// One tree a person wrote, matched against the resolved model and scored.
public struct BoundAttackTree: Equatable, Sendable {
    public let id: String
    public let name: String
    public let description: String?
    public let raisesRiskBy: Int
    public let goal: ThreatKey
    public let goalName: String
    public let goalSourceName: String
    /// Every step, in the order the file states them.
    public let steps: [BoundStep]
    /// The factor the weakest open step gave, from 0.0 to 1.0. Zero when the
    /// root is closed or the tree is stale.
    public let chainFactor: Double
    public let isOpen: Bool
    /// True when a step or the goal no longer binds. A stale tree moves no
    /// score, and `threatmodeller check` exits 1 while one remains.
    public let isStale: Bool
    public let scoreBefore: Int
    public let score: Int

    public init(
        id: String,
        name: String,
        description: String?,
        raisesRiskBy: Int,
        goal: ThreatKey,
        goalName: String,
        goalSourceName: String,
        steps: [BoundStep],
        chainFactor: Double,
        isOpen: Bool,
        isStale: Bool,
        scoreBefore: Int,
        score: Int
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.raisesRiskBy = raisesRiskBy
        self.goal = goal
        self.goalName = goalName
        self.goalSourceName = goalSourceName
        self.steps = steps
        self.chainFactor = chainFactor
        self.isOpen = isOpen
        self.isStale = isStale
        self.scoreBefore = scoreBefore
        self.score = score
    }

    /// The chain factor as a whole percentage, which is what the controls file
    /// and the report both print.
    public var chainPercentage: Int { Int((chainFactor * 100).rounded()) }
}
```

- [ ] **Step 4: Run the test to see it pass**

Run: `swift test --package-path ThreatModelKit --filter AttackTreeTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/assessment/domain/AttackTree.swift \
        ThreatModelKit/Tests/UnitTests/AttackTreeTests.swift
git commit -m "feat: the bound attack tree, its steps and their states"
```

---

### Task 7: Binding, the open rule and the node rules

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/AttackTreeBinding.swift`
- Test: `ThreatModelKit/Tests/UnitTests/AttackTreeBindingTests.swift`

**Interfaces:**
- Consumes: `SourceAttackTree`, `SourceTreeNode`, `ResolvedThreat`, `BoundAttackTree`, `BoundStep`, `StepState`, `Likelihood`, `RiskScore`.
- Produces: `AttackTreeBinding.bind(trees:to:) -> [BoundAttackTree]`.

- [ ] **Step 1: Write the failing test**

```swift
import Testing
import ThreatModelKit

@Suite("Binding an attack tree to a resolved model")
struct AttackTreeBindingTests {
    private func resolved(
        _ threatId: String,
        _ componentId: String,
        score: Int = 8,
        statuses: [ControlStatus] = [.notImplemented],
        compensating: [CompensatingControl] = [],
        likelihood: Likelihood = .commodity
    ) -> ResolvedThreat {
        ResolvedThreatFixture.make(
            threatId: threatId,
            componentId: componentId,
            score: score,
            statuses: statuses,
            compensating: compensating,
            likelihood: likelihood
        )
    }

    private func target(_ threatId: String, _ componentId: String) -> SourceTreeTarget {
        SourceTreeTarget(threatId: threatId, sourceKind: "component", sourceId: componentId)
    }

    private func tree(
        raises: Int = 40,
        goal: SourceTreeTarget,
        root: SourceTreeNode
    ) -> SourceAttackTree {
        SourceAttackTree(id: "t", raisesRiskBy: raises, goal: goal, root: root)
    }

    private func step(_ threatId: String, _ componentId: String) -> SourceTreeNode {
        .step(SourceTreeStep(target: target(threatId, componentId)))
    }

    @Test func bindsAStepTheModelRaises() throws {
        let bound = AttackTreeBinding.bind(
            trees: [tree(goal: target("g", "db"), root: step("a", "api"))],
            to: [resolved("g", "db"), resolved("a", "api")]
        )

        let first = try #require(bound.first)
        #expect(first.isStale == false)
        #expect(first.steps.map(\.state) == [.open])
    }

    @Test func makesTheWholeTreeStaleWhenOneStepDoesNotBind() throws {
        let bound = AttackTreeBinding.bind(
            trees: [tree(goal: target("g", "db"), root: .all([step("a", "api"), step("b", "gone")]))],
            to: [resolved("g", "db"), resolved("a", "api")]
        )

        let first = try #require(bound.first)
        #expect(first.isStale)
        #expect(first.steps.map(\.state) == [.open, .unbound])
        #expect(first.score == first.scoreBefore)
    }

    @Test func makesTheWholeTreeStaleWhenTheGoalDoesNotBind() throws {
        let bound = AttackTreeBinding.bind(
            trees: [tree(goal: target("g", "gone"), root: step("a", "api"))],
            to: [resolved("a", "api")]
        )

        #expect(try #require(bound.first).isStale)
    }

    @Test(arguments: [
        (ControlStatus.implemented, StepState.closed),
        (ControlStatus.notApplicable, StepState.open),
        (ControlStatus.accepted, StepState.open),
        (ControlStatus.notImplemented, StepState.open),
    ])
    func readsAStatusAsAState(status: ControlStatus, state: StepState) throws {
        let bound = AttackTreeBinding.bind(
            trees: [tree(goal: target("g", "db"), root: step("a", "api"))],
            to: [resolved("g", "db"), resolved("a", "api", statuses: [status])]
        )

        #expect(try #require(bound.first).steps.map(\.state) == [state])
    }

    @Test func closesAStepACompensatingControlAnswers() throws {
        let bound = AttackTreeBinding.bind(
            trees: [tree(goal: target("g", "db"), root: step("a", "api"))],
            to: [
                resolved("g", "db"),
                resolved("a", "api", compensating: [
                    CompensatingControl(label: "A break-glass account", reducesRiskBy: 40, rationale: "It alerts."),
                ]),
            ]
        )

        #expect(try #require(bound.first).steps.map(\.state) == [.closed])
    }

    @Test func closesAnAllOfWhenOneChildIsClosed() throws {
        let bound = AttackTreeBinding.bind(
            trees: [tree(goal: target("g", "db"), root: .all([step("a", "api"), step("b", "api")]))],
            to: [
                resolved("g", "db"),
                resolved("a", "api"),
                resolved("b", "api", statuses: [.implemented]),
            ]
        )

        #expect(try #require(bound.first).isOpen == false)
    }

    @Test func keepsAnAnyOfOpenWhileOneChildIsOpen() throws {
        let bound = AttackTreeBinding.bind(
            trees: [tree(goal: target("g", "db"), root: .any([step("a", "api"), step("b", "api")]))],
            to: [
                resolved("g", "db"),
                resolved("a", "api"),
                resolved("b", "api", statuses: [.implemented]),
            ]
        )

        #expect(try #require(bound.first).isOpen)
    }

    @Test func takesTheWeakestChildOfAnAllOf() throws {
        let bound = AttackTreeBinding.bind(
            trees: [tree(goal: target("g", "db"), root: .all([step("a", "api"), step("b", "api")]))],
            to: [
                resolved("g", "db"),
                resolved("a", "api", likelihood: .commodity),
                resolved("b", "api", likelihood: .research),
            ]
        )

        #expect(try #require(bound.first).chainFactor == 0.25)
    }

    @Test func takesTheStrongestOpenChildOfAnAnyOf() throws {
        let bound = AttackTreeBinding.bind(
            trees: [tree(goal: target("g", "db"), root: .any([step("a", "api"), step("b", "api")]))],
            to: [
                resolved("g", "db"),
                resolved("a", "api", likelihood: .targeted),
                resolved("b", "api", likelihood: .research),
            ]
        )

        #expect(try #require(bound.first).chainFactor == 0.6)
    }
}
```

The fixture keeps the test readable. Add it to `ThreatModelKit/Sources/TestSupport/ResolvedThreatFixture.swift`:

```swift
import ThreatModelKit

/// Builds a `ResolvedThreat` with the four fields a binding test cares about
/// and a plain default for the rest.
public enum ResolvedThreatFixture {
    public static func make(
        threatId: String,
        componentId: String,
        score: Int,
        statuses: [ControlStatus],
        compensating: [CompensatingControl],
        likelihood: Likelihood
    ) -> ResolvedThreat {
        let threat = Threat(
            id: ThreatId(threatId),
            name: threatId,
            description: "",
            severity: .high,
            stride: [],
            controls: []
        )
        let controls = statuses.enumerated().map { index, status in
            ResolvedControl(
                description: "control \(index)",
                isTechnologySpecific: false,
                key: ControlKey(value: "\(threatId)-\(index)"),
                isImplemented: status == .implemented,
                status: status
            )
        }
        return ResolvedThreat(
            threat: threat,
            severity: .high,
            source: .component(id: ComponentId(componentId), name: componentId, providerId: ProviderId("aws")),
            sensitivity: .confidential,
            score: RiskScore(value: score),
            controls: controls,
            context: nil,
            isTlsMitigated: false,
            overrideKey: SeverityOverrideKey(value: "\(componentId)/\(threatId)"),
            overriddenSeverityId: nil,
            mitigatedBy: [],
            compensating: compensating,
            scoreBeforeCompensation: score,
            scoreBeforePathwayMitigation: score,
            scoreBeforeControls: score,
            mitigatedByComponents: [],
            likelihood: likelihood,
            scoreBeforeLikelihood: score,
            likelihoodFinding: nil,
            severityDecision: nil,
            scoreIfAssumptionsHold: score,
            assumedMitigations: []
        )
    }
}
```

WARNING: `ResolvedThreat.init` and `Threat.init` take the parameters the current source states. Read
`ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ThreatResolver.swift` and
`ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/Threat.swift`, and change the fixture to match them
before you run the test. The names above are the ones this plan was written against.

- [ ] **Step 2: Run the test to see it fail**

Run: `swift test --package-path ThreatModelKit --filter AttackTreeBindingTests`
Expected: FAIL, because `AttackTreeBinding` does not exist.

- [ ] **Step 3: Write the binding**

```swift
/// Matches the trees a person wrote against the threats the model raises.
///
/// A step binds when the resolved model raises that threat on that source. One
/// step that does not bind makes the whole tree stale, because a route with a
/// step missing is a claim about a system that is no longer there.
public enum AttackTreeBinding {
    /// What a node is doing: whether an attacker can still walk it, and the
    /// weakest factor on the way.
    private struct NodeState {
        let isOpen: Bool
        let factor: Double
    }

    public static func bind(
        trees: [SourceAttackTree],
        to resolved: [ResolvedThreat]
    ) -> [BoundAttackTree] {
        var byKey: [ThreatKey: ResolvedThreat] = [:]
        for threat in resolved {
            byKey[ThreatKey(threatId: threat.threat.id.value, sourceId: threat.source.id)] = threat
        }

        return trees.map { tree in
            let steps = tree.steps.map { self.step($0, in: byKey) }
            let goal = byKey[tree.goal.key]
            let isStale = goal == nil || steps.contains { $0.state == .unbound }

            let root = isStale
                ? NodeState(isOpen: false, factor: 0)
                : state(of: tree.root, in: byKey)

            let scoreBefore = goal?.score.value ?? 0

            return BoundAttackTree(
                id: tree.id,
                name: tree.displayName,
                description: tree.description,
                raisesRiskBy: tree.raisesRiskBy,
                goal: tree.goal.key,
                goalName: goal?.threat.name ?? tree.goal.threatId,
                goalSourceName: goal?.source.displayName ?? tree.goal.sourceId,
                steps: steps,
                chainFactor: root.isOpen ? root.factor : 0,
                isOpen: root.isOpen,
                isStale: isStale,
                scoreBefore: scoreBefore,
                score: scoreBefore
            )
        }
    }

    private static func step(
        _ step: SourceTreeStep,
        in byKey: [ThreatKey: ResolvedThreat]
    ) -> BoundStep {
        let key = step.target.key
        guard let threat = byKey[key] else {
            return BoundStep(
                key: key,
                threatName: step.target.threatId,
                sourceName: step.target.sourceId,
                state: .unbound,
                factor: 0,
                note: step.note
            )
        }

        // An implemented control or a compensating control closes a step.
        // `not_applicable` and `accepted` answer the threat and close nothing:
        // a control that does not apply stops nobody, and a team that accepts
        // a risk still lets an attacker take the step.
        let closingControl = threat.controls.first { $0.status == .implemented }
        let isClosed = closingControl != nil || threat.compensating.isEmpty == false

        return BoundStep(
            key: key,
            threatName: threat.threat.name,
            sourceName: threat.source.displayName,
            state: isClosed ? .closed : .open,
            closedBy: closingControl?.description ?? threat.compensating.first?.label,
            factor: threat.likelihood.factor,
            note: step.note
        )
    }

    private static func state(
        of node: SourceTreeNode,
        in byKey: [ThreatKey: ResolvedThreat]
    ) -> NodeState {
        switch node {
        case .step(let step):
            let bound = self.step(step, in: byKey)
            return NodeState(isOpen: bound.state == .open, factor: bound.factor)

        case .all(let children):
            let states = children.map { state(of: $0, in: byKey) }
            // Every child is needed, so the chain is as likely as its weakest
            // one, and one closed child closes the branch.
            return NodeState(
                isOpen: states.allSatisfy(\.isOpen),
                factor: states.map(\.factor).min() ?? 0
            )

        case .any(let children):
            let states = children.map { state(of: $0, in: byKey) }
            let open = states.filter(\.isOpen)
            // An attacker takes the easiest branch that is still open.
            return NodeState(
                isOpen: open.isEmpty == false,
                factor: open.map(\.factor).max() ?? 0
            )
        }
    }
}
```

- [ ] **Step 4: Run the test to see it pass**

Run: `swift test --package-path ThreatModelKit --filter AttackTreeBindingTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/assessment/domain/AttackTreeBinding.swift \
        ThreatModelKit/Sources/TestSupport/ResolvedThreatFixture.swift \
        ThreatModelKit/Tests/UnitTests/AttackTreeBindingTests.swift
git commit -m "feat: an attack tree binds to the threats the model raises"
```

---

### Task 8: Stage 8 raises the goal

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/AttackTreeScoring.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/AttackTreeBinding.swift`
- Test: `ThreatModelKit/Tests/UnitTests/AttackTreeScoreTests.swift`

**Interfaces:**
- Consumes: `BoundAttackTree`, `ResolvedThreat`, `RiskScore`.
- Produces: `AttackTreeScoring.apply(trees:to:) -> (threats: [ResolvedThreat], trees: [BoundAttackTree])`.

- [ ] **Step 1: Write the failing test**

```swift
import Testing
import ThreatModelKit

@Suite("Stage 8: an attack tree raises its goal")
struct AttackTreeScoreTests {
    private func target(_ threatId: String, _ componentId: String) -> SourceTreeTarget {
        SourceTreeTarget(threatId: threatId, sourceKind: "component", sourceId: componentId)
    }

    private func run(
        raises: Int,
        goalScore: Int,
        steps: [(String, ControlStatus, Likelihood)]
    ) -> (threats: [ResolvedThreat], trees: [BoundAttackTree]) {
        let tree = SourceAttackTree(
            id: "t",
            raisesRiskBy: raises,
            goal: target("g", "db"),
            root: .all(steps.map { .step(SourceTreeStep(target: target($0.0, "api"))) })
        )
        var resolved = [
            ResolvedThreatFixture.make(
                threatId: "g", componentId: "db", score: goalScore,
                statuses: [.notImplemented], compensating: [], likelihood: .commodity
            ),
        ]
        resolved += steps.map {
            ResolvedThreatFixture.make(
                threatId: $0.0, componentId: "api", score: 4,
                statuses: [$0.1], compensating: [], likelihood: $0.2
            )
        }
        let bound = AttackTreeBinding.bind(trees: [tree], to: resolved)
        return AttackTreeScoring.apply(trees: bound, to: resolved)
    }

    private func goalScore(_ result: (threats: [ResolvedThreat], trees: [BoundAttackTree])) -> Int {
        result.threats.first { $0.threat.id.value == "g" }?.score.value ?? 0
    }

    @Test func reachesSevenOnTheWorkedExample() {
        let result = run(raises: 40, goalScore: 5, steps: [
            ("a", .notImplemented, .commodity),
            ("b", .notImplemented, .commodity),
        ])

        #expect(goalScore(result) == 7)
        #expect(result.trees[0].score == 7)
        #expect(result.trees[0].scoreBefore == 5)
        #expect(result.trees[0].chainPercentage == 100)
    }

    @Test func raisesNothingWhenTheRootIsClosed() {
        let result = run(raises: 40, goalScore: 5, steps: [
            ("a", .implemented, .commodity),
            ("b", .notImplemented, .commodity),
        ])

        #expect(goalScore(result) == 5)
        #expect(result.trees[0].chainFactor == 0)
    }

    @Test func raisesNothingWhenTheTreeStatesZero() {
        let result = run(raises: 0, goalScore: 5, steps: [("a", .notImplemented, .commodity)])

        #expect(goalScore(result) == 5)
    }

    @Test(arguments: [
        (Likelihood.commodity, 7),
        (Likelihood.targeted, 6),
        (Likelihood.research, 6),
    ])
    func boundsTheBoostByTheWeakestStep(weakest: Likelihood, expected: Int) {
        let result = run(raises: 40, goalScore: 5, steps: [
            ("a", .notImplemented, .commodity),
            ("b", .notImplemented, weakest),
        ])

        #expect(goalScore(result) == expected)
    }

    @Test func neverCarriesAScoreAboveSixteen() {
        let result = run(raises: 100, goalScore: 15, steps: [("a", .notImplemented, .commodity)])

        #expect(goalScore(result) == 16)
    }

    @Test func leavesAThreatNoTreeNamesWhereItIs() {
        let result = run(raises: 40, goalScore: 5, steps: [("a", .notImplemented, .commodity)])

        #expect(result.threats.first { $0.threat.id.value == "a" }?.score.value == 4)
    }
}
```

- [ ] **Step 2: Run the test to see it fail**

Run: `swift test --package-path ThreatModelKit --filter AttackTreeScoreTests`
Expected: FAIL, because `AttackTreeScoring` does not exist.

- [ ] **Step 3: Write the stage**

```swift
/// Stage 8: a tree raises the score of the threat it names as its goal.
///
/// The seven stages of `ThreatResolver` run one threat at a time. This one
/// cannot: whether a step is open depends on another threat's answers, so it
/// reads the whole resolved set and runs after it.
///
/// The goal's own likelihood is not in the chain. Stage 6 already applied it to
/// the goal's own score, and counting it again would apply it twice.
public enum AttackTreeScoring {
    public static func apply(
        trees: [BoundAttackTree],
        to resolved: [ResolvedThreat]
    ) -> (threats: [ResolvedThreat], trees: [BoundAttackTree]) {
        guard trees.isEmpty == false else { return (resolved, trees) }

        // Two trees on one goal give the stronger boost, not the sum, which is
        // the rule every other stage of this application follows.
        var boostByGoal: [ThreatKey: Double] = [:]
        for tree in trees where tree.isStale == false && tree.isOpen {
            let boost = Double(tree.raisesRiskBy) / 100 * tree.chainFactor
            boostByGoal[tree.goal] = max(boostByGoal[tree.goal] ?? 0, boost)
        }

        var scoreByGoal: [ThreatKey: Int] = [:]
        let threats = resolved.map { threat -> ResolvedThreat in
            let key = ThreatKey(threatId: threat.threat.id.value, sourceId: threat.source.id)
            guard let boost = boostByGoal[key], boost > 0 else { return threat }
            let raised = raise(threat.score.value, by: boost)
            scoreByGoal[key] = raised
            return threat.withScore(RiskScore(value: raised))
        }

        let scored = trees.map { tree in
            tree.withScore(scoreByGoal[tree.goal] ?? tree.scoreBefore)
        }

        return (threats, scored)
    }

    /// The score a boost leaves, never above the top of the scale.
    static func raise(_ score: Int, by boost: Double) -> Int {
        min(maximumScore, Int((Double(score) * (1 + boost)).rounded()))
    }

    /// The top of the scale `RiskScore` states: the highest severity rank
    /// multiplied by the highest data sensitivity rank.
    static let maximumScore = 16
}
```

Add the two `with…` helpers. `ResolvedThreat` has many fields, so each helper rebuilds the value rather than making the fields variable.

In `ThreatResolver.swift`, beside `ResolvedThreat`:

```swift
public extension ResolvedThreat {
    /// The same threat with another score. Stage 8 is the only caller.
    func withScore(_ score: RiskScore) -> ResolvedThreat {
        ResolvedThreat(
            threat: threat,
            severity: severity,
            source: source,
            sensitivity: sensitivity,
            score: score,
            controls: controls,
            context: context,
            isTlsMitigated: isTlsMitigated,
            overrideKey: overrideKey,
            overriddenSeverityId: overriddenSeverityId,
            mitigatedBy: mitigatedBy,
            compensating: compensating,
            scoreBeforeCompensation: scoreBeforeCompensation,
            scoreBeforePathwayMitigation: scoreBeforePathwayMitigation,
            scoreBeforeControls: scoreBeforeControls,
            mitigatedByComponents: mitigatedByComponents,
            likelihood: likelihood,
            scoreBeforeLikelihood: scoreBeforeLikelihood,
            likelihoodFinding: likelihoodFinding,
            severityDecision: severityDecision,
            scoreIfAssumptionsHold: scoreIfAssumptionsHold,
            assumedMitigations: assumedMitigations
        )
    }
}
```

In `AttackTree.swift`, beside `BoundAttackTree`:

```swift
public extension BoundAttackTree {
    /// The same tree with the score its goal reached.
    func withScore(_ score: Int) -> BoundAttackTree {
        BoundAttackTree(
            id: id,
            name: name,
            description: description,
            raisesRiskBy: raisesRiskBy,
            goal: goal,
            goalName: goalName,
            goalSourceName: goalSourceName,
            steps: steps,
            chainFactor: chainFactor,
            isOpen: isOpen,
            isStale: isStale,
            scoreBefore: scoreBefore,
            score: score
        )
    }
}
```

WARNING: copy the parameter list of `ResolvedThreat.init` from the current source. When a field has been added since this plan was written, the build names it.

- [ ] **Step 4: Run the test to see it pass**

Run: `swift test --package-path ThreatModelKit --filter AttackTreeScoreTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/assessment/domain/AttackTreeScoring.swift \
        ThreatModelKit/Sources/ThreatModelKit/assessment/domain/AttackTree.swift \
        ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ThreatResolver.swift \
        ThreatModelKit/Tests/UnitTests/AttackTreeScoreTests.swift
git commit -m "feat: stage 8 raises the goal of an open attack tree"
```

---

### Task 9: The model carries its trees, and the assessment runs stage 8

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/ThreatModel.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/AssessThreatModel.swift`
- Test: `ThreatModelKit/Tests/AcceptanceTests/ModellingAnAttackTreeTests.swift`

**Interfaces:**
- Consumes: `AttackTreeBinding`, `AttackTreeScoring`, `SourceAttackTree`.
- Produces: `ThreatModel.attackTrees: [SourceAttackTree]`, and `AssessThreatModelResponse.attackTrees: [BoundAttackTree]`.

- [ ] **Step 1: Write the failing test**

Create `ThreatModelKit/Tests/AcceptanceTests/ModellingAnAttackTreeTests.swift`. Task 15 adds to this file.

```swift
import Testing
import ThreatModelKit
import TestSupport

/// Given a system and the routes a person wrote through it
/// When I assess, compile, check and report
/// Then the goal of an open route scores higher and a broken route fails the build
struct ModellingAnAttackTreeTests {
    private let app = TestDependencies()

    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    @Test func assessesAModelThatStatesNoTree() throws {
        app.project.put(payments, at: "/work/threatmodel/payments.arch")
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))

        let assessed = app.assessThreatModel().execute(AssessThreatModelRequest())

        #expect(assessed.attackTrees.isEmpty)
        #expect(assessed.threats.isEmpty == false)
    }
}
```

The proof that no score moved is the whole suite, which Step 4 runs. Every model in
`ThreatModelKit/Tests` and every sample in `Resources/Samples/` states no tree, so a stage that
changes one of their numbers breaks a test that already exists.

- [ ] **Step 2: Run the test to see it fail**

Run: `swift test --package-path ThreatModelKit --filter AssessThreatModelTests`
Expected: FAIL, because `ThreatModel` has no member `attackTrees`.

- [ ] **Step 3: Add the field and run the stage**

In `ThreatModel.swift`, beside `assumptions`:

```swift
    /// The routes a person wrote in the `.attacktree` file. Empty when the
    /// project holds no such file.
    public var attackTrees: [SourceAttackTree]
```

Give it `= []` in the initialiser, so every existing call site still builds and every existing model states no tree.

In `AssessThreatModel.execute(_:)`, replace the single `resolve()` line:

```swift
        let resolvedByStages = ThreatResolver(model: model, catalogue: catalogue).resolve()
        let bound = AttackTreeBinding.bind(trees: model.attackTrees, to: resolvedByStages)
        let staged = AttackTreeScoring.apply(trees: bound, to: resolvedByStages)
        let resolved = staged.threats
```

Add `attackTrees: staged.trees` to the `AssessThreatModelResponse` it returns, and add the field to that struct:

```swift
    /// The trees a person wrote, bound to this model and scored.
    public let attackTrees: [BoundAttackTree]
```

Give it `= []` in the initialiser so every existing call site still builds.

- [ ] **Step 4: Run the whole suite**

Run: `swift test --package-path ThreatModelKit`
Expected: PASS. Every score in every existing test is unchanged, because every existing model states no tree. A failure here means stage 8 moved a number it must not move.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/modelling/domain/ThreatModel.swift \
        ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/AssessThreatModel.swift \
        ThreatModelKit/Tests/AcceptanceTests/ModellingAnAttackTreeTests.swift
git commit -m "feat: the model carries its attack trees and the assessment runs stage 8"
```

---

### Task 10: The controls file holds `tree` and `stale tree` stanzas

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ControlsSource.swift`
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/ControlsParser.swift`
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/ControlsWriter.swift`
- Test: `ThreatModelKit/Tests/UnitTests/ControlsParserTests.swift`

**Interfaces:**
- Consumes: nothing new.
- Produces: `SourceTreeAnswer`, `SourceTreeStepAnswer`, `ControlsSource.trees: [SourceTreeAnswer]`.

- [ ] **Step 1: Write the failing test**

Add to `ControlsParserTests`:

```swift
    @Test func readsATreeStanza() throws {
        let read = gateway.read("""
        controls for "P" {
          tree "read-every-customer-record" {
            goal           = "data-exfiltration@component:db"
            chain          = 100
            raises_risk_by = 40
            score          = 7
            score_before   = 5

            step "ssrf-attack@component:appserver" {
              state = "open"
            }

            step "credential-theft@component:appserver" {
              state = "closed"
              by    = "Enforce IMDSv2 with a hop limit of 1"
            }
          }
        }
        """)

        let tree = try #require(read.source?.trees.first)
        #expect(read.diagnostics.isEmpty)
        #expect(tree.treeId == "read-every-customer-record")
        #expect(tree.goalKey == "data-exfiltration@component:db")
        #expect(tree.chain == 100)
        #expect(tree.raisesRiskBy == 40)
        #expect(tree.score == 7)
        #expect(tree.scoreBefore == 5)
        #expect(tree.isStale == false)
        #expect(tree.steps.map(\.state) == ["open", "closed"])
        #expect(tree.steps[1].closedBy == "Enforce IMDSv2 with a hop limit of 1")
    }

    @Test func readsAStaleTreeStanza() throws {
        let read = gateway.read("""
        controls for "P" {
          stale tree "t" {
            step "a@component:gone" {
              state = "unbound"
            }
          }
        }
        """)

        let tree = try #require(read.source?.trees.first)
        #expect(tree.isStale)
        #expect(tree.steps[0].state == "unbound")
    }

    @Test func writesATreeStanzaBackWithNoDiff() throws {
        let text = """
        controls for "P" {
          tree "t" {
            goal           = "g@component:db"
            chain          = 100
            raises_risk_by = 40
            score          = 7
            score_before   = 5

            step "a@component:api" {
              state = "open"
            }
          }
        }

        """

        let source = try #require(gateway.read(text).source)
        #expect(gateway.write(source) == text)
    }
```

- [ ] **Step 2: Run the test to see it fail**

Run: `swift test --package-path ThreatModelKit --filter ControlsParserTests`
Expected: FAIL, because `ControlsSource` has no member `trees`.

- [ ] **Step 3: Add the values**

In `ControlsSource.swift`, add the field and the two types. Give `trees` a default of `[]` so every existing call site still builds.

```swift
    /// What the compiler found out about the trees a person wrote. The
    /// application recomputes every number here, so an edit changes nothing.
    public let trees: [SourceTreeAnswer]
```

```swift
/// One tree, as the compiler wrote it into the controls file.
public struct SourceTreeAnswer: Equatable, Sendable {
    public let treeId: String
    /// The threat key the boost lands on, as `<threat>@<kind>:<id>`.
    public let goalKey: String
    /// The chain factor as a whole percentage.
    public let chain: Int
    public let raisesRiskBy: Int
    public let score: Int
    public let scoreBefore: Int
    public let steps: [SourceTreeStepAnswer]
    /// True when a step or the goal no longer binds. A person deletes a stale
    /// tree, or restores what the tree names.
    public let isStale: Bool

    public init(
        treeId: String,
        goalKey: String = "",
        chain: Int = 0,
        raisesRiskBy: Int = 0,
        score: Int = 0,
        scoreBefore: Int = 0,
        steps: [SourceTreeStepAnswer] = [],
        isStale: Bool = false
    ) {
        self.treeId = treeId
        self.goalKey = goalKey
        self.chain = chain
        self.raisesRiskBy = raisesRiskBy
        self.score = score
        self.scoreBefore = scoreBefore
        self.steps = steps
        self.isStale = isStale
    }
}

public struct SourceTreeStepAnswer: Equatable, Sendable {
    /// `<threat>@<kind>:<id>`.
    public let key: String
    /// `open`, `closed` or `unbound`. A live stanza never holds `unbound`.
    public let state: String
    /// The control that closed this step, or nil.
    public let closedBy: String?

    public init(key: String, state: String, closedBy: String? = nil) {
        self.key = key
        self.state = state
        self.closedBy = closedBy
    }
}
```

In `ControlsParser.parseDocument()`, take a tree after `stale` and at the top level. Replace the `case "stale":` arm and add a `case "tree":` arm:

```swift
            case "stale":
                advance()
                if current.text == "tree" {
                    if let tree = parseTree(isStale: true) { trees.append(tree) }
                } else if let answer = parseThreat(isStale: true) {
                    answers.append(answer)
                }
            case "tree":
                if let tree = parseTree(isStale: false) { trees.append(tree) }
```

Declare `var trees: [SourceTreeAnswer] = []` beside `var answers`, and pass `trees: trees` to the `ControlsSource` it returns.

WARNING: the `default:` arm of `parseDocument()` states a message an existing test asserts. Change it to name the two new words, and change that test in the same commit:

```swift
                record(
                    "a controls file holds catalogue, tolerance, threat, tree, stale threat "
                        + "and stale tree, not \"\(current.text)\""
                )
```

Add the tree parser beside `parseThreat`:

```swift
    private mutating func parseTree(isStale: Bool) -> SourceTreeAnswer? {
        guard expectKeyword("tree") else { return nil }
        guard let id = expect(.string, "the tree's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var goalKey = ""
        var chain = 0
        var raisesRiskBy = 0
        var score = 0
        var scoreBefore = 0
        var steps: [SourceTreeStepAnswer] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "goal": goalKey = parseTextAttribute() ?? ""
            case "chain": chain = parseNumberAttribute() ?? 0
            case "raises_risk_by": raisesRiskBy = parseNumberAttribute() ?? 0
            case "score": score = parseNumberAttribute() ?? 0
            case "score_before": scoreBefore = parseNumberAttribute() ?? 0
            case "step":
                if let step = parseTreeStep() { steps.append(step) }
            default:
                record(
                    "a tree holds goal, chain, raises_risk_by, score, score_before and step, "
                        + "not \"\(current.text)\""
                )
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        return SourceTreeAnswer(
            treeId: id.text,
            goalKey: goalKey,
            chain: chain,
            raisesRiskBy: raisesRiskBy,
            score: score,
            scoreBefore: scoreBefore,
            steps: steps,
            isStale: isStale
        )
    }

    private mutating func parseTreeStep() -> SourceTreeStepAnswer? {
        advance()
        guard let key = expect(.string, "the step's threat key") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var state = "open"
        var closedBy: String?
        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "state": state = parseTextAttribute() ?? "open"
            case "by": closedBy = parseTextAttribute()
            default:
                record("a step holds state and by, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")
        return SourceTreeStepAnswer(key: key.text, state: state, closedBy: closedBy)
    }
```

In `ControlsWriter.write(_:)`, write the trees after the threat answers, live trees before stale ones:

```swift
        for tree in source.trees.sorted(by: Self.treeOrder) {
            body += treeBlock(tree)
            body.append("")
        }
```

```swift
    /// Live trees first, then stale ones; inside each group, by id.
    static func treeOrder(_ left: SourceTreeAnswer, _ right: SourceTreeAnswer) -> Bool {
        if left.isStale != right.isStale { return right.isStale }
        return left.treeId < right.treeId
    }

    private func treeBlock(_ tree: SourceTreeAnswer) -> [String] {
        let header = "tree \(quoted(tree.treeId)) {"
        var lines: [String] = [tree.isStale ? "stale " + header : header]
        var body: [String] = []

        if tree.isStale == false {
            body += aligned([
                ("goal", quoted(tree.goalKey)),
                ("chain", String(tree.chain)),
                ("raises_risk_by", String(tree.raisesRiskBy)),
                ("score", String(tree.score)),
                ("score_before", String(tree.scoreBefore)),
            ])
            body.append("")
        }

        for step in tree.steps {
            var stepBody: [String] = ["state = \(quoted(step.state))"]
            if let closedBy = step.closedBy {
                stepBody = aligned([("state", quoted(step.state)), ("by", quoted(closedBy))])
            }
            body.append("step \(quoted(step.key)) {")
            body += indent(stepBody)
            body.append("}")
            body.append("")
        }

        while body.last == "" { body.removeLast() }
        lines += indent(body)
        lines.append("}")
        return lines
    }
```

WARNING: `ControlsWriter` may hold no `aligned` helper today. Read the file. When it aligns its equals signs another way, use the way it already uses, so one file never aligns two ways.

- [ ] **Step 4: Run the test to see it pass**

Run: `swift test --package-path ThreatModelKit --filter ControlsParserTests`
Expected: PASS.

- [ ] **Step 5: Run the whole suite and fix the one asserted message**

Run: `swift test --package-path ThreatModelKit`
Expected: one failure, on the test that asserts the old `a controls file holds …` message. Change that test to the new message.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ControlsSource.swift \
        ThreatModelKit/Sources/ArchitectureDSL/ControlsParser.swift \
        ThreatModelKit/Sources/ArchitectureDSL/ControlsWriter.swift \
        ThreatModelKit/Tests/UnitTests/ControlsParserTests.swift
git commit -m "feat: the controls file holds tree and stale tree stanzas"
```

---

### Task 11: The compile binds the trees and merges the stanzas

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/CompileControls.swift`
- Test: `ThreatModelKit/Tests/UnitTests/CompileControlsTests.swift`

**Interfaces:**
- Consumes: `AttackTreeSourceGateway`, `AttackTreeBinding`, `AttackTreeScoring`.
- Produces: `CompileControlsRequest.attackTreeText: String?`, and `CompileControlsResponse.compiled(…, staleTrees: Int, …)`.

- [ ] **Step 1: Write the failing test**

Add to `CompileControlsTests`:

```swift
    private let architecture = """
    system "P" {
      component "api" { technology = "aws-ec2" }
      component "db" { technology = "aws-rds" data = "restricted" }
      flow api -> db
    }
    """

    @Test func writesATreeStanzaForABoundTree() throws {
        let response = compile(architecture: architecture, controls: nil, trees: """
        attack_trees for "P" {
          tree "t" {
            raises_risk_by = 40
            goal "data-exfiltration" on component "db"
            step "credential-theft" on component "api"
          }
        }
        """)

        guard case .compiled(let text, _, _, _, let staleTrees, _) = response else {
            Issue.record("the compile refused")
            return
        }
        #expect(text.contains("tree \"t\" {"))
        #expect(text.contains("step \"credential-theft@component:api\" {"))
        #expect(staleTrees == 0)
    }

    @Test func movesATreeIntoStaleWhenAStepNoLongerBinds() throws {
        let response = compile(architecture: architecture, controls: nil, trees: """
        attack_trees for "P" {
          tree "t" {
            goal "data-exfiltration" on component "db"
            step "credential-theft" on component "gone"
          }
        }
        """)

        guard case .compiled(let text, _, _, _, let staleTrees, _) = response else {
            Issue.record("the compile refused")
            return
        }
        #expect(text.contains("stale tree \"t\" {"))
        #expect(staleTrees == 1)
    }

    @Test func deletesAStanzaForATreeThePersonDeleted() throws {
        let existing = """
        controls for "P" {
          tree "gone" {
            goal = "g@component:db"
            step "a@component:api" { state = "open" }
          }
        }
        """

        let response = compile(architecture: architecture, controls: existing, trees: nil)

        guard case .compiled(let text, _, _, _, _, _) = response else {
            Issue.record("the compile refused")
            return
        }
        #expect(text.contains("tree \"gone\"") == false)
    }
```

Add the helper this suite does not hold yet, beside the helpers it does:

```swift
    private func compile(
        architecture: String,
        controls: String?,
        trees: String?
    ) -> CompileControlsResponse {
        CompileControls(
            catalogue: CatalogueFixture.catalogue(),
            architectureSources: HclArchitectureSource(),
            controlsSources: HclControlsSource(),
            attackTreeSources: HclAttackTreeSource(),
            layout: LayOutModel()
        ).execute(
            CompileControlsRequest(
                architectureText: architecture,
                controlsText: controls,
                attackTreeText: trees
            )
        )
    }
```

WARNING: `CompileControls.init` and `LayOutModel.init` take the parameters the current source states.
Read `CompileControls.swift` and copy its initialiser, adding only `attackTreeSources:`.
The suite already builds this use case somewhere; copy that call and add the one gateway.

- [ ] **Step 2: Run the test to see it fail**

Run: `swift test --package-path ThreatModelKit --filter CompileControlsTests`
Expected: FAIL, because `CompileControlsRequest` takes no tree text.

- [ ] **Step 3: Read the tree file, bind, and write the stanzas**

In `CompileControlsRequest`, add the third input:

```swift
    /// The trees a person wrote, or nil when the project holds no such file.
    public let attackTreeText: String?
```

Give it a default of `nil`, so every existing call site still builds.

In `CompileControlsResponse.compiled`, add `staleTrees: Int` after `stale: Int`. Every call site and every `case .compiled` pattern in the package then names it; the build says where.

In `CompileControls`, take the fourth gateway:

```swift
    private let attackTreeSources: AttackTreeSourceGateway
```

Add it to the initialiser, with no default, so every caller states which gateway it uses.

In `execute(_:)`, after the model resolves:

```swift
        var trees: [SourceAttackTree] = []
        if let attackTreeText = request.attackTreeText, attackTreeText.isEmpty == false {
            let read = attackTreeSources.read(attackTreeText)
            guard let source = read.source, read.hasErrors == false else {
                return .refused(diagnostics: read.diagnostics)
            }
            trees = source.trees
        }

        let resolvedByStages = ThreatResolver(model: model, catalogue: catalogue).resolve()
        let bound = AttackTreeBinding.bind(trees: trees, to: resolvedByStages)
        let staged = AttackTreeScoring.apply(trees: bound, to: resolvedByStages)
        let resolved = staged.threats
```

Replace the existing `let resolved = ThreatResolver(...).resolve()` line with the four lines above.

Turn every bound tree into a stanza. A tree the `.attacktree` file no longer states writes no stanza, because a person owns that file and deleting a tree there loses nothing:

```swift
        let treeAnswers = staged.trees.map { tree in
            SourceTreeAnswer(
                treeId: tree.id,
                goalKey: tree.goal.value,
                chain: tree.chainPercentage,
                raisesRiskBy: tree.raisesRiskBy,
                score: tree.score,
                scoreBefore: tree.scoreBefore,
                steps: tree.steps.map { step in
                    SourceTreeStepAnswer(
                        key: step.key.value,
                        state: step.state.rawValue,
                        closedBy: step.closedBy
                    )
                },
                isStale: tree.isStale
            )
        }
        let staleTrees = treeAnswers.count { $0.isStale }
```

Pass `trees: treeAnswers` into the `ControlsSource` the use case writes, and `staleTrees: staleTrees` into the response.

`ThreatKey` holds its text in `value`, and `ThreatKey(threatId:sourceId:)` mints `"<threat>@<source>"`. It is declared in `assessment/domain/CompensatingControl.swift`.

- [ ] **Step 4: Run the test to see it pass**

Run: `swift test --package-path ThreatModelKit --filter CompileControlsTests`
Expected: PASS.

- [ ] **Step 5: Run the whole suite**

Run: `swift test --package-path ThreatModelKit`
Expected: PASS, after every `case .compiled` pattern names the new field.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/CompileControls.swift \
        ThreatModelKit/Tests/UnitTests/CompileControlsTests.swift
git commit -m "feat: the compile binds the attack trees and merges their stanzas"
```

---

### Task 12: `check` exits 1 for a stale tree

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/CheckControlAnswers.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/StaleAnswers.swift`
- Test: `ThreatModelKit/Tests/UnitTests/CheckToleranceTests.swift`

**Interfaces:**
- Consumes: `ControlsSource.trees`.
- Produces: `StaleTree`, and `CheckControlAnswersResponse.checked(…, staleTrees: [String], …)`.

- [ ] **Step 1: Write the failing test**

```swift
    @Test func failsWhileAStaleTreeRemains() {
        let response = check(controls: """
        controls for "P" {
          stale tree "t" {
            step "a@component:gone" { state = "unbound" }
          }
        }
        """)

        guard case .checked(_, _, let staleTrees, _, _) = response else {
            Issue.record("the check refused")
            return
        }
        #expect(staleTrees == ["the tree \"t\" is written but no longer binds"])
        #expect(response.passed == false)
    }
```

Add the helper beside the ones the suite already uses:

```swift
    private func check(controls: String) -> CheckControlAnswersResponse {
        let project = InMemoryProject(root: "/work")
        project.put("""
        system "P" {
          component "api" { technology = "aws-ec2" }
        }
        """, at: "/work/threatmodel/p.arch")
        project.put(controls, at: "/work/threatmodel/p.controls")

        return CheckControlAnswers(
            projects: project,
            catalogue: CatalogueFixture.catalogue(),
            architectureSources: HclArchitectureSource(),
            controlsSources: HclControlsSource(),
            layout: LayOutModel()
        ).execute(CheckControlAnswersRequest(root: "/work", systemName: "p"))
    }
```

WARNING: `CheckControlAnswers.init` and `CheckControlAnswersRequest` take the parameters the current
source states. Read `CheckControlAnswers.swift` and copy them. The `case .checked` pattern also names
the fields the response states today; keep every one and add `staleTrees` in the position this task
adds it.

- [ ] **Step 2: Run the test to see it fail**

Run: `swift test --package-path ThreatModelKit --filter CheckToleranceTests`
Expected: FAIL, because the response carries no stale trees.

- [ ] **Step 3: Add the stale tree**

In `StaleAnswers.swift`, beside `StaleAnswer`:

```swift
/// A tree a person wrote that the architecture no longer supports.
///
/// Nothing deletes one. It is work for a person: read the tree, then either
/// restore what it names or delete it.
public struct StaleTree: Equatable, Sendable {
    public let treeId: String
    /// How many steps the tree holds, so a person sees what they lose by
    /// deleting it.
    public let stepCount: Int

    public init(treeId: String, stepCount: Int) {
        self.treeId = treeId
        self.stepCount = stepCount
    }

    public var described: String {
        "the tree \"\(treeId)\" is written but no longer binds"
    }
}
```

In `CheckControlAnswers`, add `staleTrees: [String]` to the `checked` case, fill it from the source, and add it to `passed`:

```swift
        let staleTrees = source.trees
            .filter(\.isStale)
            .map { StaleTree(treeId: $0.treeId, stepCount: $0.steps.count).described }
```

```swift
    public var passed: Bool {
        guard case .checked(let unanswered, let stale, let staleTrees, _, _) = self else { return false }
        return unanswered.isEmpty && stale.isEmpty && staleTrees.isEmpty
    }
```

- [ ] **Step 4: Run the test to see it pass**

Run: `swift test --package-path ThreatModelKit --filter CheckToleranceTests`
Expected: PASS.

- [ ] **Step 5: Run the whole suite**

Run: `swift test --package-path ThreatModelKit`
Expected: PASS, after every `case .checked` pattern names the new field.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/CheckControlAnswers.swift \
        ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/StaleAnswers.swift \
        ThreatModelKit/Tests/UnitTests/CheckToleranceTests.swift
git commit -m "feat: check exits 1 while a stale attack tree remains"
```

---

### Task 13: The report writes the attack tree section

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownAttackTrees.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/Report.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/BuildThreatModelReport.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/ExportModelAsMarkdown.swift`
- Test: `ThreatModelKit/Tests/UnitTests/MarkdownAttackTreesTests.swift`

**Interfaces:**
- Consumes: `BoundAttackTree`, `Report.attackPaths`.
- Produces: `Report.attackTrees: [BoundAttackTree]`, `Report.attackPathCount: Int`, `MarkdownAttackTrees.lines(_:routes:)`.

- [ ] **Step 1: Write the failing test**

```swift
import Testing
import ThreatModelKit

@Suite("The attack tree section of the report")
struct MarkdownAttackTreesTests {
    private func step(_ name: String, _ state: StepState, closedBy: String? = nil) -> BoundStep {
        BoundStep(
            key: ThreatKey(threatId: name, sourceId: "component:api"),
            threatName: name,
            sourceName: "Application Server",
            state: state,
            closedBy: closedBy,
            factor: 1.0,
            note: nil
        )
    }

    private let tree = BoundAttackTree(
        id: "read-every-customer-record",
        name: "Read every customer record",
        description: "An unauthenticated caller reaches the customer table.",
        raisesRiskBy: 40,
        goal: ThreatKey(threatId: "data-exfiltration", sourceId: "component:db"),
        goalName: "Data Exfiltration",
        goalSourceName: "PostgreSQL Database",
        steps: [],
        chainFactor: 1.0,
        isOpen: true,
        isStale: false,
        scoreBefore: 5,
        score: 7
    )

    @Test func writesNoSectionWhenAModelStatesNoTree() {
        #expect(MarkdownAttackTrees.lines([], routes: 20).isEmpty)
    }

    @Test func writesTheHeadingWithBothScoresAndTheChain() {
        let lines = MarkdownAttackTrees.lines([tree], routes: 20)

        #expect(lines.contains("## Attack trees"))
        #expect(lines.contains("### Read every customer record — 5 → 7, chain 100%"))
    }

    @Test func statesHowManyRoutesTheWalkFoundBesideTheTreesAPersonWrote() {
        let lines = MarkdownAttackTrees.lines([tree], routes: 20)

        #expect(lines.contains("This model states 1 tree. The walk found 20 routes."))
    }

    @Test func namesTheControlThatClosedAStep() {
        var withSteps = tree
        withSteps = BoundAttackTree(
            id: tree.id, name: tree.name, description: tree.description,
            raisesRiskBy: tree.raisesRiskBy, goal: tree.goal, goalName: tree.goalName,
            goalSourceName: tree.goalSourceName,
            steps: [step("Credential Theft", .closed, closedBy: "Enforce IMDSv2")],
            chainFactor: tree.chainFactor, isOpen: tree.isOpen, isStale: tree.isStale,
            scoreBefore: tree.scoreBefore, score: tree.score
        )

        let lines = MarkdownAttackTrees.lines([withSteps], routes: 1)

        #expect(lines.contains(
            "| Credential Theft | Application Server | closed | Enforce IMDSv2 |"
        ))
    }
}
```

- [ ] **Step 2: Run the test to see it fail**

Run: `swift test --package-path ThreatModelKit --filter MarkdownAttackTreesTests`
Expected: FAIL, because `MarkdownAttackTrees` does not exist.

- [ ] **Step 3: Write the section**

```swift
/// The attack tree section of the report.
///
/// It sits after the attack paths, because the walk proposes the routes and a
/// tree states the one a person confirmed.
public enum MarkdownAttackTrees {
    /// `routes` is how many routes the attack path walk found, which the
    /// section states so a reader sees how much of the graph one tree covers.
    public static func lines(_ trees: [BoundAttackTree], routes: Int) -> [String] {
        guard trees.isEmpty == false else { return [] }

        var lines: [String] = ["## Attack trees", ""]

        for tree in trees.sorted(by: { $0.score > $1.score }) {
            lines.append(heading(tree))
            lines.append("")
            if let description = tree.description {
                lines.append(description)
                lines.append("")
            }
            lines.append("Goal: \(tree.goalName) on \(tree.goalSourceName).")
            lines.append("")
            lines.append("| Step | Raised on | State | Closed by |")
            lines.append("| --- | --- | --- | --- |")
            for step in tree.steps {
                lines.append(
                    "| \(step.threatName) | \(step.sourceName) | \(step.state.rawValue)"
                        + " | \(step.closedBy ?? "\u{2014}") |"
                )
            }
            lines.append("")
        }

        lines.append(
            "This model states \(count(trees.count, "tree"))."
                + " The walk found \(count(routes, "route"))."
        )
        lines.append("")
        return lines
    }

    private static func heading(_ tree: BoundAttackTree) -> String {
        guard tree.isStale == false else {
            return "### \(tree.name) — no longer binds"
        }
        return "### \(tree.name) — \(tree.scoreBefore) \u{2192} \(tree.score),"
            + " chain \(tree.chainPercentage)%"
    }

    private static func count(_ number: Int, _ word: String) -> String {
        "\(number) \(word)\(number == 1 ? "" : "s")"
    }
}
```

In `Report.swift`, add the two fields, each with a default so every existing call site still builds:

```swift
    /// The trees a person wrote, bound and scored.
    public let attackTrees: [BoundAttackTree]
    /// How many routes the attack path walk found, listed and not listed.
    public let attackPathCount: Int
```

In `BuildThreatModelReport`, fill both from the assessment and from the walk it already runs.

In `ExportModelAsMarkdown`, place the section after the attack paths:

```swift
        lines += MarkdownAttackPaths.lines(report.attackPaths, prefix: report.attackPathPrefix)
        lines += MarkdownAttackTrees.lines(report.attackTrees, routes: report.attackPathCount)
```

- [ ] **Step 4: Run the test to see it pass**

Run: `swift test --package-path ThreatModelKit --filter MarkdownAttackTreesTests`
Expected: PASS.

- [ ] **Step 5: Run the whole suite**

Run: `swift test --package-path ThreatModelKit`
Expected: PASS. A report of a model with no tree writes no new line, because the section is empty.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/reporting/ \
        ThreatModelKit/Tests/UnitTests/MarkdownAttackTreesTests.swift
git commit -m "feat: the report writes the attack tree section"
```

---

### Task 14: The summary and the threat register name the tree

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownExecutiveSummary.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownThreatStanza.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/Report.swift`
- Test: `ThreatModelKit/Tests/AcceptanceTests/ModellingAnAttackTreeTests.swift`

**Interfaces:**
- Consumes: `BoundAttackTree`.
- Produces: `ReportThreat.raisedByTree: String?` and `ReportThreat.scoreBeforeTree: Int?`.

- [ ] **Step 1: Write the failing test**

The test reads the report the application writes, so it needs no fixture for `ReportThreat`, whose
field list is long and changes with the report. Add to `ModellingAnAttackTreeTests`:

```swift
    private let raisedArchitecture = """
    system "Payments" {
      component "api" { technology = "aws-ec2" data = "confidential" }
      component "db" { technology = "aws-rds" data = "restricted" }
      flow api -> db
    }

    """

    private let oneTree = """
    attack_trees for "Payments" {
      tree "read-every-customer-record" {
        name           = "Read every customer record"
        raises_risk_by = 40

        goal "data-exfiltration" on component "db"

        step "credential-theft" on component "api"
      }
    }

    """

    @Test func namesTheTreeOnTheThreatItRaised() throws {
        app.project.put(raisedArchitecture, at: "/work/threatmodel/payments.arch")
        app.project.put(oneTree, at: "/work/threatmodel/payments.attacktree")
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))
        _ = app.exportModelAsMarkdown().execute(
            ExportModelAsMarkdownRequest(root: "/work", systemName: "payments")
        )

        let report = try #require(app.project.text(at: "/work/threatmodel/payments.md"))
        #expect(report.contains("- Raised by the tree: Read every customer record"))
        #expect(report.contains("- Before the attack tree: "))
    }

    @Test func namesNoTreeOnAThreatNoTreeRaised() throws {
        app.project.put(payments, at: "/work/threatmodel/payments.arch")
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))
        _ = app.exportModelAsMarkdown().execute(
            ExportModelAsMarkdownRequest(root: "/work", systemName: "payments")
        )

        let report = try #require(app.project.text(at: "/work/threatmodel/payments.md"))
        #expect(report.contains("Raised by the tree") == false)
    }
```

WARNING: `app.exportModelAsMarkdown()` and `ExportModelAsMarkdownRequest` take the names the current
source states. Read `ExportModelAsMarkdown.swift` and `TestDependencies.swift`, and use the use case
and the request they state. `ReportingAThreatModelTests` already exports a report this way; copy its
call.

- [ ] **Step 2: Run the test to see it fail**

Run: `swift test --package-path ThreatModelKit --filter ModellingAnAttackTreeTests`
Expected: FAIL, because the report states neither line.

- [ ] **Step 3: Add the two fields and the two lines**

In `Report.swift`, on `ReportThreat`, with defaults of `nil`:

```swift
    /// The score before stage 8, or nil when no tree names this threat.
    public let scoreBeforeTree: Int?
    /// The tree that raised this threat, or nil when none did.
    public let raisedByTree: String?
```

In `BuildThreatModelReport`, set both from the bound trees: a threat whose key matches a tree's goal, and whose tree is open and not stale, takes the tree's name and its `scoreBefore`.

In `MarkdownThreatStanza.lines(_:)`, beside the line that states the score before controls:

```swift
        if let scoreBeforeTree = threat.scoreBeforeTree {
            lines.append("- Before the attack tree: \(scoreBeforeTree)")
        }
        if let raisedByTree = threat.raisedByTree {
            lines.append("- Raised by the tree: \(raisedByTree)")
        }
```

In `MarkdownExecutiveSummary`, add the same sentence to the line of a highest-risk threat a tree raised:

```swift
            if let raisedByTree = threat.raisedByTree {
                lines.append("   The tree \(raisedByTree) raises this threat.")
            }
```

- [ ] **Step 4: Run the test to see it pass**

Run: `swift test --package-path ThreatModelKit --filter ModellingAnAttackTreeTests`
Expected: PASS.

- [ ] **Step 5: Run the whole suite**

Run: `swift test --package-path ThreatModelKit`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/reporting/ \
        ThreatModelKit/Tests/AcceptanceTests/ModellingAnAttackTreeTests.swift
git commit -m "feat: the summary and the threat register name the tree that raised a goal"
```

---

### Task 15: The command line reads the file

**Files:**
- Modify: `ThreatModelKit/Sources/CommandLineApplication/CommandLineApplication.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift`
- Test: `ThreatModelKit/Tests/UnitTests/CommandLineApplicationTests.swift`

**Interfaces:**
- Consumes: every use case of Tasks 11 to 14.
- Produces: no new type.

- [ ] **Step 1: Write the failing test**

Add to `ThreatModelKit/Tests/UnitTests/CommandLineApplicationTests.swift`, which already runs the
verbs against an `InMemoryProject`:

```swift
    // MARK: the attack tree file

    private let treeSystem = """
    system "Payments" {
      component "api" { technology = "aws-ec2" data = "confidential" }
      component "db" { technology = "aws-rds" data = "restricted" }
      flow api -> db
    }

    """

    private let oneTree = """
    attack_trees for "Payments" {
      tree "t" {
        raises_risk_by = 40

        goal "data-exfiltration" on component "db"

        step "credential-theft" on component "api"
      }
    }

    """

    private let brokenTree = """
    attack_trees for "Payments" {
      tree "t" {
        goal "data-exfiltration" on component "db"

        step "credential-theft" on component "gone"
      }
    }

    """

    @Test func compileWritesATreeStanzaIntoTheControlsFile() throws {
        project.put(treeSystem, at: "/work/threatmodel/payments.arch")
        project.put(oneTree, at: "/work/threatmodel/payments.attacktree")

        #expect(run("compile", "/work").code == 0)

        let controls = try #require(project.text(at: "/work/threatmodel/payments.controls"))
        #expect(controls.contains("tree \"t\" {"))
        #expect(controls.contains("step \"credential-theft@component:api\" {"))
    }

    @Test func checkFailsOnATreeThatNoLongerBinds() throws {
        project.put(treeSystem, at: "/work/threatmodel/payments.arch")
        project.put(brokenTree, at: "/work/threatmodel/payments.attacktree")
        _ = run("compile", "/work")

        let checked = run("check", "/work")

        #expect(checked.code == 1)
        #expect(checked.lines.contains {
            $0.contains("the tree \"t\" is written but no longer binds")
        })
    }

    @Test func reportWritesTheAttackTreeSection() throws {
        project.put(treeSystem, at: "/work/threatmodel/payments.arch")
        project.put(oneTree, at: "/work/threatmodel/payments.attacktree")
        _ = run("compile", "/work")

        #expect(run("report", "/work").code == 0)

        let report = try #require(project.text(at: "/work/threatmodel/payments.md"))
        #expect(report.contains("## Attack trees"))
    }

    @Test func formatRewritesTheAttackTreeFile() throws {
        project.put(treeSystem, at: "/work/threatmodel/payments.arch")
        project.put("""
        attack_trees for "Payments" {
        tree "t" {
        goal "data-exfiltration" on component "db"
        step "credential-theft" on component "api"
        }
        }
        """, at: "/work/threatmodel/payments.attacktree")

        #expect(run("format", "/work").code == 0)

        let written = try #require(project.text(at: "/work/threatmodel/payments.attacktree"))
        #expect(written.contains("  tree \"t\" {"))
    }

    @Test func everyVerbRunsOnASystemWithNoAttackTreeFile() {
        project.put(payments, at: "/work/threatmodel/payments.arch")

        #expect(run("compile", "/work").code == 0)
        #expect(run("format", "/work").code == 0)
        #expect(run("report", "/work").code == 0)
    }
```

WARNING: `project.put(_:at:)`, `project.text(at:)` and `run(_:)` are the helpers this suite already
holds. Read the top of the file, and use the names it states.

- [ ] **Step 2: Run the test to see it fail**

Run: `swift test --package-path ThreatModelKit --filter CommandLineApplicationTests`
Expected: FAIL, because the command line application reads no `.attacktree` file.

- [ ] **Step 3: Read the file in each verb**

In `CommandLineApplication`, wherever a verb reads `system.controlsPath`, read `system.attackTreePath` beside it. A file that is not there is not a fault: a system with no tree passes `nil`.

```swift
        let attackTreeText = projects.exists(path: system.attackTreePath)
            ? try? projects.read(path: system.attackTreePath)
            : nil
```

- `compile` passes it as `CompileControlsRequest.attackTreeText`, and prints the stale tree count beside the stale answer count.
- `check` prints one line for each stale tree, in the shape the other lines use:
  `output("\(system.controlsPath): \(described)")`.
- `report` and the application both apply the trees to the model before they assess it, so `ThreatModel.attackTrees` is set from the parsed file.
- `format` reads every `.attacktree` file, writes it back through `HclAttackTreeSource`, and prints `formatted <path>` or `unchanged <path>`, the same way it does for a `.arch` file.

In `UseCaseFactory`, build `HclAttackTreeSource()` once and pass it to `CompileControls`.

- [ ] **Step 4: Run the test to see it pass**

Run: `swift test --package-path ThreatModelKit --filter CommandLineApplicationTests`
Expected: PASS.

- [ ] **Step 5: Run the whole suite**

Run: `swift test --package-path ThreatModelKit`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add ThreatModelKit/Sources/CommandLineApplication/CommandLineApplication.swift \
        ThreatModelKit/Sources/ThreatModelKit/UseCaseFactory.swift \
        ThreatModelKit/Tests/UnitTests/CommandLineApplicationTests.swift
git commit -m "feat: the command line reads the attack tree file in every verb"
```

---

### Task 16: The language guide states the fourth language

**Files:**
- Modify: `docs/LANGUAGE.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: the grammar of Tasks 3, 4, 5 and 10.
- Produces: no code.

- [ ] **Step 1: Write the new section**

Add section 7, `## 7. The attack tree language`, after section 6 and before the diagnostics section. Move every section after it up by one, and change every cross-reference in the file that names a moved number. Search for `section 7`, `section 8`, `section 9`, `section 10` and `section 11` and change each hit.

The new section holds, in this order and in the shape sections 4, 5 and 6 already use:

1. The grammar block, copied from section 3.2 of the design.
2. `attack_trees for`, with its one attribute.
3. `tree`, with the table of section 3.3 of the design.
4. `goal` and `step`, stating that both take the `"<threat>" on component "<id>"` shape the controls language uses, and that a `step` with no body is a step with an empty body.
5. `all_of` and `any_of`, with the node rules of section 5.3 of the design.
6. What binds, and what makes a tree stale.
7. What the parser refuses: every row of the table of section 3.5 of the design.

Add the `tree` and `stale tree` stanzas to section 5, the controls language, with the tables of section 4.1 of the design.

Add the two new rows to the "What each block holds" table of the diagnostics section.

Add the whole grammar to the "The grammar in full" section, under a `(* the attack tree language *)` comment, in the same shape as the other three.

Add the two new files to the "Where the code is" table:

```markdown
| [`AttackTreeParser.swift`](../ThreatModelKit/Sources/ArchitectureDSL/AttackTreeParser.swift) | section 7 |
| [`AttackTreeWriter.swift`](../ThreatModelKit/Sources/ArchitectureDSL/AttackTreeWriter.swift) | the canonical form of a `.attacktree` file |
```

- [ ] **Step 2: Add the row to the README**

In the table under "A project holds two source files for each system", add:

```markdown
| `<name>.attacktree` | a person | the routes through several components, and what each route raises |
```

Change the sentence above the table, which says a project holds two source files, to say three. Add a paragraph under "Scoring" that states stage 8 and the weakest-step rule, and name `docs/superpowers/specs/2026-09-14-attack-trees-design.md`.

- [ ] **Step 3: Check every cross-reference**

Run: `grep -n "section [0-9]" docs/LANGUAGE.md`
Read every hit and check the number still names the section it means.

- [ ] **Step 4: Commit**

```bash
git add docs/LANGUAGE.md README.md
git commit -m "docs: the language guide states the attack tree language"
```
