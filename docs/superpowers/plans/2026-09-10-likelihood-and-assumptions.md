# Likelihood and assumptions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make likelihood and assumption first-class dimensions of a threat's score, so a research-only threat scores lower than a commodity one, and hardening nobody has shipped yet never lowers the residual.

**Architecture:** A new `Likelihood` stage runs inside `ThreatResolver`, after the `mitigates` edges and before the compensating control. A library threat carries a prior; a `likelihood` block in a controls file overrides it for one threat on one source. `MitigatesEdge` carries `adopted` or `assumed`, and the resolver runs the edge stage twice so every threat carries a residual score and a target-posture score. Three new controls-file blocks (`likelihood`, `severity_override`, and `sources` lists) travel through the same parser, writer, `CompileControls` and `ApplyControlAnswers` path the existing blocks use.

**Tech Stack:** Swift 6, swift-testing (`@Suite`, `@Test`, `#expect`, `#require`), the local package `ThreatModelKit`, the hand-written lexer and recursive-descent parsers in `Sources/ArchitectureDSL`.

**Spec:** `docs/superpowers/specs/2026-09-10-likelihood-and-assumptions-design.md`

## Global Constraints

- Run every test from the package directory: `cd ThreatModelKit && swift test`.
- Filter one suite with `swift test --filter <SuiteName>`.
- Every new type is `public`, `Equatable` and `Sendable`, which every domain type in this package already is.
- Every new field on an existing type takes a default in the initialiser, so no call site outside the task breaks.
- Defaults keep every existing model's numbers: no likelihood means `commodity` (factor 1.0); no edge status means `adopted`; no `risk_tolerance` means `low`.
- A block that changes a score needs a rationale. A block with no rationale is an error, and it changes nothing.
- Every score stage floors at 1: `max(1, Int((Double(score) * factor).rounded()))`.
- Write code comments and commit messages in ASD-STE100: short common words, active voice, one instruction per sentence.
- Never write a placeholder value into a golden test file. Run the test, read the failure, and write what the code produced only after you have checked it by hand.

---

### Task 1: The Likelihood type

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/Likelihood.swift`
- Test: `ThreatModelKit/Tests/UnitTests/LikelihoodTests.swift`

**Interfaces:**
- Consumes: nothing.
- Produces: `Likelihood` with `static let commodity/targeted/research`, `init?(rawValue: String)`, `init?(prior: Int)`, `var id: String`, `var label: String`, `var factor: Double`, and `static func apply(to score: Int, likelihood: Likelihood) -> Int`.

- [ ] **Step 1: Write the failing test**

```swift
import Testing
import ThreatModelKit

@Suite("What a likelihood does to a score")
struct LikelihoodTests {
    @Test func namesThreeTiers() throws {
        #expect(Likelihood.commodity.factor == 1.0)
        #expect(Likelihood.targeted.factor == 0.6)
        #expect(Likelihood.research.factor == 0.25)
        #expect(Likelihood.commodity.label == "Commodity")
    }

    @Test func readsATierByItsIdentifier() throws {
        #expect(Likelihood(rawValue: "research") == .research)
        #expect(Likelihood(rawValue: "folklore") == nil)
    }

    @Test func readsAPriorAsAPercentage() throws {
        let prior = try #require(Likelihood(prior: 25))
        #expect(prior.factor == 0.25)
        #expect(prior.id == "25")
        #expect(prior.label == "25%")
        #expect(Likelihood(prior: 101) == nil)
        #expect(Likelihood(prior: -1) == nil)
    }

    @Test func multipliesTheScoreAndNeverGoesBelowOne() throws {
        #expect(Likelihood.apply(to: 10, likelihood: .commodity) == 10)
        #expect(Likelihood.apply(to: 10, likelihood: .targeted) == 6)
        #expect(Likelihood.apply(to: 10, likelihood: .research) == 3)
        #expect(Likelihood.apply(to: 1, likelihood: .research) == 1)
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd ThreatModelKit && swift test --filter LikelihoodTests`
Expected: FAIL, "cannot find 'Likelihood' in scope".

- [ ] **Step 3: Write the implementation**

```swift
/// How often an attack of this kind actually happens.
///
/// The score says how bad a threat is. This says whether anybody does it. A
/// threat that states none is `commodity`, so a model that says nothing about
/// likelihood keeps the numbers it had.
public struct Likelihood: Equatable, Sendable {
    public let id: String
    public let label: String
    /// 0.0 to 1.0. The stage multiplies the score by this.
    public let factor: Double

    private init(id: String, label: String, factor: Double) {
        self.id = id
        self.label = label
        self.factor = factor
    }

    /// Malware families use it today.
    public static let commodity = Likelihood(id: "commodity", label: "Commodity", factor: 1.0)
    /// A funded attacker uses it against a chosen target.
    public static let targeted = Likelihood(id: "targeted", label: "Targeted", factor: 0.6)
    /// A researcher has shown it, and no campaign has used it.
    public static let research = Likelihood(id: "research", label: "Research", factor: 0.25)

    public static let allTiers: [Likelihood] = [.commodity, .targeted, .research]

    /// The tier with that id, or nil. A file that names another word is wrong,
    /// and the parser says so.
    public init?(rawValue: String) {
        guard let tier = Self.allTiers.first(where: { $0.id == rawValue }) else { return nil }
        self = tier
    }

    /// A number from 0 to 100, which is a percentage.
    public init?(prior: Int) {
        guard (0...100).contains(prior) else { return nil }
        self = Likelihood(id: String(prior), label: "\(prior)%", factor: Double(prior) / 100)
    }

    /// The score after the likelihood, and never below 1.
    public static func apply(to score: Int, likelihood: Likelihood) -> Int {
        max(1, Int((Double(score) * likelihood.factor).rounded()))
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd ThreatModelKit && swift test --filter LikelihoodTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources/ThreatModelKit/assessment/domain/Likelihood.swift ThreatModelKit/Tests/UnitTests/LikelihoodTests.swift
git commit -m "feat: a likelihood tier and the factor it applies to a score"
```

---

### Task 2: The library threat carries a prior

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/LibrarySource.swift` (`SourceLibraryThreat`)
- Modify: `ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/Threat.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/catalogue/domain/Library.swift:127`
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/LibraryParser.swift:122-192`
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/LibraryWriter.swift:83-100`
- Test: `ThreatModelKit/Tests/UnitTests/LibraryLikelihoodTests.swift`

**Interfaces:**
- Consumes: `Likelihood` from Task 1.
- Produces: `SourceLibraryThreat.likelihood: String?`, `Threat.likelihood: Likelihood` (defaults to `.commodity`), and the `likelihood` attribute in the `.lib` language.

- [ ] **Step 1: Write the failing test**

```swift
import ArchitectureDSL
import Testing
import ThreatModelKit

@Suite("A library threat's likelihood")
struct LibraryLikelihoodTests {
    private let gateway = HclLibrarySource()

    private func library(_ likelihoodLine: String) -> String {
        """
        library "endpoint" {
          threat "sip-bypass" {
            name       = "SIP Bypass"
            severity   = "critical"
        \(likelihoodLine)
          }
        }
        """
    }

    @Test func readsATier() throws {
        let source = try #require(gateway.read(library("    likelihood = \"research\"")).source)
        #expect(source.threats.first?.likelihood == "research")
    }

    @Test func readsANumericPrior() throws {
        let source = try #require(gateway.read(library("    likelihood = 25")).source)
        #expect(source.threats.first?.likelihood == "25")
    }

    @Test func aThreatThatStatesNoneReadsAsNil() throws {
        let source = try #require(gateway.read(library("")).source)
        #expect(source.threats.first?.likelihood == nil)
    }

    @Test func refusesAWordTheApplicationDoesNotHold() throws {
        let read = gateway.read(library("    likelihood = \"folklore\""))
        let errors = read.diagnostics.filter { $0.severity == .error }
        #expect(errors.count == 1)
        #expect(errors.first?.message.contains("folklore") == true)
    }

    @Test func buildsIntoTheThreatAndDefaultsToCommodity() throws {
        let stated = try #require(gateway.read(library("    likelihood = \"targeted\"")).source)
        let silent = try #require(gateway.read(library("")).source)

        let built = Library.build(from: stated, taxonomy: Taxonomy.fallback)
        let plain = Library.build(from: silent, taxonomy: Taxonomy.fallback)

        #expect(built.library?.threats.first?.likelihood == .targeted)
        #expect(plain.library?.threats.first?.likelihood == .commodity)
    }

    @Test func writesTheAttributeBackOnlyWhenTheThreatStatesOne() throws {
        let stated = try #require(gateway.read(library("    likelihood = \"research\"")).source)
        #expect(gateway.write(stated).contains("likelihood = \"research\""))

        let silent = try #require(gateway.read(library("")).source)
        #expect(gateway.write(silent).contains("likelihood") == false)
    }
}
```

Note: read `Library.build`'s current signature in `catalogue/domain/Library.swift` before writing the last test, and call it the way `LibraryTests.swift` already calls it. Change the call in the test to match; do not change `Library.build`'s signature.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd ThreatModelKit && swift test --filter LibraryLikelihoodTests`
Expected: FAIL, "value of type 'SourceLibraryThreat' has no member 'likelihood'".

- [ ] **Step 3: Write the implementation**

In `LibrarySource.swift`, add to `SourceLibraryThreat` a stored property and an initialiser parameter with a default:

```swift
    /// The tier id or the whole number a threat states, or nil for none.
    public let likelihood: String?
```

```swift
        likelihood: String? = nil,
```

```swift
        self.likelihood = likelihood
```

In `Threat.swift`, add the same way:

```swift
    /// How often an attack of this kind happens. A threat that states none is
    /// `commodity`, so an old catalogue keeps its numbers.
    public let likelihood: Likelihood
```

```swift
        likelihood: Likelihood = .commodity,
```

```swift
        self.likelihood = likelihood
```

In `LibraryParser.swift`, add a variable beside the others, a case in the attribute switch, the word in the fault message, and pass it through:

```swift
        var likelihood: String?
```

```swift
            case "likelihood":
                let token = current
                if peekIsNumber() {
                    let prior = parseNumberAttribute()
                    if let prior, Likelihood(prior: prior) == nil {
                        record("likelihood is \(prior); a whole number runs from 0 to 100", at: token)
                    }
                    likelihood = prior.map(String.init)
                } else {
                    let raw = parseTextAttribute() ?? ""
                    if Likelihood(rawValue: raw) == nil {
                        record(
                            "likelihood is \"\(raw)\"; this application holds "
                                + Likelihood.allTiers.map { "\"\($0.id)\"" }.joined(separator: ", ")
                                + ", or a whole number from 0 to 100",
                            at: token
                        )
                    } else {
                        likelihood = raw
                    }
                }
```

Add the helper beside the other token readers in the same file:

```swift
    /// True when the value after `name =` is a number rather than a text.
    private func peekIsNumber() -> Bool {
        tokens[min(index + 2, tokens.count - 1)].kind == .number
    }
```

Add `likelihood` to the `default:` fault message list, and to the `SourceLibraryThreat(...)` the function returns.

In `Library.swift:127`, map it:

```swift
                likelihood: threat.likelihood.flatMap(Self.likelihood(from:)) ?? .commodity,
```

and add the private helper to the same type:

```swift
    /// A tier id, or a whole number, or nil for neither.
    private static func likelihood(from raw: String) -> Likelihood? {
        if let tier = Likelihood(rawValue: raw) { return tier }
        guard let prior = Int(raw) else { return nil }
        return Likelihood(prior: prior)
    }
```

In `LibraryWriter.swift`, emit it after `severity`:

```swift
        if let likelihood = threat.likelihood {
            let isNumber = Int(likelihood) != nil
            attributes.append(("likelihood", isNumber ? likelihood : quoted(likelihood)))
        }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd ThreatModelKit && swift test --filter LibraryLikelihoodTests`
Then: `cd ThreatModelKit && swift test --filter LibraryParserTests --filter LibraryWriterTests --filter LibraryTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources ThreatModelKit/Tests/UnitTests/LibraryLikelihoodTests.swift
git commit -m "feat: a library threat states how often the attack happens"
```

---

### Task 3: The resolver's likelihood stage

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ThreatResolver.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/AssessThreatModel.swift`
- Test: `ThreatModelKit/Tests/UnitTests/LikelihoodScoringTests.swift`

**Interfaces:**
- Consumes: `Likelihood`, `Threat.likelihood`.
- Produces: `ResolvedThreat.likelihood: Likelihood`, `ResolvedThreat.scoreBeforeLikelihood: Int`, `AssessedThreat.likelihoodId: String`, `AssessedThreat.likelihoodLabel: String`, `AssessedThreat.scoreBeforeLikelihood: Int`.

The stage runs inside `raise(_:)`, between the `mitigates` edge stage and `compensated(_:)`, so every source kind gets it once.

- [ ] **Step 1: Write the failing test**

```swift
import Testing
import ThreatModelKit
import TestSupport

@Suite("Where the likelihood stage sits in the score")
struct LikelihoodScoringTests {
    private let app = TestDependencies()

    private func threats() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    @Test func aCommodityThreatKeepsItsScore() throws {
        app.catalogue.add(
            technology: "laptop",
            threat: Threat(
                id: ThreatId("theft"),
                name: "Theft",
                description: "",
                severity: app.catalogue.severity(id: "critical"),
                likelihood: .commodity
            )
        )
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "laptop", x: 0, y: 0, sensitivity: "restricted")
        )

        let threat = try #require(threats().first)
        #expect(threat.riskScore == threat.scoreBeforeLikelihood)
        #expect(threat.likelihoodId == "commodity")
    }

    @Test func aResearchThreatScoresAQuarter() throws {
        app.catalogue.add(
            technology: "laptop",
            threat: Threat(
                id: ThreatId("sip-bypass"),
                name: "SIP Bypass",
                description: "",
                severity: app.catalogue.severity(id: "critical"),
                likelihood: .research
            )
        )
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "laptop", x: 0, y: 0, sensitivity: "restricted")
        )

        let threat = try #require(threats().first)
        #expect(threat.scoreBeforeLikelihood == 16)
        #expect(threat.riskScore == 4)
        #expect(threat.likelihoodLabel == "Research")
    }
}
```

Note: `InMemoryTechnologyCatalogue` is the fake behind `TestDependencies`. Read `Sources/TestSupport/InMemoryTechnologyCatalogue.swift` and `Sources/TestSupport/TestDependencies.swift` first, and use the helpers they already give for adding a technology and a threat. Add a helper to the fake only if none exists; keep the fake's existing names.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd ThreatModelKit && swift test --filter LikelihoodScoringTests`
Expected: FAIL, "value of type 'AssessedThreat' has no member 'scoreBeforeLikelihood'".

- [ ] **Step 3: Write the implementation**

In `ThreatResolver.swift`, add two fields to `ResolvedThreat` with defaults:

```swift
    /// How often an attack of this kind happens, and what the stage used.
    public let likelihood: Likelihood
    /// The score the likelihood stage received. Equal to `score.value` when
    /// the likelihood is `commodity`.
    public let scoreBeforeLikelihood: Int
```

```swift
        likelihood: Likelihood = .commodity,
        scoreBeforeLikelihood: Int? = nil,
```

```swift
        self.likelihood = likelihood
        self.scoreBeforeLikelihood = scoreBeforeLikelihood ?? score.value
```

Add the stage and call it from `raise(_:)`:

```swift
        func raise(_ threat: ResolvedThreat) {
            let pair = "\(threat.threat.id.value)@\(threat.source.id)"
            guard raised.contains(pair) == false else { return }
            raised.insert(pair)
            resolved.append(compensated(likelihooded(threat)))
        }
```

```swift
    /// Spec section 3: the likelihood stage runs after the `mitigates` edges
    /// and before the compensating control. It multiplies, because a
    /// likelihood finding and a control are separate evidence.
    private func likelihooded(_ threat: ResolvedThreat) -> ResolvedThreat {
        let likelihood = threat.threat.likelihood
        guard likelihood != .commodity else { return threat }
        let reduced = Likelihood.apply(to: threat.score.value, likelihood: likelihood)

        return ResolvedThreat(
            threat: threat.threat,
            severity: threat.severity,
            source: threat.source,
            sensitivity: threat.sensitivity,
            score: RiskScore(value: reduced),
            controls: threat.controls,
            context: threat.context,
            isTlsMitigated: threat.isTlsMitigated,
            overrideKey: threat.overrideKey,
            overriddenSeverityId: threat.overriddenSeverityId,
            mitigatedBy: threat.mitigatedBy,
            scoreBeforePathwayMitigation: threat.scoreBeforePathwayMitigation,
            scoreBeforeControls: threat.scoreBeforeControls,
            compensating: threat.compensating,
            scoreBeforeCompensation: threat.scoreBeforeCompensation,
            mitigatedByComponents: threat.mitigatedByComponents,
            likelihood: likelihood,
            scoreBeforeLikelihood: threat.score.value
        )
    }
```

In `compensated(_:)`, carry the two new fields into the `ResolvedThreat` it builds, so the compensating stage does not drop them.

In `AssessThreatModel.swift`, add three fields to `AssessedThreat` with defaults and set them from the resolved threat:

```swift
    /// The likelihood tier the score used, and what a reader sees.
    public let likelihoodId: String
    public let likelihoodLabel: String
    /// The score before the likelihood stage. Equal to `riskScore` when the
    /// likelihood is `commodity`.
    public let scoreBeforeLikelihood: Int
```

```swift
        likelihoodId: String = Likelihood.commodity.id,
        likelihoodLabel: String = Likelihood.commodity.label,
        scoreBeforeLikelihood: Int? = nil,
```

```swift
        self.likelihoodId = likelihoodId
        self.likelihoodLabel = likelihoodLabel
        self.scoreBeforeLikelihood = scoreBeforeLikelihood ?? riskScore
```

```swift
                    likelihoodId: threat.likelihood.id,
                    likelihoodLabel: threat.likelihood.label,
                    scoreBeforeLikelihood: threat.scoreBeforeLikelihood,
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd ThreatModelKit && swift test --filter LikelihoodScoringTests`
Then the whole suite: `cd ThreatModelKit && swift test`
Expected: PASS, 815 tests plus the new ones.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources ThreatModelKit/Tests/UnitTests/LikelihoodScoringTests.swift
git commit -m "feat: the likelihood stage multiplies a threat's score"
```

---

### Task 4: The `likelihood` block in a controls file

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/LikelihoodFinding.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ControlsSource.swift`
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/ControlsParser.swift`
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/ControlsWriter.swift`
- Test: `ThreatModelKit/Tests/UnitTests/LikelihoodBlockTests.swift`

**Interfaces:**
- Consumes: `Likelihood`.
- Produces: `LikelihoodFinding(label:likelihood:rationale:sources:)`, `SourceThreatAnswer.likelihood: LikelihoodFinding?`.

- [ ] **Step 1: Write the failing test**

```swift
import ArchitectureDSL
import Testing
import ThreatModelKit

@Suite("The likelihood block in a controls file")
struct LikelihoodBlockTests {
    private let gateway = HclControlsSource()

    private func controls(_ block: String) -> String {
        """
        controls for "Payments" {
          threat "sip-bypass" on component "laptop" {
        \(block)
          }
        }
        """
    }

    private func errors(_ text: String) -> [Diagnostic] {
        gateway.read(text).diagnostics.filter { $0.severity == .error }
    }

    @Test func readsATierWithARationaleAndItsSources() throws {
        let text = controls("""
            likelihood "no in-the-wild use" {
              tier      = "research"
              rationale = "every bypass was researcher-found"
              sources   = ["https://example.test/a", "CVE-2021-30892"]
            }
        """)
        let source = try #require(gateway.read(text).source)
        let finding = try #require(source.answers.first?.likelihood)

        #expect(finding.label == "no in-the-wild use")
        #expect(finding.likelihood == .research)
        #expect(finding.rationale == "every bypass was researcher-found")
        #expect(finding.sources == ["https://example.test/a", "CVE-2021-30892"])
    }

    @Test func readsANumericPrior() throws {
        let text = controls("""
            likelihood "one campaign in five years" {
              prior     = 20
              rationale = "one campaign, 2021, no repeat"
            }
        """)
        let finding = try #require(gateway.read(text).source?.answers.first?.likelihood)
        #expect(finding.likelihood.factor == 0.2)
    }

    @Test func refusesABlockWithNoRationale() throws {
        let text = controls("""
            likelihood "no in-the-wild use" {
              tier = "research"
            }
        """)
        let found = errors(text)
        #expect(found.count == 1)
        #expect(found.first?.message.contains("rationale") == true)
    }

    @Test func refusesABlockThatStatesBothATierAndAPrior() throws {
        let text = controls("""
            likelihood "two numbers" {
              tier      = "research"
              prior     = 20
              rationale = "it says both"
            }
        """)
        #expect(errors(text).count == 1)
    }

    @Test func refusesTwoBlocksOnOneThreat() throws {
        let text = controls("""
            likelihood "first" {
              tier      = "research"
              rationale = "one"
            }

            likelihood "second" {
              tier      = "targeted"
              rationale = "two"
            }
        """)
        #expect(errors(text).count == 1)
    }

    @Test func writesTheBlockBackInTheCanonicalShape() throws {
        let text = controls("""
            likelihood "no in-the-wild use" {
              tier      = "research"
              rationale = "every bypass was researcher-found"
              sources   = ["https://example.test/a"]
            }
        """)
        let source = try #require(gateway.read(text).source)
        let written = gateway.write(source)
        let again = try #require(gateway.read(written).source)

        #expect(again == source)
        #expect(written.contains("likelihood \"no in-the-wild use\" {"))
        #expect(written.contains("sources   = [\"https://example.test/a\"]"))
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd ThreatModelKit && swift test --filter LikelihoodBlockTests`
Expected: FAIL, "cannot find 'LikelihoodFinding' in scope".

- [ ] **Step 3: Write the implementation**

Create `LikelihoodFinding.swift`:

```swift
/// What a person found out about how often an attack of this kind happens.
///
/// It is evidence, not a control. It multiplies the score, and it carries the
/// reasoning and the sources a reviewer reads.
public struct LikelihoodFinding: Equatable, Sendable {
    public let label: String
    public let likelihood: Likelihood
    public let rationale: String
    /// A URL, a CVE identifier, or any other text that says where the finding
    /// comes from.
    public let sources: [String]

    public init(label: String, likelihood: Likelihood, rationale: String, sources: [String] = []) {
        self.label = label
        self.likelihood = likelihood
        self.rationale = rationale
        self.sources = sources
    }
}
```

In `ControlsSource.swift`, add to `SourceThreatAnswer`:

```swift
    /// What a person found out about how often this attack happens, or nil.
    public let likelihood: LikelihoodFinding?
```

```swift
        likelihood: LikelihoodFinding? = nil,
```

```swift
        self.likelihood = likelihood
```

Leave `isAnswered` as it is: a finding is not an answer. Task 11 gives it the tolerance rule.

In `ControlsParser.swift`, add the variable, the case, the fault-message word, and the parse function:

```swift
        var likelihood: LikelihoodFinding?
```

```swift
            case "likelihood":
                let token = current
                if let finding = parseLikelihood() {
                    if likelihood != nil {
                        record("this threat holds two likelihood blocks; it holds one", at: token)
                    } else {
                        likelihood = finding
                    }
                }
```

```swift
    private mutating func parseLikelihood() -> LikelihoodFinding? {
        advance()
        guard let label = expect(.string, "what the finding is called") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var tier: String?
        var prior: Int?
        var rationale: String?
        var sources: [String] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "tier":
                let token = current
                let raw = parseTextAttribute() ?? ""
                if Likelihood(rawValue: raw) == nil {
                    record(
                        "tier is \"\(raw)\"; this application holds "
                            + Likelihood.allTiers.map { "\"\($0.id)\"" }.joined(separator: ", "),
                        at: token
                    )
                } else {
                    tier = raw
                }
            case "prior":
                let token = current
                prior = parseNumberAttribute()
                if let value = prior, Likelihood(prior: value) == nil {
                    record("prior is \(value); it runs from 0 to 100", at: token)
                }
            case "rationale":
                rationale = parseTextAttribute()
            case "sources":
                sources = parseListAttribute()
            default:
                record("a likelihood holds tier, prior, rationale and sources, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        if tier != nil && prior != nil {
            record("the likelihood \"\(label.text)\" states a tier and a prior; it states one", at: label)
            return nil
        }
        guard let rationale, rationale.isEmpty == false else {
            // Evidence nobody can justify is not evidence.
            record("the likelihood \"\(label.text)\" has no rationale", at: label)
            return nil
        }
        let read = tier.flatMap(Likelihood.init(rawValue:)) ?? prior.flatMap(Likelihood.init(prior:))
        guard let read else {
            record("the likelihood \"\(label.text)\" states no tier and no prior", at: label)
            return nil
        }
        return LikelihoodFinding(
            label: label.text,
            likelihood: read,
            rationale: rationale,
            sources: sources
        )
    }
```

`ControlsParser` has no `parseListAttribute` yet. Copy the one `ArchitectureParser.swift` already holds into `ControlsParser`, unchanged, beside `parseNumberAttribute`.

Add `likelihood` to the `default:` fault message inside `parseThreat`, and pass the value into the `SourceThreatAnswer(...)` it returns.

In `ControlsWriter.swift`, emit the block first inside the threat body, before the controls:

```swift
        if let finding = answer.likelihood {
            if body.isEmpty == false { body.append("") }
            body.append("likelihood \(quoted(finding.label)) {")
            var inner: [(String, String)] = []
            if Int(finding.likelihood.id) == nil {
                inner.append(("tier", quoted(finding.likelihood.id)))
            } else {
                inner.append(("prior", finding.likelihood.id))
            }
            inner.append(("rationale", quoted(finding.rationale)))
            if finding.sources.isEmpty == false {
                inner.append(("sources", "[" + finding.sources.map(quoted).joined(separator: ", ") + "]"))
            }
            body += indent(aligned(inner))
            body.append("}")
        }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd ThreatModelKit && swift test --filter LikelihoodBlockTests --filter ControlsParserTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources ThreatModelKit/Tests/UnitTests/LikelihoodBlockTests.swift
git commit -m "feat: a controls file states a likelihood finding with its sources"
```

---

### Task 5: A finding wins over the library's prior

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/ThreatModel.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/ApplyControlAnswers.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ThreatResolver.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/AssessThreatModel.swift`
- Test: `ThreatModelKit/Tests/UnitTests/LikelihoodFindingTests.swift`

**Interfaces:**
- Consumes: `LikelihoodFinding`, `ThreatKey`.
- Produces: `ThreatModel.likelihoodFindings: [ThreatKey: LikelihoodFinding]`, `ResolvedThreat.likelihoodFinding: LikelihoodFinding?`, `AssessedThreat.likelihoodRationale: String?`, `AssessedThreat.likelihoodSources: [String]`.

- [ ] **Step 1: Write the failing test**

```swift
import Testing
import ThreatModelKit
import TestSupport

@Suite("A likelihood finding against a library prior")
struct LikelihoodFindingTests {
    private let app = TestDependencies()

    private func threats() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    private func aComponentRaisingAThreat(likelihood: Likelihood) -> String {
        app.catalogue.add(
            technology: "laptop",
            threat: Threat(
                id: ThreatId("sip-bypass"),
                name: "SIP Bypass",
                description: "",
                severity: app.catalogue.severity(id: "critical"),
                likelihood: likelihood
            )
        )
        guard case .added(let componentId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "laptop", x: 0, y: 0, sensitivity: "restricted")
        ) else { return "" }
        return componentId
    }

    @Test func theFindingWinsOverThePrior() throws {
        let componentId = aComponentRaisingAThreat(likelihood: .commodity)
        let key = ThreatKey(threatId: "sip-bypass", sourceId: "component:\(componentId)")

        app.modelStore.mutate { model in
            model.likelihoodFindings[key] = LikelihoodFinding(
                label: "no in-the-wild use",
                likelihood: .research,
                rationale: "every bypass was researcher-found",
                sources: ["CVE-2021-30892"]
            )
        }

        let threat = try #require(threats().first)
        #expect(threat.scoreBeforeLikelihood == 16)
        #expect(threat.riskScore == 4)
        #expect(threat.likelihoodId == "research")
        #expect(threat.likelihoodRationale == "every bypass was researcher-found")
        #expect(threat.likelihoodSources == ["CVE-2021-30892"])
    }

    @Test func thePriorStandsWhenNoFindingNamesTheThreat() throws {
        _ = aComponentRaisingAThreat(likelihood: .targeted)
        let threat = try #require(threats().first)
        #expect(threat.riskScore == 10)
        #expect(threat.likelihoodRationale == nil)
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd ThreatModelKit && swift test --filter LikelihoodFindingTests`
Expected: FAIL, "value of type 'ThreatModel' has no member 'likelihoodFindings'".

- [ ] **Step 3: Write the implementation**

In `ThreatModel.swift`, add the store, its initialiser parameter with a default, and the assignment:

```swift
    /// What a person found out about how often each threat happens, keyed the
    /// way a compensating control is.
    public var likelihoodFindings: [ThreatKey: LikelihoodFinding]
```

In `ThreatResolver.swift`, read the finding first inside `likelihooded(_:)`:

```swift
    private func likelihooded(_ threat: ResolvedThreat) -> ResolvedThreat {
        let key = ThreatKey(threatId: threat.threat.id.value, sourceId: threat.source.id)
        let finding = model.likelihoodFindings[key]
        let likelihood = finding?.likelihood ?? threat.threat.likelihood
        guard likelihood != .commodity else { return threat }
```

and carry `likelihoodFinding: finding` into the `ResolvedThreat` it returns. Add the field to `ResolvedThreat` with a `nil` default, and carry it through `compensated(_:)` too.

In `ApplyControlAnswers.swift`, collect and write the findings beside the compensating controls:

```swift
        var likelihoods: [ThreatKey: LikelihoodFinding] = [:]
```

```swift
            if let finding = answer.likelihood {
                likelihoods[answer.key] = finding
            }
```

```swift
            model.likelihoodFindings = readLikelihoods
```

In `AssessThreatModel.swift`, add two fields with defaults and set them:

```swift
    /// Why the likelihood is what it is, from the controls file, or nil when
    /// the library's prior stands.
    public let likelihoodRationale: String?
    public let likelihoodSources: [String]
```

```swift
                    likelihoodRationale: threat.likelihoodFinding?.rationale,
                    likelihoodSources: threat.likelihoodFinding?.sources ?? [],
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd ThreatModelKit && swift test --filter LikelihoodFindingTests --filter ApplyControlAnswersTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources ThreatModelKit/Tests/UnitTests/LikelihoodFindingTests.swift
git commit -m "feat: a controls file's likelihood finding wins over the library prior"
```

---

### Task 6: The `severity_override` block

**Files:**
- Create: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/SeverityDecision.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ControlsSource.swift`
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/ControlsParser.swift`
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/ControlsWriter.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/ThreatModel.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/ApplyControlAnswers.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ThreatResolver.swift`
- Test: `ThreatModelKit/Tests/UnitTests/SeverityDecisionTests.swift`

**Interfaces:**
- Consumes: `ThreatKey`, `Taxonomy`.
- Produces: `SeverityDecision(severityId:rationale:sources:)`, `SourceThreatAnswer.severityDecision: SeverityDecision?`, `ThreatModel.severityDecisions: [ThreatKey: SeverityDecision]`, `ResolvedThreat.severityDecision: SeverityDecision?`.

The file's block is keyed by `ThreatKey`, and it wins over the technology-wide `severityOverrides` the application's own menu writes.

- [ ] **Step 1: Write the failing test**

```swift
import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

@Suite("An assessor's severity decision")
struct SeverityDecisionTests {
    private let gateway = HclControlsSource()
    private let app = TestDependencies()

    private func controls(_ block: String) -> String {
        """
        controls for "Payments" {
          threat "sip-bypass" on component "laptop" {
        \(block)
          }
        }
        """
    }

    @Test func readsTheBlockWithItsRationaleAndSources() throws {
        let text = controls("""
            severity_override "high" {
              rationale = "the exploit reads; the write path stays gated"
              sources   = ["CVE-2021-30892"]
            }
        """)
        let decision = try #require(gateway.read(text).source?.answers.first?.severityDecision)

        #expect(decision.severityId == "high")
        #expect(decision.rationale == "the exploit reads; the write path stays gated")
        #expect(decision.sources == ["CVE-2021-30892"])
    }

    @Test func refusesABlockWithNoRationale() throws {
        let text = controls("""
            severity_override "high" {
              sources = ["CVE-2021-30892"]
            }
        """)
        let errors = gateway.read(text).diagnostics.filter { $0.severity == .error }
        #expect(errors.count == 1)
        #expect(errors.first?.message.contains("rationale") == true)
    }

    @Test func writesTheBlockBackAndReadsWhatItWrote() throws {
        let text = controls("""
            severity_override "high" {
              rationale = "the exploit reads"
            }
        """)
        let source = try #require(gateway.read(text).source)
        let written = gateway.write(source)
        #expect(try #require(gateway.read(written).source) == source)
    }

    @Test func lowersTheSeverityTheScoreUses() throws {
        app.catalogue.add(
            technology: "laptop",
            threat: Threat(
                id: ThreatId("sip-bypass"),
                name: "SIP Bypass",
                description: "",
                severity: app.catalogue.severity(id: "critical")
            )
        )
        guard case .added(let componentId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "laptop", x: 0, y: 0, sensitivity: "restricted")
        ) else {
            Issue.record("the component was not added")
            return
        }

        app.modelStore.mutate { model in
            model.severityDecisions[
                ThreatKey(threatId: "sip-bypass", sourceId: "component:\(componentId)")
            ] = SeverityDecision(
                severityId: "medium",
                rationale: "the exploit reads",
                sources: []
            )
        }

        let threat = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats.first
        )
        #expect(threat.severityId == "medium")
        #expect(threat.riskScore < 16)
    }
}
```

Note: read `InMemoryTechnologyCatalogue` for the severity ids its taxonomy holds, and use ids that taxonomy has.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd ThreatModelKit && swift test --filter SeverityDecisionTests`
Expected: FAIL, "cannot find 'SeverityDecision' in scope".

- [ ] **Step 3: Write the implementation**

Create `SeverityDecision.swift`:

```swift
/// The severity an assessor chose for one threat on one source, and why.
///
/// The `severity` attribute a controls file holds is what the compiler wrote,
/// and the application recomputes it. This is what a person decided, so a
/// catalogue that raises a threat's severity never hides behind a stale
/// written value.
public struct SeverityDecision: Equatable, Sendable {
    public let severityId: String
    public let rationale: String
    public let sources: [String]

    public init(severityId: String, rationale: String, sources: [String] = []) {
        self.severityId = severityId
        self.rationale = rationale
        self.sources = sources
    }
}
```

Add `severityDecision: SeverityDecision?` to `SourceThreatAnswer` and `severityDecisions: [ThreatKey: SeverityDecision]` to `ThreatModel`, both with defaults, the way Task 4 and Task 5 added theirs.

In `ControlsParser.swift`, add the case and the function:

```swift
            case "severity_override":
                let token = current
                if let decision = parseSeverityOverride() {
                    if severityDecision != nil {
                        record("this threat holds two severity_override blocks; it holds one", at: token)
                    } else {
                        severityDecision = decision
                    }
                }
```

```swift
    private mutating func parseSeverityOverride() -> SeverityDecision? {
        advance()
        guard let label = expect(.string, "the severity the assessor chose") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var rationale: String?
        var sources: [String] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "rationale": rationale = parseTextAttribute()
            case "sources": sources = parseListAttribute()
            default:
                record("a severity_override holds rationale and sources, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard let rationale, rationale.isEmpty == false else {
            record("the severity_override \"\(label.text)\" has no rationale", at: label)
            return nil
        }
        return SeverityDecision(severityId: label.text, rationale: rationale, sources: sources)
    }
```

The parser does not know the taxonomy, so it does not check the severity id here. `ApplyControlAnswers` checks it against the taxonomy and warns:

```swift
            if let decision = answer.severityDecision {
                if catalogue.taxonomy().severity(id: decision.severityId) == nil {
                    warnings.append(
                        Diagnostic(
                            severity: .warning,
                            line: 1,
                            column: 1,
                            message: "\"\(decision.severityId)\" is not a severity this catalogue holds, "
                                + "so the severity_override on \"\(answer.threatId)\" is not applied"
                        )
                    )
                } else {
                    decisions[answer.key] = decision
                }
            }
```

In `ControlsWriter.swift`, emit the block after the controls and before the compensating blocks:

```swift
        if let decision = answer.severityDecision {
            if body.isEmpty == false { body.append("") }
            body.append("severity_override \(quoted(decision.severityId)) {")
            var inner: [(String, String)] = [("rationale", quoted(decision.rationale))]
            if decision.sources.isEmpty == false {
                inner.append(("sources", "[" + decision.sources.map(quoted).joined(separator: ", ") + "]"))
            }
            body += indent(aligned(inner))
            body.append("}")
        }
```

In `ThreatResolver.swift`, the `severity(for:overrideKey:)` function takes the source id as well, and reads the decision first:

```swift
    private func severity(for threat: Threat, overrideKey: SeverityOverrideKey, sourceId: String)
        -> (severity: ThreatSeverity, overriddenId: String?, decision: SeverityDecision?) {
        let key = ThreatKey(threatId: threat.id.value, sourceId: sourceId)
        if let decision = model.severityDecisions[key],
           let chosen = catalogue.taxonomy().severity(id: decision.severityId) {
            return (chosen, decision.severityId, decision)
        }
        guard let overriddenId = model.severityOverrides[overrideKey],
              let overridden = catalogue.taxonomy().severity(id: overriddenId) else {
            return (threat.severity, nil, nil)
        }
        return (overridden, overriddenId, nil)
    }
```

Update the three call sites to pass the source id they already build (`"component:\(component.id.value)"`, `"connection:\(connection.id.value)"`, `"zone:\(zone.id.value)"`), and carry `chosen.decision` into each `ResolvedThreat` as a new `severityDecision` field with a `nil` default.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd ThreatModelKit && swift test --filter SeverityDecisionTests --filter OverrideThreatSeverityTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources ThreatModelKit/Tests/UnitTests/SeverityDecisionTests.swift
git commit -m "feat: an assessor states a severity decision with its reason"
```

---

### Task 7: `sources` on the compensating and recommendation blocks

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/CompensatingControl.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/Recommendation.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ControlsSource.swift` (`SourceRecommendation`)
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/ControlsParser.swift`
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/ControlsWriter.swift`
- Test: `ThreatModelKit/Tests/UnitTests/EvidenceSourcesTests.swift`

**Interfaces:**
- Consumes: the parser and writer from Task 4 and Task 6.
- Produces: `CompensatingControl.sources: [String]`, `Recommendation.sources: [String]`, `SourceRecommendation.sources: [String]`.

- [ ] **Step 1: Write the failing test**

```swift
import ArchitectureDSL
import Testing
import ThreatModelKit

@Suite("Where a piece of evidence comes from")
struct EvidenceSourcesTests {
    private let gateway = HclControlsSource()

    private let text = """
    controls for "Payments" {
      threat "credential-theft" on component "api" {
        compensating "Break-glass account watched by the SIEM" {
          reduces_risk_by = 40
          rationale       = "The one account left alerts on use."
          sources         = ["https://example.test/adr/17"]
        }

        recommendation "Allow-list hardened-runtime binaries only" {
          note    = "Homebrew builds are ad-hoc signed"
          sources = ["https://attack.mitre.org/techniques/T1218/"]
        }
      }
    }
    """

    @Test func readsTheSourcesOfBothBlocks() throws {
        let answer = try #require(gateway.read(text).source?.answers.first)
        #expect(answer.compensating.first?.sources == ["https://example.test/adr/17"])
        #expect(answer.recommendations.first?.sources == ["https://attack.mitre.org/techniques/T1218/"])
    }

    @Test func writesThemBackAndReadsWhatItWrote() throws {
        let source = try #require(gateway.read(text).source)
        #expect(try #require(gateway.read(gateway.write(source)).source) == source)
    }

    @Test func aBlockWithNoSourcesReadsAsAnEmptyList() throws {
        let plain = """
        controls for "Payments" {
          threat "credential-theft" on component "api" {
            compensating "Watched" {
              reduces_risk_by = 40
              rationale       = "It alerts on use."
            }
          }
        }
        """
        let answer = try #require(gateway.read(plain).source?.answers.first)
        #expect(answer.compensating.first?.sources == [])
        #expect(gateway.write(try #require(gateway.read(plain).source)).contains("sources") == false)
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd ThreatModelKit && swift test --filter EvidenceSourcesTests`
Expected: FAIL, "value of type 'CompensatingControl' has no member 'sources'".

- [ ] **Step 3: Write the implementation**

Add `public let sources: [String]` with a `[]` default to `CompensatingControl`, `Recommendation` and `SourceRecommendation`. Add the `case "sources": sources = parseListAttribute()` line to `parseCompensating()` and `parseRecommendation()`, name `sources` in both `default:` fault messages, and pass the list into the value each function returns. In `ControlsWriter.swift`, append the `sources` attribute to the compensating block's `aligned([...])` list and to the recommendation block when the list is not empty.

`ApplyControlAnswers.swift` already maps `SourceRecommendation` to `Recommendation`; add `sources: $0.sources` to that mapping.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd ThreatModelKit && swift test --filter EvidenceSourcesTests --filter RecommendationLanguageTests --filter CompensatingControlTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources ThreatModelKit/Tests/UnitTests/EvidenceSourcesTests.swift
git commit -m "feat: every evidence block carries its sources"
```

---

### Task 8: A compile keeps the new blocks

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/CompileControls.swift:96-126`
- Test: `ThreatModelKit/Tests/UnitTests/CompileControlsTests.swift`

**Interfaces:**
- Consumes: `SourceThreatAnswer.likelihood`, `.severityDecision`, and the `sources` lists.
- Produces: nothing new. A compile of a file holding the new blocks writes them back.

- [ ] **Step 1: Write the failing test**

Add to `CompileControlsTests.swift`, matching the fixture helpers that file already holds:

```swift
    @Test func keepsALikelihoodFindingAndASeverityDecisionThroughACompile() throws {
        let first = try #require(compiled(architecture: architectureText, controls: nil))
        let edited = first.replacingOccurrences(
            of: "  score",
            with: """
              likelihood "no in-the-wild use" {
                tier      = "research"
                rationale = "every bypass was researcher-found"
                sources   = ["CVE-2021-30892"]
              }

              severity_override "high" {
                rationale = "the exploit reads"
              }

              score
            """
        )

        let again = try #require(compiled(architecture: architectureText, controls: edited))

        #expect(again.contains("likelihood \"no in-the-wild use\""))
        #expect(again.contains("severity_override \"high\""))
        #expect(again.contains("CVE-2021-30892"))
    }
```

Note: read the fixtures at the top of `CompileControlsTests.swift` first. Use its existing `architectureText` and its existing helper for running a compile; if the helper has another name, use that name. The `replacingOccurrences` above targets the first `score` attribute the writer emits, which is inside the first threat block.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd ThreatModelKit && swift test --filter CompileControlsTests`
Expected: FAIL, the second compile drops both blocks.

- [ ] **Step 3: Write the implementation**

In `CompileControls.swift`, carry the two new fields from `previous` into the `SourceThreatAnswer` the loop builds, beside `compensating` and `recommendations`:

```swift
                likelihood: previous?.likelihood,
                severityDecision: previous?.severityDecision,
```

Do the same in the stale-answer loop below it, so an answer that moves into a stale block keeps its evidence.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd ThreatModelKit && swift test --filter CompileControlsTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources ThreatModelKit/Tests/UnitTests/CompileControlsTests.swift
git commit -m "fix: a compile keeps the likelihood and severity blocks it read"
```

---

### Task 9: Assumed edges, system assumptions and the tolerance in `.arch`

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ArchitectureSource.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/MitigatesEdge.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/modelling/domain/ThreatModel.swift`
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/ArchitectureParser.swift`
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/ArchitectureWriter.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/ImportArchitecture.swift:120-127`
- Test: `ThreatModelKit/Tests/UnitTests/AssumptionLanguageTests.swift`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `MitigationStatus` (`.adopted`, `.assumed`), `MitigatesEdge.status`, `SystemAssumption(label:text:owner:)`, `ArchitectureSource.assumptions`, `ArchitectureSource.riskTolerance: String?`, `ThreatModel.assumptions`, `ThreatModel.riskTolerance: RiskLevel`.

- [ ] **Step 1: Write the failing test**

```swift
import ArchitectureDSL
import Testing
import ThreatModelKit

@Suite("Assumptions and the risk tolerance in an architecture file")
struct AssumptionLanguageTests {
    private let gateway = HclArchitectureSource()

    private let text = """
    system "clearancekit" {
      risk_tolerance = "medium"

      assumption "mdm-push" {
        text  = "the hardening baseline is written, and MDM has not pushed it yet"
        owner = "platform team"
      }

      component "laptop" {
        technology = "workstation"
      }

      component "hardening" {
        technology = "es-client"
      }

      mitigates hardening -> laptop {
        threats         = ["persistence"]
        reduces_risk_by = 60
        status          = "assumed"
      }
    }
    """

    private func errors(_ text: String) -> [Diagnostic] {
        gateway.read(text).diagnostics.filter { $0.severity == .error }
    }

    @Test func readsTheToleranceTheAssumptionAndTheStatus() throws {
        let source = try #require(gateway.read(text).source)

        #expect(source.riskTolerance == "medium")
        #expect(source.assumptions.first?.label == "mdm-push")
        #expect(source.assumptions.first?.owner == "platform team")
        #expect(source.mitigates.first?.status == "assumed")
    }

    @Test func anEdgeThatStatesNoStatusIsAdopted() throws {
        let plain = text.replacingOccurrences(of: "    status          = \"assumed\"\n", with: "")
        let source = try #require(gateway.read(plain).source)
        #expect(source.mitigates.first?.status == nil)
    }

    @Test func refusesAStatusTheApplicationDoesNotHold() throws {
        let wrong = text.replacingOccurrences(of: "\"assumed\"", with: "\"hoped\"")
        #expect(errors(wrong).count == 1)
    }

    @Test func refusesAToleranceTheRiskLadderDoesNotHold() throws {
        let wrong = text.replacingOccurrences(of: "\"medium\"", with: "\"relaxed\"")
        #expect(errors(wrong).count == 1)
    }

    @Test func refusesAnAssumptionWithNoText() throws {
        let wrong = text.replacingOccurrences(
            of: "    text  = \"the hardening baseline is written, and MDM has not pushed it yet\"\n",
            with: ""
        )
        #expect(errors(wrong).count == 1)
    }

    @Test func refusesTwoAssumptionsWithOneLabel() throws {
        let twice = text.replacingOccurrences(
            of: "  component \"laptop\" {",
            with: """
              assumption "mdm-push" {
                text = "said twice"
              }

              component "laptop" {
            """
        )
        #expect(errors(twice).count == 1)
    }

    @Test func writesEverythingBackAndReadsWhatItWrote() throws {
        let source = try #require(gateway.read(text).source)
        #expect(try #require(gateway.read(gateway.write(source)).source) == source)
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd ThreatModelKit && swift test --filter AssumptionLanguageTests`
Expected: FAIL, "value of type 'ArchitectureSource' has no member 'riskTolerance'".

- [ ] **Step 3: Write the implementation**

In `ArchitectureSource.swift`:

```swift
    /// The risk level a likelihood finding may answer up to. Nil means low.
    public let riskTolerance: String?
    public let assumptions: [SourceAssumption]
```

```swift
public struct SourceAssumption: Equatable, Sendable {
    public let label: String
    public let text: String
    public let owner: String?

    public init(label: String, text: String, owner: String? = nil) {
        self.label = label
        self.text = text
        self.owner = owner
    }
}
```

Add `public let status: String?` to `SourceMitigates`, with a `nil` default.

Create the status in `MitigatesEdge.swift`:

```swift
/// Whether a team has done the work an edge describes.
public enum MitigationStatus: String, CaseIterable, Equatable, Sendable {
    case adopted
    case assumed

    public var label: String {
        switch self {
        case .adopted: "Adopted"
        case .assumed: "Assumed"
        }
    }
}
```

and add `public let status: MitigationStatus` to `MitigatesEdge`, defaulting to `.adopted`.

In `ThreatModel.swift`:

```swift
    /// What the model takes on trust. The report gives them a section.
    public var assumptions: [SystemAssumption]
    /// The risk level a likelihood finding may answer up to.
    public var riskTolerance: RiskLevel
```

with `assumptions: [SystemAssumption] = []` and `riskTolerance: RiskLevel = .low` in the initialiser. Put `SystemAssumption` in a new file beside `ThreatModel.swift`:

```swift
/// Something the model takes on trust, and who owns it.
public struct SystemAssumption: Equatable, Sendable {
    public let label: String
    public let text: String
    public let owner: String?

    public init(label: String, text: String, owner: String? = nil) {
        self.label = label
        self.text = text
        self.owner = owner
    }
}
```

In `ArchitectureParser.swift`, add the two cases to the system switch, name them in the `default:` fault message, and add the two functions:

```swift
            case "risk_tolerance":
                let token = current
                let raw = parseTextAttribute() ?? ""
                if RiskLevel(rawValue: raw) == nil {
                    record(
                        "risk_tolerance is \"\(raw)\"; this application holds "
                            + RiskLevel.allCases.map { "\"\($0.rawValue)\"" }.joined(separator: ", "),
                        at: token
                    )
                } else {
                    riskTolerance = raw
                }
            case "assumption":
                if let assumption = parseAssumption() { assumptions.append(assumption) }
```

```swift
    private mutating func parseAssumption() -> SourceAssumption? {
        advance()
        guard let label = expect(.string, "what the assumption is called") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var text: String?
        var owner: String?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "text": text = parseTextAttribute()
            case "owner": owner = parseTextAttribute()
            default:
                record("an assumption holds text and owner, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard let text, text.isEmpty == false else {
            record("the assumption \"\(label.text)\" has no text", at: label)
            return nil
        }
        return SourceAssumption(label: label.text, text: text, owner: owner)
    }
```

In `parseMitigates()`, add the case, name `status` in its `default:` message, and pass it through:

```swift
            case "status":
                let token = current
                let raw = parseTextAttribute() ?? ""
                if MitigationStatus(rawValue: raw) == nil {
                    record(
                        "status is \"\(raw)\"; a mitigates edge is \"adopted\" or \"assumed\"",
                        at: token
                    )
                } else {
                    status = raw
                }
```

In `check(_:)`, where the parser already checks the mitigates edges, add the duplicate-label check:

```swift
        var labels: Set<String> = []
        for assumption in source.assumptions where labels.insert(assumption.label).inserted == false {
            record("the assumption \"\(assumption.label)\" is declared twice", at: tokens[0])
        }
```

In `ArchitectureWriter.swift`, emit `risk_tolerance` first inside the system body when it is not nil, then each `assumption` block, and emit `status` inside a `mitigates` block only when the edge states `"assumed"`. Follow the alignment helpers the writer already uses.

In `ImportArchitecture.swift:120`, carry all three onto the model:

```swift
        model.mitigatesEdges = source.mitigates.map { edge in
            MitigatesEdge(
                source: ComponentId(edge.sourceId),
                target: ComponentId(edge.targetId),
                threatIds: edge.threatIds.map(ThreatId.init),
                reducesRiskBy: edge.reducesRiskBy,
                status: edge.status.flatMap(MitigationStatus.init(rawValue:)) ?? .adopted
            )
        }
        model.assumptions = source.assumptions.map {
            SystemAssumption(label: $0.label, text: $0.text, owner: $0.owner)
        }
        model.riskTolerance = source.riskTolerance.flatMap(RiskLevel.init(rawValue:)) ?? .low
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd ThreatModelKit && swift test --filter AssumptionLanguageTests --filter ArchitectureParserTests --filter ArchitectureWriterTests --filter ImportArchitectureTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources ThreatModelKit/Tests/UnitTests/AssumptionLanguageTests.swift
git commit -m "feat: an architecture file states assumptions and a risk tolerance"
```

---

### Task 10: Two postures

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ComponentMitigations.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/domain/ThreatResolver.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/assessment/usecase/AssessThreatModel.swift`
- Test: `ThreatModelKit/Tests/UnitTests/AssumedMitigationTests.swift`

**Interfaces:**
- Consumes: `MitigationStatus`, `MitigatesEdge.status`.
- Produces: `ComponentMitigations.apply(score:threatId:target:edges:statuses:nameOf:)`, `ResolvedThreat.scoreIfAssumptionsHold: Int`, `ResolvedThreat.assumedMitigations: [ComponentMitigation]`, `AssessedThreat.scoreIfAssumptionsHold: Int`, `AssessedThreat.assumedByComponentLabels: [String]`.

The residual pass reads `[.adopted]`. The target pass reads `[.adopted, .assumed]`. Every later stage runs on both numbers, so the two differ by the assumed edges alone.

- [ ] **Step 1: Write the failing test**

```swift
import Testing
import ThreatModelKit
import TestSupport

@Suite("What an assumed mitigation does to the two postures")
struct AssumedMitigationTests {
    private let app = TestDependencies()

    private func threats() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    @Test func anAdoptedEdgeLowersBothNumbers() throws {
        let (protector, target, threatId) = twoComponents(status: .adopted)
        _ = protector
        _ = threatId

        let threat = try #require(threats().first { $0.source.id == "component:\(target)" })
        #expect(threat.riskScore == threat.scoreIfAssumptionsHold)
        #expect(threat.mitigatedByComponentLabels.isEmpty == false)
        #expect(threat.assumedByComponentLabels.isEmpty)
    }

    @Test func anAssumedEdgeLowersTheTargetPostureOnly() throws {
        let (_, target, _) = twoComponents(status: .assumed)

        let threat = try #require(threats().first { $0.source.id == "component:\(target)" })
        #expect(threat.riskScore == 16)
        #expect(threat.scoreIfAssumptionsHold == 6)
        #expect(threat.mitigatedByComponentLabels.isEmpty)
        #expect(threat.assumedByComponentLabels.isEmpty == false)
    }

    /// Draws a protector, a protected component and one edge between them.
    private func twoComponents(status: MitigationStatus) -> (String, String, String) {
        app.catalogue.add(
            technology: "laptop",
            threat: Threat(
                id: ThreatId("persistence"),
                name: "Persistence",
                description: "",
                severity: app.catalogue.severity(id: "critical")
            )
        )
        app.catalogue.add(technology: "es-client", threat: nil)

        guard case .added(let target) = app.addComponent().execute(
            AddComponentRequest(technologyId: "laptop", x: 0, y: 0, sensitivity: "restricted")
        ),
        case .added(let protector) = app.addComponent().execute(
            AddComponentRequest(technologyId: "es-client", x: 200, y: 0, sensitivity: "internal")
        ) else { return ("", "", "") }

        app.modelStore.mutate { model in
            model.mitigatesEdges = [
                MitigatesEdge(
                    source: ComponentId(protector),
                    target: ComponentId(target),
                    threatIds: [ThreatId("persistence")],
                    reducesRiskBy: 60,
                    status: status
                )
            ]
        }
        return (protector, target, "persistence")
    }
}
```

Note: `InMemoryTechnologyCatalogue.add(technology:threat:)` may not take a nil threat. Read the fake and use whatever call it gives for a technology with no threats.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd ThreatModelKit && swift test --filter AssumedMitigationTests`
Expected: FAIL, "value of type 'AssessedThreat' has no member 'scoreIfAssumptionsHold'".

- [ ] **Step 3: Write the implementation**

In `ComponentMitigations.swift`, filter by status:

```swift
    public static func apply(
        score: Int,
        threatId: ThreatId,
        target: ComponentId,
        edges: [MitigatesEdge],
        statuses: Set<MitigationStatus> = [.adopted],
        nameOf: (ComponentId) -> String
    ) -> (score: Int, by: [ComponentMitigation]) {
        let answering = edges.filter {
            $0.target == target && $0.answers(threatId) && statuses.contains($0.status)
        }
```

In `ThreatResolver.swift`, add the two fields to `ResolvedThreat`:

```swift
    /// The score when every assumed mitigation is in place. Equal to
    /// `score.value` when no assumed edge answers this threat.
    public let scoreIfAssumptionsHold: Int
    /// The assumed edges that lowered the target posture.
    public let assumedMitigations: [ComponentMitigation]
```

with `scoreIfAssumptionsHold: Int? = nil` and `assumedMitigations: [ComponentMitigation] = []` in the initialiser, and `self.scoreIfAssumptionsHold = scoreIfAssumptionsHold ?? score.value`.

In the component loop, run the edge stage twice:

```swift
                let byComponents = ComponentMitigations.apply(
                    score: mitigation.score,
                    threatId: threat.id,
                    target: component.id,
                    edges: model.mitigatesEdges,
                    statuses: [.adopted],
                    nameOf: { nameById[$0] ?? $0.value }
                )
                let byAssumed = ComponentMitigations.apply(
                    score: mitigation.score,
                    threatId: threat.id,
                    target: component.id,
                    edges: model.mitigatesEdges,
                    statuses: [.adopted, .assumed],
                    nameOf: { nameById[$0] ?? $0.value }
                )
```

Pass `scoreIfAssumptionsHold: byAssumed.score` and `assumedMitigations: byAssumed.by.filter { assumed(edgeFrom: $0.protectorId, to: component.id, threat: threat.id) }` — where the filter is this private helper on the resolver:

```swift
    /// True when the edge that gives this mitigation is assumed, so the report
    /// names only the work nobody has done yet.
    private func assumed(edgeFrom source: ComponentId, to target: ComponentId, threat: ThreatId) -> Bool {
        model.mitigatesEdges.contains {
            $0.source == source && $0.target == target && $0.answers(threat) && $0.status == .assumed
        }
    }
```

The likelihood stage and the compensating stage each carry both numbers. In `likelihooded(_:)` and `compensated(_:)`, apply the same factor to `scoreIfAssumptionsHold` that the function applies to `score`:

```swift
        let reducedTarget = Likelihood.apply(to: threat.scoreIfAssumptionsHold, likelihood: likelihood)
```

```swift
        let reducedTarget = max(
            1,
            Int((Double(threat.scoreIfAssumptionsHold) * (1 - Double(strongest) / 100)).rounded())
        )
```

In `AssessThreatModel.swift`, add `scoreIfAssumptionsHold: Int` (default `nil` resolving to `riskScore`) and `assumedByComponentLabels: [String]` (default `[]`) to `AssessedThreat`, and set them from the resolved threat.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd ThreatModelKit && swift test --filter AssumedMitigationTests --filter ComponentMitigationTests`
Then the whole suite: `cd ThreatModelKit && swift test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources ThreatModelKit/Tests/UnitTests/AssumedMitigationTests.swift
git commit -m "feat: an assumed mitigation lowers the target posture, never the residual"
```

---

### Task 11: `check` reads the tolerance

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/domain/ControlsSource.swift` (`SourceThreatAnswer.isAnswered`)
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/CheckControlAnswers.swift`
- Modify: `ThreatModelKit/Sources/ArchitectureDSL/ControlsParser.swift` and `ControlsWriter.swift` (the `tolerance` attribute on the controls file)
- Modify: `ThreatModelKit/Sources/ThreatModelKit/architecture/usecase/CompileControls.swift`
- Modify: `ThreatModelKit/Sources/CommandLineApplication/CommandLineApplication.swift`
- Test: `ThreatModelKit/Tests/UnitTests/CheckToleranceTests.swift`

**Interfaces:**
- Consumes: `RiskLevel`, `SourceThreatAnswer.likelihood`, `SourceThreatAnswer.score`, `ThreatModel.riskTolerance`.
- Produces: `ControlsSource.riskTolerance: String?`, `CheckControlAnswersRequest.tolerance: String?`, and the `--tolerance <level>` flag.

The compiler writes the system's tolerance into the controls file as `tolerance = "<level>"`, so `check` reads one file and needs no second parse of the architecture. `CheckControlAnswersRequest.tolerance` overrides it.

- [ ] **Step 1: Write the failing test**

```swift
import Testing
import ThreatModelKit
import TestSupport

@Suite("What the risk tolerance does to a check")
struct CheckToleranceTests {
    private let app = TestDependencies()

    private func controls(score: Int, tolerance: String) -> String {
        """
        controls for "ClearanceKit" {
          tolerance = "\(tolerance)"

          threat "sip-bypass" on component "laptop" {
            severity = "critical"
            score    = \(score)

            likelihood "no in-the-wild use" {
              tier      = "research"
              rationale = "every bypass was researcher-found"
            }
          }
        }
        """
    }

    @Test func aFindingAnswersAThreatInsideTheTolerance() throws {
        let source = try #require(HclControlsSource().read(controls(score: 3, tolerance: "low")).source)
        #expect(source.answers.first?.isAnswered(within: .low) == true)
    }

    @Test func aFindingAnswersNothingAboveTheTolerance() throws {
        let source = try #require(HclControlsSource().read(controls(score: 6, tolerance: "low")).source)
        #expect(source.answers.first?.isAnswered(within: .low) == false)
        #expect(source.answers.first?.isAnswered(within: .medium) == true)
    }

    @Test func aThreatWithNoFindingStillNeedsAnAnswer() throws {
        let plain = """
        controls for "ClearanceKit" {
          threat "sip-bypass" on component "laptop" {
            severity = "critical"
            score    = 2
          }
        }
        """
        let source = try #require(HclControlsSource().read(plain).source)
        #expect(source.answers.first?.isAnswered(within: .critical) == false)
    }

    @Test func theFileStatesTheToleranceTheCheckUses() throws {
        let source = try #require(HclControlsSource().read(controls(score: 3, tolerance: "medium")).source)
        #expect(source.riskTolerance == "medium")
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd ThreatModelKit && swift test --filter CheckToleranceTests`
Expected: FAIL, "value of type 'SourceThreatAnswer' has no member 'isAnswered(within:)'".

- [ ] **Step 3: Write the implementation**

In `ControlsSource.swift`, add the file-level attribute and the rule:

```swift
    /// The risk level a likelihood finding may answer up to, written by the
    /// compiler from the architecture file. Nil means low.
    public let riskTolerance: String?
```

```swift
    /// True when a person has answered this threat.
    ///
    /// A likelihood finding answers a threat only inside the project's
    /// tolerance: evidence closes a threat nobody exploits, and it never
    /// closes a High one.
    public func isAnswered(within tolerance: RiskLevel) -> Bool {
        if isAnswered { return true }
        guard likelihood != nil, let score else { return false }
        return RiskScore(value: score).level.rank <= tolerance.rank
    }
```

`RiskLevel` has no `rank` yet. Add one to `RiskScore.swift`:

```swift
    /// Weakest first, so a check can ask whether one level sits inside another.
    public var rank: Int {
        switch self {
        case .low: 1
        case .medium: 2
        case .high: 3
        case .critical: 4
        }
    }
```

In `ControlsParser.swift`, read `tolerance` beside `catalogue`, and check the value against `RiskLevel`. In `ControlsWriter.swift`, write it under `catalogue`. In `CompileControls.swift`, set it from the imported model:

```swift
                    riskTolerance: model.riskTolerance.rawValue,
```

In `CheckControlAnswers.swift`, take the override and use the rule:

```swift
public struct CheckControlAnswersRequest: Equatable, Sendable {
    public let architectureText: String
    public let controlsText: String?
    /// A risk level that overrides what the architecture file states, or nil.
    public let tolerance: String?

    public init(architectureText: String, controlsText: String? = nil, tolerance: String? = nil) {
        self.architectureText = architectureText
        self.controlsText = controlsText
        self.tolerance = tolerance
    }
}
```

```swift
        let tolerance = request.tolerance.flatMap(RiskLevel.init(rawValue:))
            ?? source.riskTolerance.flatMap(RiskLevel.init(rawValue:))
            ?? .low
```

```swift
            guard answer.isAnswered(within: tolerance) == false else { continue }
```

Add the level to the response so the executable can say what it used:

```swift
    case checked(unanswered: [UnansweredThreat], stale: [String], diagnostics: [Diagnostic], tolerance: String)
```

Update `isClean` and every call site for the new associated value.

In `CommandLineApplication.swift`, read the flag beside `--catalogue`:

```swift
            case "--tolerance":
                index += 1
                tolerance = index < words.count ? words[index] : nil
```

pass it into the request, and after the loop over `unanswered`, state what the check used:

```swift
            output("\(system.name): checked against a \(tolerance) risk tolerance")
```

Add the flag to `Self.usage` under `Options:`:

```
      --tolerance <level>  a likelihood finding answers a threat up to this level
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd ThreatModelKit && swift test --filter CheckToleranceTests --filter CommandLineApplicationTests`
Expected: PASS. Fix the `CommandLineApplicationTests` expectation for the help text, which now holds one more line.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources ThreatModelKit/Tests/UnitTests/CheckToleranceTests.swift
git commit -m "feat: a likelihood finding answers a threat inside the risk tolerance"
```

---

### Task 12: The report shows likelihood, sources and both postures

**Files:**
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/domain/Report.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/BuildThreatModelReport.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/ExportModelAsMarkdown.swift`
- Modify: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownRollups.swift`
- Create: `ThreatModelKit/Sources/ThreatModelKit/reporting/usecase/MarkdownAssumptions.swift`
- Test: `ThreatModelKit/Tests/UnitTests/LikelihoodReportTests.swift`

**Interfaces:**
- Consumes: every field Tasks 3, 5, 6, 7 and 10 added to `AssessedThreat`, and `ThreatModel.assumptions`.
- Produces: `ReportThreat.likelihoodLabel/likelihoodRationale/likelihoodSources/scoreBeforeLikelihood/scoreIfAssumptionsHold/severityDecision`, `Report.assumptions: [ReportAssumption]`, `MarkdownAssumptions.lines(_:)`.

- [ ] **Step 1: Write the failing test**

```swift
import Testing
import ThreatModelKit
import TestSupport

@Suite("What the report says about likelihood and assumptions")
struct LikelihoodReportTests {
    private let app = TestDependencies()

    private func markdown() -> String {
        app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown
    }

    @Test func statesTheTierTheReasonAndTheSources() throws {
        app.catalogue.add(
            technology: "laptop",
            threat: Threat(
                id: ThreatId("sip-bypass"),
                name: "SIP Bypass",
                description: "A researcher's path.",
                severity: app.catalogue.severity(id: "critical")
            )
        )
        guard case .added(let componentId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "laptop", x: 0, y: 0, sensitivity: "restricted")
        ) else {
            Issue.record("the component was not added")
            return
        }
        app.modelStore.mutate { model in
            model.likelihoodFindings[
                ThreatKey(threatId: "sip-bypass", sourceId: "component:\(componentId)")
            ] = LikelihoodFinding(
                label: "no in-the-wild use",
                likelihood: .research,
                rationale: "every bypass was researcher-found",
                sources: ["https://example.test/a"]
            )
        }

        let text = markdown()
        #expect(text.contains("- Likelihood: Research (16 \u{2192} 4)"))
        #expect(text.contains("  - Rationale: every bypass was researcher-found"))
        #expect(text.contains("  - Source: https://example.test/a"))
    }

    @Test func listsTheAssumptionsAndTheirEdges() throws {
        app.modelStore.mutate { model in
            model.assumptions = [
                SystemAssumption(
                    label: "mdm-push",
                    text: "MDM has not pushed the baseline yet",
                    owner: "platform team"
                )
            ]
        }

        let text = markdown()
        #expect(text.contains("## Assumptions"))
        #expect(text.contains("- mdm-push: MDM has not pushed the baseline yet (platform team)"))
    }

    @Test func aModelWithNoAssumptionWritesNoSection() throws {
        #expect(markdown().contains("## Assumptions") == false)
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd ThreatModelKit && swift test --filter LikelihoodReportTests`
Expected: FAIL, the report holds no Likelihood line.

- [ ] **Step 3: Write the implementation**

In `Report.swift`, add to `ReportThreat` (each with a default):

```swift
    public let likelihoodLabel: String
    public let likelihoodRationale: String?
    public let likelihoodSources: [String]
    public let scoreBeforeLikelihood: Int
    public let scoreIfAssumptionsHold: Int
    public let severityDecision: ReportSeverityDecision?
```

```swift
public struct ReportSeverityDecision: Equatable, Sendable {
    public let fromLabel: String
    public let toLabel: String
    public let rationale: String
    public let sources: [String]

    public init(fromLabel: String, toLabel: String, rationale: String, sources: [String] = []) {
        self.fromLabel = fromLabel
        self.toLabel = toLabel
        self.rationale = rationale
        self.sources = sources
    }
}

public struct ReportAssumption: Equatable, Sendable {
    public let label: String
    public let text: String
    public let owner: String?
    /// The edges this assumption stands behind, already worded for a reader.
    public let edges: [String]

    public init(label: String, text: String, owner: String? = nil, edges: [String] = []) {
        self.label = label
        self.text = text
        self.owner = owner
        self.edges = edges
    }
}
```

Add `public let assumptions: [ReportAssumption]` to `Report`, with a `[]` default.

In `BuildThreatModelReport.swift`, map the new fields from `AssessedThreat`, and build `assumptions` from the model's `assumptions` plus one line for each assumed edge:

```swift
            edges: model.mitigatesEdges.filter { $0.status == .assumed }.map {
                "\(nameOf($0.source)) \u{2192} \(nameOf($0.target)),"
                    + " mitigates \($0.threatIds.map(\.value).joined(separator: ", ")),"
                    + " \u{2212}\($0.reducesRiskBy)%"
            }
```

Read how `BuildThreatModelReport` already reaches the model and names a component; reuse that, and add no second gateway.

Create `MarkdownAssumptions.swift`:

```swift
/// The report's Assumptions section.
///
/// A model that takes nothing on trust writes no section, so a reader never
/// meets an empty heading.
public enum MarkdownAssumptions {
    public static func lines(_ assumptions: [ReportAssumption]) -> [String] {
        guard assumptions.isEmpty == false else { return [] }

        var lines = ["## Assumptions", ""]
        for assumption in assumptions {
            var line = "- \(assumption.label): \(assumption.text)"
            if let owner = assumption.owner { line += " (\(owner))" }
            lines.append(line)
            for edge in assumption.edges {
                lines.append("  - \(edge)")
            }
        }
        lines.append("")
        return lines
    }
}
```

In `ExportModelAsMarkdown.swift`, call `MarkdownAssumptions.lines(report.assumptions)` after the rollup tables and before the threats, and add to the threat block, after the Risk line:

```swift
            if threat.scoreBeforeLikelihood != threat.riskScore {
                lines.append(
                    "- Likelihood: \(threat.likelihoodLabel)"
                        + " (\(threat.scoreBeforeLikelihood) \u{2192} \(threat.riskScore))"
                )
                if let rationale = threat.likelihoodRationale {
                    lines.append("  - Rationale: \(rationale)")
                }
                for source in threat.likelihoodSources {
                    lines.append("  - Source: \(source)")
                }
            }
            if let decision = threat.severityDecision {
                lines.append("- Severity decided: \(decision.fromLabel) \u{2192} \(decision.toLabel)")
                lines.append("  - Rationale: \(decision.rationale)")
                for source in decision.sources {
                    lines.append("  - Source: \(source)")
                }
            }
            if threat.scoreIfAssumptionsHold != threat.riskScore {
                lines.append("- If the assumptions hold: \(threat.scoreIfAssumptionsHold)")
            }
            for compensating in threat.compensating where compensating.sources.isEmpty == false {
                for source in compensating.sources {
                    lines.append("  - Source: \(source)")
                }
            }
```

In `MarkdownRollups.swift`, add the extra column to the top-residual table only when at least one row differs:

```swift
            let showsAssumed = tables.topResidual.contains { $0.scoreIfAssumptionsHold != $0.riskScore }
            lines.append(
                showsAssumed
                    ? "| Threat | Raised by | Residual | If assumed hold | Before controls | Level |"
                    : "| Threat | Raised by | Residual | Before controls | Level |"
            )
```

and write the matching separator row and the matching cells.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd ThreatModelKit && swift test --filter LikelihoodReportTests --filter RecommendationsSectionTests`
Then the whole suite: `cd ThreatModelKit && swift test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Sources ThreatModelKit/Tests/UnitTests/LikelihoodReportTests.swift
git commit -m "feat: the report states likelihood, sources and the target posture"
```

---

### Task 13: One model from source to report

**Files:**
- Test: `ThreatModelKit/Tests/GatewayIntegrationTests/LikelihoodEndToEndTests.swift`

**Interfaces:**
- Consumes: every task above.
- Produces: nothing. It proves the whole path.

- [ ] **Step 1: Write the failing test**

```swift
import Foundation
import Testing
import ThreatModelKit
import TestSupport

@Suite("An endpoint model with likelihood and assumptions, from source to report")
struct LikelihoodEndToEndTests {
    private let architecture = """
    system "ClearanceKit" {
      risk_tolerance = "low"

      assumption "mdm-push" {
        text  = "the hardening baseline is written, and MDM has not pushed it yet"
        owner = "platform team"
      }

      technology "workstation" {
        name     = "Developer Laptop"
        category = "compute"
        threats  = ["sip-bypass"]
      }

      technology "hardening" {
        name     = "Hardening Baseline"
        category = "compute"
      }

      component "laptop" {
        technology = "workstation"
        data       = "restricted"
      }

      component "baseline" {
        technology = "hardening"
      }

      mitigates baseline -> laptop {
        threats         = ["sip-bypass"]
        reduces_risk_by = 60
        status          = "assumed"
      }
    }
    """

    @Test func compilesChecksAndReports() throws {
        // Fill in from the fixtures the other integration tests use: build the
        // use cases the way `InitialiseProjectFromBundledSamplesTests` does,
        // write the two files into a temporary directory, then:
        //   1. run compile, and expect the controls file to hold
        //      `tolerance = "low"`;
        //   2. add a likelihood block with tier "research" to the sip-bypass
        //      threat, and run check;
        //   3. expect check to exit 0 when the residual sits at or below Low,
        //      and to exit 1 with the block removed;
        //   4. run report, and expect the Markdown to hold "## Assumptions",
        //      "- Likelihood: Research", and "If the assumptions hold".
        Issue.record("write this test from the fixtures named above")
    }
}
```

Replace the body with the real test before running it. Read `Tests/GatewayIntegrationTests/InitialiseProjectFromBundledSamplesTests.swift` for how that suite builds a project directory and calls the use cases, and follow it exactly. The `sip-bypass` threat must exist in the catalogue the test uses; if the fixture catalogue has no such threat, declare the threat inside a `.lib` file in the same temporary project and add the library to it, the way `LibraryEndToEndTests` does.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd ThreatModelKit && swift test --filter LikelihoodEndToEndTests`
Expected: FAIL until the body is written and the path works.

- [ ] **Step 3: Make it pass**

Fix whatever the failure names. Every behaviour it needs is built by Tasks 1 to 12; a failure here is a wiring fault in one of them, not new behaviour. Do not add a feature to make this test pass without adding a unit test for it in the task that owns it.

- [ ] **Step 4: Run the whole suite**

Run: `cd ThreatModelKit && swift test`
Then the application: `cd .. && xcodebuild test -project threatmodeller.xcodeproj -scheme threatmodeller -destination 'platform=macOS'`
Expected: both PASS.

- [ ] **Step 5: Commit**

```bash
git add ThreatModelKit/Tests/GatewayIntegrationTests/LikelihoodEndToEndTests.swift
git commit -m "test: an endpoint model with likelihood and assumptions, source to report"
```

---

### Task 14: The language guide

**Files:**
- Modify: `docs/LANGUAGE.md`
- Modify: `README.md`
- Test: `python3 scripts/check_docs_page.py` (read the script's arguments first)

**Interfaces:**
- Consumes: the language every task above added.
- Produces: nothing.

- [ ] **Step 1: Write the documentation**

Add to `docs/LANGUAGE.md`, matching the shape of the sections around each one:

- In the library-threat section: the `likelihood` attribute, its three tier words, the numeric prior, and the sentence that a threat stating none is `commodity`.
- In the architecture-system section: `risk_tolerance` and the `assumption` block.
- In the `mitigates` section: `status`, its two words, and the sentence that an assumed edge never lowers the residual.
- A new controls-file section for `likelihood`, `severity_override`, and the `sources` list, each with an example and the rule that a block with no rationale is an error.
- In the diagnostics table: one row for each new fault message.

In `README.md`, add `--tolerance <level>` to the options list under the command line usage.

- [ ] **Step 2: Check the documentation builds**

Run: `python3 scripts/build_docs_page.py` (it needs the `markdown` package; `pip install -r .github/pages-requirements.txt` installs it), then `python3 scripts/check_docs_page.py` with the arguments the script names.
Expected: no fault lines.

- [ ] **Step 3: Commit**

```bash
git add docs/LANGUAGE.md README.md
git commit -m "docs: the likelihood, assumption and severity blocks"
```

---

## Self-Review

**Spec coverage**

| Spec section | Task |
| --- | --- |
| 2.1, 2.2, 3 the likelihood stage | 1, 3 |
| 2.3 prior in the library, finding in the file | 2, 4, 5 |
| 2.4 assumed edges | 9, 10 |
| 2.5 system assumptions | 9, 12 |
| 2.6 sources | 4, 6, 7 |
| 2.7 severity decision | 6 |
| 2.8 tolerance | 9, 11 |
| 4.1, 4.2, 4.3 the file formats | 2, 4, 6, 7, 9 |
| 5 check | 11 |
| 6 the report | 12 |
| 8 testing | every task, and 13 |
| 9 files | every task |

**Placeholders**

Task 13's test body is written as instructions, not code, because the fixture helpers in `GatewayIntegrationTests` must be read before the test can name them. Every other step holds the code it asks for.

**Type consistency**

`Likelihood`, `LikelihoodFinding`, `SeverityDecision`, `MitigationStatus`, `SystemAssumption`, `ReportAssumption` and `ReportSeverityDecision` keep the same names and the same fields in every task that uses them. `ComponentMitigations.apply` gains one parameter, `statuses`, with a default that holds today's behaviour.
